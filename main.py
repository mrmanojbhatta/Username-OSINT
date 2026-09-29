#!/usr/bin/env python3
import argparse, json, re, sys, time, uuid, hashlib, html, sqlite3
from pathlib import Path
from urllib.parse import urlparse
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock
from collections import Counter, defaultdict
from datetime import datetime, timezone

VERSION='4.0.0'
ROOT=Path(__file__).resolve().parent
CFG_PATH=ROOT/'config.json'
SITES_PATH=ROOT/'data/sites.json'

DEFAULT_CFG={'workers':8,'timeout':10,'retries':2,'delay':0.5,'cache_ttl':86400,'evidence_max_bytes':262144,
'user_agent':'MANOJ-USERNAME-OSINT/4.0 (+public-osint-research)','database':'cases/osint.sqlite3','evidence_dir':'cases'}

def cfg():
    c=DEFAULT_CFG.copy()
    if CFG_PATH.exists(): c.update(json.loads(CFG_PATH.read_text()))
    return c

def load_sites(): return json.loads(SITES_PATH.read_text())

def valid_username(u): return bool(re.fullmatch(r'[A-Za-z0-9._-]{1,64}',u or ''))

def validate_sites(sites):
    errors=[]; names=set(); domains=set(); allowed={'verified','needs_validation','disabled'}
    for i,s in enumerate(sites):
        for k in ('name','domain','category','url'):
            if not s.get(k): errors.append(f'[{i}] missing {k}')
        if s.get('name') in names: errors.append(f'[{i}] duplicate name: {s.get("name")}')
        if s.get('domain') in domains: errors.append(f'[{i}] duplicate domain: {s.get("domain")}')
        names.add(s.get('name')); domains.add(s.get('domain'))
        if '{username}' not in s.get('url',''): errors.append(f'[{i}] URL lacks {{username}}: {s.get("name")}')
        if s.get('method','GET') not in {'GET','HEAD'}: errors.append(f'[{i}] unsupported method: {s.get("name")}')
        if s.get('verification','needs_validation') not in allowed: errors.append(f'[{i}] bad verification: {s.get("name")}')
    return errors

class DB:
    def __init__(self,path):
        self.path=ROOT/path; self.path.parent.mkdir(parents=True,exist_ok=True)
        self.con=sqlite3.connect(self.path,check_same_thread=False); self.con.row_factory=sqlite3.Row; self.lock=Lock()
        self.con.executescript('''CREATE TABLE IF NOT EXISTS cases(case_id TEXT PRIMARY KEY,username TEXT,started REAL,finished REAL,status TEXT);
        CREATE TABLE IF NOT EXISTS results(case_id TEXT,site TEXT,domain TEXT,category TEXT,username TEXT,status TEXT,confidence TEXT,url TEXT,final_url TEXT,http_status INTEGER,reason TEXT,captured TEXT,evidence TEXT,sha256 TEXT,metadata TEXT,signals TEXT,PRIMARY KEY(case_id,site));
        CREATE TABLE IF NOT EXISTS cache(url TEXT PRIMARY KEY,created REAL,status INTEGER,final_url TEXT,headers TEXT,body BLOB,sha256 TEXT);'''); self.con.commit()
    def case(self,c,u):
        with self.lock:self.con.execute('INSERT OR IGNORE INTO cases VALUES(?,?,?,NULL,?)',(c,u,time.time(),'RUNNING'));self.con.commit()
    def save(self,c,r):
        with self.lock:self.con.execute('INSERT OR REPLACE INTO results VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',(c,r['site'],r['domain'],r['category'],r['username'],r['status'],r['confidence'],r['url'],r['final_url'],r['http_status'],r['reason'],r['captured'],r['evidence'],r['sha256'],json.dumps(r['metadata']),json.dumps(r['signals'])));self.con.commit()
    def cache_get(self,url,ttl):
        r=self.con.execute('SELECT * FROM cache WHERE url=?',(url,)).fetchone()
        return dict(r) if r and time.time()-r['created']<=ttl else None
    def cache_put(self,url,x):
        with self.lock:self.con.execute('INSERT OR REPLACE INTO cache VALUES(?,?,?,?,?,?,?)',(url,time.time(),x['status'],x['final_url'],json.dumps(x['headers']),x['body'],hashlib.sha256(x['body']).hexdigest()));self.con.commit()
    def done(self,c): return {r['site'] for r in self.con.execute('SELECT site FROM results WHERE case_id=?',(c,))}
    def finish(self,c,status='COMPLETED'):
        with self.lock:self.con.execute('UPDATE cases SET finished=?,status=? WHERE case_id=?',(time.time(),status,c));self.con.commit()

class Limiter:
    def __init__(self): self.last=defaultdict(float); self.lock=Lock()
    def wait(self,host,delay):
        with self.lock:
            w=max(0,delay-(time.monotonic()-self.last[host]));
            if w: time.sleep(w)
            self.last[host]=time.monotonic()

class Client:
    def __init__(self,c,db): self.c=c; self.db=db; self.l=Limiter()
    def get(self,url,site):
        cached=self.db.cache_get(url,self.c['cache_ttl'])
        if cached:return {'status':cached['status'],'final_url':cached['final_url'],'headers':json.loads(cached['headers'] or '{}'),'body':cached['body'],'error':'','chain':[url,cached['final_url']]}
        host=urlparse(url).netloc; last=''
        for attempt in range(self.c['retries']+1):
            self.l.wait(host,float(site.get('rate_limit',self.c['delay'])))
            req=Request(url,headers={'User-Agent':self.c['user_agent'],'Accept':'text/html,application/xhtml+xml'})
            try:
                with urlopen(req,timeout=float(site.get('timeout',self.c['timeout']))) as r:
                    body=r.read(self.c['evidence_max_bytes']+1)[:self.c['evidence_max_bytes']]; out={'status':r.status,'final_url':r.geturl(),'headers':dict(r.headers.items()),'body':body,'error':'','chain':[url,r.geturl()]}
                    self.db.cache_put(url,out); return out
            except HTTPError as e:
                body=e.read(self.c['evidence_max_bytes']+1)[:self.c['evidence_max_bytes']]; out={'status':e.code,'final_url':e.geturl() or url,'headers':dict(e.headers.items()) if e.headers else {},'body':body,'error':f'HTTP {e.code}','chain':[url,e.geturl() or url]};
                if e.code not in (429,500,502,503,504) or attempt>=self.c['retries']: return out
                last=out['error']
            except (URLError,TimeoutError) as e:
                last=str(e); out={'status':None,'final_url':url,'headers':{},'body':b'','error':last,'chain':[url]}
                if attempt>=self.c['retries']: return out
            except Exception as e:
                last=str(e); out={'status':None,'final_url':url,'headers':{},'body':b'','error':last,'chain':[url]}
                if attempt>=self.c['retries']: return out
            time.sleep(min(8,.5*(2**attempt)))
        return out

def metadata(body):
    t=body.decode('utf-8','replace'); low=t.lower();
    m=re.search(r'<title[^>]*>(.*?)</title>',t,re.I|re.S); title=re.sub(r'\s+',' ',html.unescape(m.group(1))).strip()[:300] if m else ''
    def meta(n):
        x=re.search(r'<meta[^>]+(?:name|property)=["\']'+re.escape(n)+r'["\'][^>]+content=["\'](.*?)["\']',t,re.I|re.S); return html.unescape(x.group(1))[:500] if x else ''
    cm=re.search(r'<link[^>]+rel=["\']canonical["\'][^>]+href=["\'](.*?)["\']',t,re.I|re.S)
    text=re.sub(r'<[^>]+>',' ',t); text=re.sub(r'\s+',' ',text).lower()[:60000]
    return {'title':title,'description':meta('description'),'og_title':meta('og:title'),'og_description':meta('og:description'),'og_image':meta('og:image'),'canonical':html.unescape(cm.group(1))[:1000] if cm else '','text':text}

def verify(site,u,x,url):
    now=datetime.now(timezone.utc).isoformat(); m=metadata(x['body']); text=m['text']; title=m['title'].lower(); sig=[]; score=0
    def ret(status,conf,reason): return {'site':site['name'],'domain':site['domain'],'category':site['category'],'username':u,'url':url,'final_url':x['final_url'],'status':status,'confidence':conf,'http_status':x['status'],'reason':reason,'captured':now,'evidence':'','sha256':'','metadata':{k:v for k,v in m.items() if k!='text'}|{'redirect_chain':x['chain']},'signals':sig}
    if x['status'] is None:return ret('TIMEOUT','NONE','Request failed: '+x['error'])
    if x['status'] in (401,403):return ret('BLOCKED','NONE',f'Access restricted (HTTP {x["status"]}).')
    if x['status']==429:return ret('RATE_LIMITED','NONE','Rate limit response.')
    if x['status'] in (404,410):return ret('NOT_FOUND','HIGH','Strong HTTP not-found response.')
    if x['status']>=500:return ret('ERROR','NONE',f'Server error HTTP {x["status"]}.')
    if any(z in text for z in ('captcha','verify you are human','challenge.cloudflare.com')):return ret('CAPTCHA','NONE','Challenge/CAPTCHA indicators detected.')
    if x['final_url'].rstrip('/')!=url.rstrip('/') and any(z in x['final_url'].lower() for z in ('/login','/signin','/auth')):return ret('BLOCKED','MEDIUM','Redirected to an authentication page.')
    for z in site.get('negative',[]):
        if z.lower() in text or z.lower() in title: sig.append({'type':'negative','marker':z,'weight':-5});score-=5
    for z in site.get('positive',[]):
        if z.lower() in text or z.lower() in title: sig.append({'type':'positive','marker':z,'weight':2});score+=2
    if u.lower() in text:sig.append({'type':'username_present','weight':3});score+=3
    final=x['final_url'].lower()
    if any(z.lower().replace('{username}',u.lower()) in final for z in site.get('url_contains',[])):sig.append({'type':'url_match','weight':2});score+=2
    if score>=5:return ret('FOUND','HIGH','Multiple positive public-profile signals detected.')
    if score>=2:return ret('FOUND','MEDIUM','Some positive public-profile signals detected.')
    if score<=-5:return ret('NOT_FOUND','HIGH','Strong negative/soft-404 indicators detected.')
    if x['status']==200:return ret('UNKNOWN','LOW','Public response received, but profile existence could not be confidently verified.')
    return ret('UNKNOWN','NONE',f'HTTP {x["status"]}; insufficient verification evidence.')

def evidence(case_dir,r,body):
    p=Path(case_dir)/'evidence';p.mkdir(parents=True,exist_ok=True); name=re.sub(r'[^A-Za-z0-9._-]+','_',r['site'])[:80]+'.html'; fp=p/name
    data=b'<!-- Public OSINT evidence snapshot; untrusted web content. -->\n'+body;fp.write_bytes(data);r['evidence']=str(fp);r['sha256']=hashlib.sha256(data).hexdigest()

def correlations(results):
    sites=[r['site'] for r in results if r['status']=='FOUND']
    return [{'type':'same_username','sites':sites,'statement':'Potential public correlation: the exact username produced FOUND results on multiple public endpoints. This does not prove common ownership.'}] if len(sites)>1 else []

CSS='''body{margin:0;background:#0b1020;color:#e8edf7;font:14px system-ui}main{max-width:1400px;margin:auto;padding:24px}.card{background:#121a2e;border:1px solid #26324d;border-radius:16px;padding:18px;margin:14px 0}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:10px}.stat{padding:14px;border:1px solid #26324d;border-radius:12px}.num{font-size:24px;font-weight:800}input,select{background:#0b1020;color:#fff;border:1px solid #26324d;padding:9px;border-radius:8px;margin:3px}table{width:100%;border-collapse:collapse;min-width:1050px}th,td{padding:10px;border-bottom:1px solid #26324d;text-align:left;vertical-align:top}th{background:#121a2e;position:sticky;top:0}a{color:#70adff}.wrap{overflow:auto}.muted{color:#9ba8bd}code{word-break:break-all}'''
JS='''const q=document.querySelector('#q'),s=document.querySelector('#s'),c=document.querySelector('#c'),f=document.querySelector('#f');function go(){document.querySelectorAll('tbody tr').forEach(x=>{let ok=(!q.value||x.innerText.toLowerCase().includes(q.value.toLowerCase()))&&(!s.value||x.dataset.s==s.value)&&(!c.value||x.dataset.c==c.value)&&(!f.value||x.dataset.f==f.value);x.style.display=ok?'':'none'})}[q,s,c,f].forEach(x=>x.oninput=go);'''

def report(case,u,results,started,finished,cors):
    cnt=Counter(r['status'] for r in results); cats=sorted({r['category'] for r in results});
    cards=''.join(f'<div class="stat"><div class="muted">{k}</div><div class="num">{cnt[k]}</div></div>' for k in ['FOUND','NOT_FOUND','UNKNOWN','BLOCKED','RATE_LIMITED','CAPTCHA','ERROR','TIMEOUT'])
    rows=[]
    for r in results:
        ep=f'<a href="{html.escape(r["evidence"])}">snapshot</a>' if r['evidence'] else '—'; u=html.escape(r['final_url'] or r['url'],quote=True)
        rows.append(f'<tr data-s="{r["status"]}" data-c="{html.escape(r["category"])}" data-f="{r["confidence"]}"><td><b>{html.escape(r["site"])}</b><br><span class="muted">{html.escape(r["domain"])}</span></td><td>{html.escape(r["category"])}</td><td>{r["status"]}</td><td>{r["confidence"]}</td><td>{r["http_status"]}</td><td><a href="{u}" target="_blank" rel="noopener">{u}</a><details><summary>Details</summary>{html.escape(r["reason"])}<br>{html.escape(json.dumps(r["signals"]))}</details></td><td>{html.escape(r["reason"])}</td><td>{ep}<br><code>{html.escape(r["sha256"])}</code></td></tr>')
    return f'''<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>MANOJ USERNAME OSINT — {html.escape(u)}</title><style>{CSS}</style><main><section class="card"><h1>MANOJ USERNAME OSINT</h1><div class="muted">v{VERSION} · Public username OSINT report</div><p>Target: <b>{html.escape(u)}</b><br>Case: <code>{case}</code><br>{started} → {finished}</p></section><section class="grid">{cards}</section><section class="card"><input id="q" placeholder="Search…"><select id="s"><option value="">All status</option>{''.join(f'<option>{x}</option>' for x in sorted(cnt))}</select><select id="c"><option value="">All categories</option>{''.join(f'<option>{html.escape(x)}</option>' for x in cats)}</select><select id="f"><option value="">All confidence</option><option>HIGH</option><option>MEDIUM</option><option>LOW</option><option>NONE</option></select></section><section class="card wrap"><table><thead><tr><th>Site</th><th>Category</th><th>Status</th><th>Confidence</th><th>HTTP</th><th>URL / Details</th><th>Reason</th><th>Evidence / SHA-256</th></tr></thead><tbody>{''.join(rows)}</tbody></table></section><section class="card"><h2>Potential public correlations</h2>{''.join('<p>'+html.escape(x['statement'])+'</p>' for x in cors) or '<p class="muted">No multi-site exact-username correlation observed.</p>'}</section><p class="muted">A username match does not prove account ownership or identity. Respect law, site terms and rate limits.</p></main><script>{JS}</script>'''

def scan(args):
    c=cfg(); c.update({k:v for k,v in vars(args).items() if k in ('workers','timeout','delay','retries') and v is not None}); sites=load_sites();
    if not valid_username(args.username): raise SystemExit('Invalid username. Allowed: letters, numbers, dot, underscore, hyphen.')
    if args.category: sites=[s for s in sites if s.get('category') in args.category]
    db=DB(c['database']); case=datetime.now().strftime('%Y%m%d-%H%M%S')+'-'+uuid.uuid4().hex[:6]; db.case(case,args.username); case_dir=ROOT/c['evidence_dir']/args.username/case; case_dir.mkdir(parents=True)
    client=Client(c,db); results=[]; start=datetime.now(timezone.utc).isoformat()
    def one(s):
        if not s.get('enabled',True) or s.get('verification')=='disabled': return {'site':s['name'],'domain':s['domain'],'category':s['category'],'username':args.username,'url':s['url'].format(username=args.username),'final_url':'','status':'DISABLED','confidence':'NONE','http_status':None,'reason':'Site definition disabled.','captured':datetime.now(timezone.utc).isoformat(),'evidence':'','sha256':'','metadata':{},'signals':[]}
        url=s['url'].format(username=args.username); x=client.get(url,s); r=verify(s,args.username,x,url)
        if r['status'] in ('FOUND','UNKNOWN','REDIRECTED') and x['body']: evidence(case_dir,r,x['body'])
        return r
    try:
        with ThreadPoolExecutor(max_workers=max(1,c['workers'])) as ex:
            for f in as_completed([ex.submit(one,s) for s in sites]):
                r=f.result();results.append(r);db.save(case,r)
    except KeyboardInterrupt: db.finish(case,'INTERRUPTED'); print('\nInterrupted; completed results saved.'); return 130
    end=datetime.now(timezone.utc).isoformat();cors=correlations(results); rp=case_dir/'report.html';jp=case_dir/'results.json';rp.write_text(report(case,args.username,results,start,end,cors),encoding='utf-8');jp.write_text(json.dumps({'case_id':case,'target':args.username,'scanner':{'name':'MANOJ USERNAME OSINT','version':VERSION},'statistics':dict(Counter(r['status'] for r in results)),'results':results,'correlations':cors},indent=2),encoding='utf-8');db.finish(case); print(f'\nMANOJ USERNAME OSINT v{VERSION}\nTarget: {args.username}\nSites: {len(sites)}'); [print(f'{k:12} {Counter(r["status"] for r in results)[k]}') for k in ['FOUND','NOT_FOUND','UNKNOWN','BLOCKED','RATE_LIMITED','CAPTCHA','ERROR','TIMEOUT']]; print(f'\nCase: {case}\nHTML: {rp}\nJSON: {jp}')

def main():
    p=argparse.ArgumentParser();sub=p.add_subparsers(dest='cmd',required=True);s=sub.add_parser('scan');s.add_argument('--username',required=True);s.add_argument('--category',action='append');s.add_argument('--workers',type=int);s.add_argument('--timeout',type=float);s.add_argument('--delay',type=float);s.add_argument('--retries',type=int);s.add_argument('--no-cache',action='store_true');v=sub.add_parser('validate-sites');t=sub.add_parser('test-site');t.add_argument('--site',required=True);t.add_argument('--username',required=True);a=p.parse_args()
    if a.cmd=='validate-sites':
        e=validate_sites(load_sites());print(f'Loaded {len(load_sites())} site definitions.');print('\n'.join(e) if e else 'PASS: site database is structurally valid.');return 1 if e else 0
    if a.cmd=='test-site':
        found=[x for x in load_sites() if x['name'].lower()==a.site.lower()];
        if not found:return print('Site not found.'),2
        a.category=[found[0]['category']];scan(a);return 0
    scan(a);return 0
if __name__=='__main__':sys.exit(main())
