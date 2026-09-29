#!/usr/bin/env python3
import sys,json
from pathlib import Path
p=Path(__file__).resolve().parents[1];sys.path.insert(0,str(p));from main import load_sites,validate_sites
s=load_sites();e=validate_sites(s);print(f'Loaded {len(s)} site definitions.');print('\n'.join(e) if e else 'PASS: site database is structurally valid.');raise SystemExit(1 if e else 0)
