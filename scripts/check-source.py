#!/usr/bin/env python3
"""Check repository boundaries and high-confidence secret patterns; not a security audit."""
import json,re,subprocess
from pathlib import Path
root=Path(__file__).resolve().parents[1]
paths=subprocess.check_output(['git','ls-files','--cached','--others','--exclude-standard','-z'],cwd=root).decode().split('\0')
errors=[];count=0
for relative in sorted(set(filter(None,paths))):
    file=root/relative
    if not file.is_file():continue
    count+=1
    if any(relative.startswith(prefix) for prefix in ['.local-dev/','.dev-tools/','.runtime/','node_modules/','dist/','build/','release/','telemetry-agent/target/','docs/implementation/evidence/','.openai/']):
        errors.append({'path':relative,'reason':'generated, private or historical local-only material in source index'})
    if file.stat().st_size>5*1024*1024:errors.append({'path':relative,'reason':'source file exceeds 5MiB; publish release artifacts separately'})
    if file.suffix in ['.woff','.woff2','.png','.jpg']:continue
    try:text=file.read_text(encoding='utf-8-sig')
    except UnicodeError:errors.append({'path':relative,'reason':'unexpected binary source artifact'});continue
    for name,pattern in [('GitHub token',r'\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})\b'),('AWS access key',r'\bAKIA[A-Z0-9]{16}\b')]:
        if re.search(pattern,text):errors.append({'path':relative,'reason':name})
    if re.search(r'-----BEGIN (?:OPENSSH |RSA |EC )?PRIVATE KEY-----\s+[A-Za-z0-9+/=\r\n]{60,}',text) and not ('/tests/' in '/'+relative or relative.endswith('_test.go') or '/fixtures/' in '/'+relative):
        errors.append({'path':relative,'reason':'private key material outside synthetic tests'})
print(json.dumps({'check':'source boundaries and obvious secrets only','files':count,'errors':errors},ensure_ascii=False,indent=2))
raise SystemExit(1 if errors else 0)
