"""Patch the renderHIBRInvestigationSummary to include cached/live badge."""

with open('frontend/index.html', 'r', encoding='utf-8') as f:
    content = f.read()

OLD = '''  const startEntity=data.start_entity||{};
  return `<div style="background:linear-gradient(135deg,rgba(0,212,255,.08),rgba(56,139,253,.06));border:1px solid rgba(0,212,255,.25);border-radius:var(--r);padding:12px;margin-top:6px">`
    +`<div style="font-size:13px;font-weight:700;color:var(--cyan);margin-bottom:6px">✓ Investigation Complete \u2014 ${esc(startEntity.value||'')}</div>`'''

NEW = '''  const startEntity=data.start_entity||{};
  const isCached=data._cached_at!=null;
  const cacheBadge=isCached
    ?`<span style="background:rgba(0,212,255,.15);color:var(--cyan);border:1px solid rgba(0,212,255,.3);padding:2px 8px;border-radius:10px;font-size:9px;font-weight:700;margin-left:8px">&#128190; CACHED &mdash; ${esc(String(data._cached_at||'').replace('T',' ').substring(0,19))} UTC</span>`
    :`<span style="background:rgba(63,185,80,.15);color:var(--green);border:1px solid rgba(63,185,80,.3);padding:2px 8px;border-radius:10px;font-size:9px;font-weight:700;margin-left:8px">&#9889; LIVE SCAN</span>`;
  return `<div style="background:linear-gradient(135deg,rgba(0,212,255,.08),rgba(56,139,253,.06));border:1px solid rgba(0,212,255,.25);border-radius:var(--r);padding:12px;margin-top:6px">`
    +`<div style="font-size:13px;font-weight:700;color:var(--cyan);margin-bottom:6px">&#10003; Investigation Complete \u2014 ${esc(startEntity.value||'')}${cacheBadge}</div>`'''

if OLD in content:
    content = content.replace(OLD, NEW, 1)
    with open('frontend/index.html', 'w', encoding='utf-8') as f:
        f.write(content)
    print('SUCCESS: Cache badge patch applied.')
else:
    print('FAIL: Target string not found. Check the OLD string matches exactly.')
    # Show context
    idx = content.find('const startEntity=data.start_entity')
    print('Context around that area:')
    print(repr(content[idx:idx+300]))
