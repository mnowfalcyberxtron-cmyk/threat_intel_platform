import re

with open('frontend/index.html', 'r', encoding='utf-8') as f:
    content = f.read()

scripts = re.findall(r'<script[^>]*>(.*?)</script>', content, re.DOTALL)
combined = '\n'.join(scripts)

checks = [
    ('_renderHIBRSection defined', 'function _renderHIBRSection(' in combined),
    ('hibrInvestigateDomain forceRefresh', 'hibrInvestigateDomain(forceRefresh=false)' in combined),
    ('hibrInvestigateEmail forceRefresh', 'hibrInvestigateEmail(forceRefresh=false)' in combined),
    ('Force Refresh btn domain', 'hibr-domain-refresh-btn' in content),
    ('Force Refresh btn email', 'hibr-email-refresh-btn' in content),
    ('Cache badge in summary', '_cached_at' in combined),
    ('refresh=true API call', '?refresh=true' in combined),
    ('clearTGFilters no double brace', 'loadTelegram(1);}}' not in combined),
    ('No spaasync corruption', 'spaasync' not in combined),
]

all_ok = True
for label, result in checks:
    status = 'OK  ' if result else 'FAIL'
    print(f'  {status}: {label}')
    if not result:
        all_ok = False

print()
print('Overall:', 'ALL CHECKS PASSED' if all_ok else 'SOME CHECKS FAILED')
