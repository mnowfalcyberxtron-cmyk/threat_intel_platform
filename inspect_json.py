import urllib.request
import json
import re

url = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2021/44xxx/CVE-2021-44228.json"
resp = urllib.request.urlopen(url)
data = json.loads(resp.read())

import pprint
print("CNA metrics:")
if 'metrics' in data.get('containers', {}).get('cna', {}):
    pprint.pprint(data['containers']['cna']['metrics'])

print("ADP metrics:")
adps = data.get('containers', {}).get('adp', [])
for adp in adps:
    if 'metrics' in adp:
        pprint.pprint(adp['metrics'])
