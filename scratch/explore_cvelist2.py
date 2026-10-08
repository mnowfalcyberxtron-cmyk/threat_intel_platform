import zipfile, json, sys

zf = zipfile.ZipFile('cvelistV5.zip')
names = zf.namelist()

# Find a CVE that we know is in our ICS advisories (July 2026, multi-CVE advisory)
# CVE-2021-41617 is in ICSA-26-209-04
target = 'cvelistV5-main/cves/2021/41xxx/CVE-2021-41617.json'
# Also check a 2026 one
target2 = 'cvelistV5-main/cves/2026/0xxx/CVE-2026-0001.json'

for path in [target, target2]:
    if path in names:
        data = json.loads(zf.read(path))
        print('=== FULL SCHEMA FOR:', path)
        meta = data.get('cveMetadata', {})
        cna = data.get('containers', {}).get('cna', {})
        adp_list = data.get('containers', {}).get('adp', [])
        
        print('METADATA KEYS:', list(meta.keys()))
        print('  cveId:', meta.get('cveId'))
        print('  state:', meta.get('state'))
        print('  dateReserved:', meta.get('dateReserved'))
        print('  datePublished:', meta.get('datePublished'))
        print('  dateUpdated:', meta.get('dateUpdated'))
        
        print('CNA KEYS:', list(cna.keys()))
        
        # Description
        descs = cna.get('descriptions', [])
        if descs:
            print('  description:', descs[0].get('value','')[:200])
        
        # Metrics
        metrics = cna.get('metrics', [])
        print('  CNA metrics:', metrics[:3] if metrics else 'NONE')
        
        # ADP metrics (NVD enriches here)
        for adp in adp_list:
            title = adp.get('title','')
            adp_metrics = adp.get('metrics', [])
            if adp_metrics:
                print(f'  ADP ({title}) metrics:', adp_metrics[:2])
        
        # Problem types / CWE
        pt = cna.get('problemTypes', [])
        for p in pt[:2]:
            for d in p.get('descriptions', []):
                print('  CWE:', d.get('cweId'), d.get('description','')[:80])
        
        # Affected
        aff = cna.get('affected', [])
        if aff:
            a = aff[0]
            print('  vendor:', a.get('vendor'))
            print('  product:', a.get('product'))
            versions = a.get('versions', [])
            if versions:
                print('  versions[0]:', versions[0])
        
        # References
        refs = cna.get('references', [])
        print('  references:', [r.get('url','')[:80] for r in refs[:3]])
        
        print()
    else:
        print(f'NOT FOUND: {path}')

# Count how many CVEs match our ICS advisory CVE list
# Load a few ICS CVEs from DB to see match rate
import sqlite3
con = sqlite3.connect('data/threat_intel.db')
cur = con.cursor()
cur.execute('SELECT DISTINCT cve_id FROM ics_advisories WHERE cve_id NOT IN ("N/A","") LIMIT 20')
ics_cves = [r[0] for r in cur.fetchall()]
con.close()

print('=== MATCH RATE CHECK ===')
zip_index = set()
for n in names:
    if n.endswith('.json') and '/cves/' in n:
        basename = n.split('/')[-1].replace('.json','').upper()
        zip_index.add(basename)

found = sum(1 for c in ics_cves if c.upper() in zip_index)
print(f'ICS CVEs found in zip: {found}/{len(ics_cves)}')
print('Zip total CVE count:', len(zip_index))

zf.close()
print('Done.')
