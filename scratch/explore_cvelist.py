import zipfile, json, sys

zf = zipfile.ZipFile('cvelistV5.zip')
names = zf.namelist()
print(f'Total files in zip: {len(names)}')
print('Sample paths:', names[:5])

# Count 2026 CVEs
cves_2026 = [n for n in names if '/2026/' in n and n.endswith('.json')]
print(f'2026 CVEs found: {len(cves_2026)}')

# Sample 3 of them
for path in cves_2026[:3]:
    try:
        data = json.loads(zf.read(path))
        meta = data.get('cveMetadata', {})
        cna = data.get('containers', {}).get('cna', {})
        print()
        print('=== FILE:', path)
        print('  cveId:', meta.get('cveId'))
        print('  state:', meta.get('state'))
        print('  datePublished:', meta.get('datePublished'))
        print('  dateUpdated:', meta.get('dateUpdated'))
        print('  dateReserved:', meta.get('dateReserved'))
        # CVSS from cna.metrics
        metrics = cna.get('metrics', [])
        for m in metrics[:2]:
            for k in ('cvssV4_0', 'cvssV3_1', 'cvssV3_0', 'cvssV2_0'):
                if k in m:
                    print(f'  {k} score:', m[k].get('baseScore'), 'severity:', m[k].get('baseSeverity'))
        # ADP container (NVD adds scores here)
        adp_list = data.get('containers', {}).get('adp', [])
        for adp in adp_list:
            adp_metrics = adp.get('metrics', [])
            for m in adp_metrics[:2]:
                for k in ('cvssV4_0', 'cvssV3_1', 'cvssV3_0', 'cvssV2_0'):
                    if k in m:
                        print(f'  ADP {k} score:', m[k].get('baseScore'), 'severity:', m[k].get('baseSeverity'))
        # affected products
        affected = cna.get('affected', [])
        if affected:
            print('  affected[0] vendor:', affected[0].get('vendor'), 'product:', affected[0].get('product'))
    except Exception as e:
        print('Error:', e)

zf.close()
print('\nDone.')
