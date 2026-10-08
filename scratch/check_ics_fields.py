import sqlite3

con = sqlite3.connect('data/threat_intel.db')
con.row_factory = sqlite3.Row

# Check existing column names first
cols = con.execute("PRAGMA table_info(ics_advisories)").fetchall()
print("Columns:", [c[1] for c in cols])

# Count records
total = con.execute("SELECT COUNT(*) FROM ics_advisories").fetchone()[0]
print(f"\nTotal records: {total:,}")

# Check vendor_hq
vhq = con.execute("SELECT COUNT(*) FROM ics_advisories WHERE vendor_hq != ''").fetchone()[0]
print(f"vendor_hq filled: {vhq:,}")

# Check product_distribution
pd_count = con.execute("SELECT COUNT(*) FROM ics_advisories WHERE product_distribution != ''").fetchone()[0]
print(f"product_distribution filled: {pd_count:,}")

# Check kev_flag
kev = con.execute("SELECT COUNT(*) FROM ics_advisories WHERE kev_flag != ''").fetchone()[0]
print(f"kev_flag filled: {kev:,}")

# Check normalized_data for these fields  
sample = con.execute("SELECT normalized_data FROM ics_advisories WHERE normalized_data IS NOT NULL AND normalized_data != '{}' LIMIT 1").fetchone()
if sample:
    import json
    nd = json.loads(sample[0])
    print("\nSample normalized_data keys:", list(nd.keys())[:30])
    # Look for vendor_hq-like keys
    matching = {k: v for k, v in nd.items() if 'hq' in k.lower() or 'kev' in k.lower() or 'distribution' in k.lower() or 'headquarter' in k.lower()}
    print("Matching fields:", matching)

# Check what the API actually returns — look at raw_data
sample_raw = con.execute("SELECT ics_number, raw_data FROM ics_advisories WHERE raw_data != '{}' LIMIT 1").fetchone()
if sample_raw:
    import json
    rd = json.loads(sample_raw[1])
    print(f"\nSample raw_data for {sample_raw['ics_number']}: keys = {list(rd.keys())}")

con.close()
