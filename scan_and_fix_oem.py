import sqlite3
import json

conn = sqlite3.connect('data/threat_intel.db')
cursor = conn.cursor()

# Find all advisories
cursor.execute("SELECT cve_id, title, vendor, product, raw_data FROM ics_advisories")
rows = cursor.fetchall()

updated_count = 0

for cve_id, title, vendor, product, raw_json in rows:
    try:
        raw_data = json.loads(raw_json) if raw_json else {}
    except Exception:
        raw_data = {}
        
    # We only care about aligning vendor back to the ICS vendor if the title explicitly mentions them.
    title_lower = str(title).lower()
    
    new_vendor = None
    new_product = None
    new_hq = None
    
    # Prioritize exact matches in the title
    if 'siemens' in title_lower:
        new_vendor = 'Siemens'
        new_hq = 'Germany'
    elif 'fortinet' in title_lower or 'fortios' in title_lower:
        new_vendor = 'Fortinet'
        new_hq = 'United States'
    elif 'milestone' in title_lower or 'xprotect' in title_lower:
        new_vendor = 'Milestone Systems'
        new_hq = 'Denmark'
    elif 'rockwell' in title_lower:
        new_vendor = 'Rockwell Automation'
        new_hq = 'United States'
    elif 'schneider' in title_lower:
        new_vendor = 'Schneider Electric'
        new_hq = 'France'
    elif 'abb ' in title_lower or title_lower.startswith('abb'):
        new_vendor = 'ABB'
        new_hq = 'Switzerland'
    elif 'mitsubishi' in title_lower:
        new_vendor = 'Mitsubishi Electric'
        new_hq = 'Japan'
    elif 'omron' in title_lower:
        new_vendor = 'OMRON'
        new_hq = 'Japan'
    elif 'panasonic' in title_lower:
        new_vendor = 'Panasonic'
        new_hq = 'Japan'
    elif 'honeywell' in title_lower:
        new_vendor = 'Honeywell'
        new_hq = 'United States'
    elif 'advantech' in title_lower:
        new_vendor = 'Advantech'
        new_hq = 'Taiwan'
        
    if new_vendor and (str(vendor).lower() != new_vendor.lower()):
        # Try to extract the product from the title. E.g. "Siemens RUGGEDCOM APE1808 Devices" -> "RUGGEDCOM APE1808 Devices"
        # Since this is a rough alignment, we'll just keep the original product if it's already there, or set to the new vendor.
        # But actually, the title usually has the product name.
        if title_lower.startswith(new_vendor.lower() + " "):
            extracted_prod = title[len(new_vendor)+1:].strip()
        else:
            extracted_prod = title
            
        new_product = extracted_prod
            
        raw_data['affected_vendor'] = new_vendor
        raw_data['affected_application'] = new_product
        if new_hq:
            raw_data['vendor_hq'] = new_hq
            
        cursor.execute("""
            UPDATE ics_advisories 
            SET vendor = ?, product = ?, vendor_hq = COALESCE(?, vendor_hq), raw_data = ?
            WHERE cve_id = ?
        """, (new_vendor, new_product, new_hq, json.dumps(raw_data), cve_id))
        updated_count += 1

conn.commit()
print(f"Total rows aligned across database: {updated_count}")
conn.close()
