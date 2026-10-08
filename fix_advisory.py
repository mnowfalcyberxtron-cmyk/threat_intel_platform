import re

with open('api/advisory_routes.py', 'r', encoding='utf-8') as f:
    data = f.read()

good_code = """
def _merge_ics_rows(primary_rows: list, fallback_rows: list) -> list:
    merged = {}
    cve_index = {}

    def key_for(row):
        adv = str(row.get("ics_number") or row.get("advisory_id") or "").strip().lower()
        cve = str(row.get("cve_id") or "").strip().upper()
        return (adv, cve)

    def merge_row(base, preferred):
        out = dict(base)
        for k, v in preferred.items():
            if v and str(v).strip() != "N/A" and str(v).strip() != "Unknown":
                out[k] = v
        
        sources = set(f"{base.get('data_source','')},{preferred.get('data_source','')}".split(","))
        out["data_source"] = "+".join([s.strip() for s in sources if s.strip()]) or "csv"
        return out

    for row in fallback_rows:
        row.setdefault("data_source", "csv")
        key = key_for(row)
        merged[key] = row
        if key[1]:
            cve_index.setdefault(key[1], key)
            
    for row in primary_rows:
        row.setdefault("data_source", "rapidapi")
        key = key_for(row)
        target_key = key if key in merged else cve_index.get(key[1], key)
        merged[target_key] = merge_row(merged[target_key], row) if target_key in merged else row
        if key[1]:
            cve_index.setdefault(key[1], target_key)
    return list(merged.values())

def _map_db_row_to_frontend(row: dict) -> dict:
    out = dict(row)
    if "vendor" in row:
        out["affected_vendor"] = row["vendor"]
    if "product" in row:
        out["affected_application"] = row["product"]
    if "severity" in row:
        out["cvss_severity"] = str(row["severity"]).capitalize() if row["severity"] else ""
    if "ics_number" in row:
        out["advisory_id"] = row["ics_number"]
    if "vendor_hq" in row:
        out["vendor_hq"] = row["vendor_hq"]
    if "product_distribution" in row:
        out["product_distribution"] = row["product_distribution"]
    if "kev_flag" in row:
        out["kev_flag"] = row["kev_flag"]
        
    if out.get("nvd_cvss_v4_score"):
        out["cvss_score"] = out["nvd_cvss_v4_score"]
        
    def _is_placeholder(val):
        if not val:
            return True
        v = str(val).strip().lower()
        return v in ("n/a", "unknown", "none", "null", "")

    def _derive_fixed_version_hint(affected):
        if not affected: return "Unknown"
        import re
        aff = str(affected)
        m = re.search(r'(?:prior to|before|through|<=|<)\s*([vV]?\d+(?:\.\d+)*)', aff)
        if m: return "Update to " + m.group(1) + " or later"
        return "Unknown"

    if _is_placeholder(out.get("fixed_version")) and not _is_placeholder(out.get("affected_version")):
        hint = _derive_fixed_version_hint(out.get("affected_version"))
        if not _is_placeholder(hint):
            out["fixed_version"] = hint
            
    return out

async def _get_ics_data(force: bool = False, schedule_sync: bool = True) -> list:
    global _ics_cache, _ics_cache_ts, _ics_cache_key
    import time
    from config import settings
    now = time.time()
    cache_key = "rapidapi+excel" if getattr(settings, "RAPIDAPI_KEY", "").strip() else "csv+excel"
    
    # If we have fresh memory cache, return it
    if not force and _ics_cache and _ics_cache_key == cache_key and (now - _ics_cache_ts) < 600:
        return _ics_cache
"""

start_idx = data.find('def _merge_ics_rows')
end_idx = data.find('    # Try to load from SQLite database (persistent cache)')

if start_idx != -1 and end_idx != -1:
    new_data = data[:start_idx] + good_code + data[end_idx:]
    with open('api/advisory_routes.py', 'w', encoding='utf-8') as f:
        f.write(new_data)
    print('Fixed advisory_routes.py!')
else:
    print('Could not find boundaries. start:', start_idx, 'end:', end_idx)
