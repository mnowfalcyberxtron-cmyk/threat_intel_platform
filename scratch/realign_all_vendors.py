"""
Comprehensive Vendor & Product Re-alignment Script across all 14k+ ICS Advisories.

Identifies advisories where a third-party software component / vendor is embedded inside another vendor's advisory wrapper
(e.g., 'Siemens Siveillance Video' containing 'Milestone XProtect Management Server', 'Fortinet FortiOS', 'CODESYS', etc.)
and aligns vendor/product so the table accurately reflects the true vulnerable component vendor.
"""

import sqlite3
import re
import sys

def realign_all_advisories():
    sys.stdout.reconfigure(encoding='utf-8')
    conn = sqlite3.connect('data/threat_intel.db')
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    cur.execute('SELECT id, ics_number, cve_id, title, vendor, product, affected_version, fixed_version FROM ics_advisories')
    rows = cur.fetchall()

    updates = []
    
    # Common third-party component extraction patterns
    patterns = [
        (r'Milestone\s+XProtect', 'Milestone Systems', 'Milestone XProtect Management Server'),
        (r'Fortinet\s+(?:NGFW|FortiOS|FortiProxy|FortiPAM)', 'Fortinet', 'FortiOS / Fortinet NGFW'),
        (r'CODESYS\s+in\s+([A-Za-z0-9\s]+)', 'CODESYS Development GmbH', r'CODESYS in \1'),
        (r'OpenSSL\s+in\s+([A-Za-z0-9\s]+)', 'OpenSSL Project', r'OpenSSL in \1'),
        (r'Apache\s+([A-Za-z0-9\s]+)', 'Apache Software Foundation', r'Apache \1'),
    ]

    for r in rows:
        title = r['title'] or ''
        fixed = r['fixed_version'] or ''
        affected = r['affected_version'] or ''
        current_vendor = r['vendor'] or ''

        # Check for Milestone Systems
        if 'Milestone' in title or 'Milestone' in fixed or 'Milestone' in affected:
            if current_vendor != 'Milestone Systems':
                updates.append((r['id'], 'Milestone Systems', 'Milestone XProtect Management Server'))
                continue

        # Check for Fortinet
        if 'Fortinet' in title or 'Fortinet' in fixed or 'Fortinet' in affected:
            if current_vendor != 'Fortinet':
                updates.append((r['id'], 'Fortinet', 'FortiOS / Fortinet NGFW'))
                continue

        # Check for CODESYS
        if 'CODESYS' in title or 'CODESYS' in fixed or 'CODESYS' in affected:
            if 'CODESYS' not in current_vendor:
                updates.append((r['id'], 'CODESYS Development GmbH', 'CODESYS Runtime / Component'))
                continue

    print(f"Total rows evaluated: {len(rows)}")
    print(f"Total rows requiring vendor re-alignment: {len(updates)}")

    for row_id, new_vendor, new_product in updates:
        cur.execute(
            'UPDATE ics_advisories SET vendor = ?, product = ? WHERE id = ?',
            (new_vendor, new_product, row_id)
        )

    conn.commit()
    print("Re-alignment complete!")

if __name__ == '__main__':
    realign_all_advisories()
