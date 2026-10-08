import sqlite3
import time

db_path = 'data/threat_intel.db'

def add_indexes():
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    
    print("Creating covering index on iocs table...")
    t0 = time.time()
    cur.execute("CREATE INDEX IF NOT EXISTS idx_iocs_covering_stats ON iocs (ioc_type, confidence_label, updated_at)")
    conn.commit()
    print(f"Index idx_iocs_covering_stats created in {time.time()-t0:.4f}s")
    
    print("Creating covering index on ransomware_victims table...")
    t0 = time.time()
    cur.execute("CREATE INDEX IF NOT EXISTS idx_rv_discovery_group ON ransomware_victims (discovery_date DESC, group_name)")
    conn.commit()
    print(f"Index idx_rv_discovery_group created in {time.time()-t0:.4f}s")
    
    conn.close()

if __name__ == '__main__':
    add_indexes()
