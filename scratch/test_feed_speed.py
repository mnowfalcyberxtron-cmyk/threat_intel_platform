import sqlite3
import time
import json

db_path = 'data/threat_intel.db'

def test_queries():
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    
    # 1. Test stats query 1
    t0 = time.time()
    cur = conn.execute("SELECT COUNT(*) FROM threat_feed")
    total = cur.fetchone()[0]
    t1 = time.time()
    print(f"Total count query: {t1-t0:.4f}s (Result: {total})")
    
    # 2. Test stats query 2
    t0 = time.time()
    cur = conn.execute("SELECT COUNT(*) FROM threat_feed WHERE fetched_at >= datetime('now','-1 hour')")
    last_hour = cur.fetchone()[0]
    t1 = time.time()
    print(f"Last hour query: {t1-t0:.4f}s (Result: {last_hour})")
    
    # 3. Test stats query 3
    t0 = time.time()
    cur = conn.execute("SELECT COUNT(*) FROM threat_feed WHERE fetched_at >= datetime('now','-5 minutes')")
    last_5min = cur.fetchone()[0]
    t1 = time.time()
    print(f"Last 5min query: {t1-t0:.4f}s (Result: {last_5min})")

    # 4. Test latest feed query
    t0 = time.time()
    hours = 24
    time_filter = f"(published >= datetime('now','-{hours} hours') OR fetched_at >= datetime('now','-{hours} hours'))"
    sql = f"SELECT * FROM threat_feed WHERE {time_filter} AND relevance >= ? ORDER BY published DESC, fetched_at DESC LIMIT ?"
    cur = conn.execute(sql, (0.3, 50))
    rows = cur.fetchall()
    t1 = time.time()
    print(f"Latest feed query: {t1-t0:.4f}s (Result: {len(rows)} rows)")
    
    # 5. Let's look at get_stats
    print("\nProfiling get_stats queries:")
    
    queries = {
        "ioc_stats": """
            SELECT 
                COUNT(*) as total,
                SUM(CASE WHEN confidence_label='high' THEN 1 ELSE 0 END) as high_conf,
                SUM(CASE WHEN updated_at >= datetime('now','-1 day') THEN 1 ELSE 0 END) as new_24h
            FROM iocs 
            WHERE ioc_type <> 'onion' AND NOT (ioc_type='domain' AND ioc LIKE '%.onion%')
        """,
        "victim_stats": """
            SELECT 
                COUNT(*) as total,
                SUM(CASE WHEN discovery_date >= datetime('now','-1 day') THEN 1 ELSE 0 END) as new_24h
            FROM ransomware_victims
        """,
        "alert_stats": """
            SELECT 
                SUM(CASE WHEN acknowledged=0 AND alert_type NOT IN ('onion_status_change','onion_new_active','darkweb_monitor') THEN 1 ELSE 0 END) as unack_intel,
                SUM(CASE WHEN acknowledged=0 AND alert_type IN ('onion_status_change','onion_new_active','darkweb_monitor') THEN 1 ELSE 0 END) as unack_darkweb
            FROM alerts
        """,
        "top_actors": "SELECT threat_actor,COUNT(*) as cnt FROM iocs WHERE threat_actor NOT IN ('unknown','') GROUP BY threat_actor ORDER BY cnt DESC LIMIT 10",
        "top_groups": "SELECT group_name,COUNT(*) as victims FROM ransomware_victims WHERE discovery_date>=datetime('now','-30 days') GROUP BY group_name ORDER BY victims DESC LIMIT 10",
        "daily": "SELECT date(updated_at) as day,COUNT(*) as cnt FROM iocs WHERE updated_at>=datetime('now','-7 days') AND ioc_type <> 'onion' AND NOT (ioc_type='domain' AND ioc LIKE '%.onion%') GROUP BY day ORDER BY day",
        "status_history_total": "SELECT COUNT(*) FROM status_history"
    }
    
    for name, sql in queries.items():
        t0 = time.time()
        try:
            cur = conn.execute(sql)
            res = cur.fetchall()
            t1 = time.time()
            print(f"  {name}: {t1-t0:.4f}s")
        except Exception as e:
            print(f"  {name} failed: {e}")
            
    conn.close()

if __name__ == '__main__':
    test_queries()
