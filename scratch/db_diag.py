import sqlite3

dbs = ['data/threat_intel.db', 'tip.db', 'data.db']
for db_name in dbs:
    try:
        conn = sqlite3.connect(db_name)
        cur = conn.cursor()
        print(f"Checking DB: {db_name}")
        cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [t[0] for t in cur.fetchall()]
        print("  Tables:", tables)
        for table in tables:
            cur.execute(f"SELECT COUNT(*) FROM {table}")
            cnt = cur.fetchone()[0]
            print(f"    Table {table}: {cnt} rows")
            
            # Show indexes
            cur.execute(f"PRAGMA index_list('{table}')")
            indexes = cur.fetchall()
            if indexes:
                print(f"      Indexes for {table}:")
                for idx in indexes:
                    idx_name = idx[1]
                    cur.execute(f"PRAGMA index_info('{idx_name}')")
                    cols = [c[2] for c in cur.fetchall()]
                    print(f"        {idx_name} on {cols}")
        conn.close()
    except Exception as e:
        print(f"  Error checking {db_name}: {e}")
