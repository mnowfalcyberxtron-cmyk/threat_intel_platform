import sqlite3
import os

def inspect_db(db_path):
    if not os.path.exists(db_path):
        print(f"Database {db_path} does not exist.")
        return
    print(f"\n================ Inspecting: {db_path} ================")
    try:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        
        # Get list of tables
        cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [r['name'] for r in cur.fetchall()]
        print("Tables:", tables)
        
        for table in tables:
            cur.execute(f"SELECT COUNT(*) as cnt FROM {table}")
            cnt = cur.fetchone()['cnt']
            print(f"  Table: {table} -> {cnt} rows")
            
            # Print a few sample rows for onion_sites or breach_markets
            if table in ['onion_sites', 'breach_markets', 'advisories']:
                cur.execute(f"SELECT * FROM {table} LIMIT 3")
                rows = cur.fetchall()
                if rows:
                    print(f"    Sample {table} rows:")
                    for row in rows:
                        print("     ", dict(row))
        conn.close()
    except Exception as e:
        print(f"Error inspecting {db_path}: {e}")

def main():
    inspect_db("data/threat_intel.db")
    inspect_db("data/data.db")
    inspect_db("data/tip.db")

if __name__ == "__main__":
    main()
