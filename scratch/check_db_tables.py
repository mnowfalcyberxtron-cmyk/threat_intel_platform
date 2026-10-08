import sqlite3

def check_tables():
    conn = sqlite3.connect('data/threat_intel.db')
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = cursor.fetchall()
    print("Database Tables and Row Counts:")
    print("=" * 40)
    for t in tables:
        name = t[0]
        try:
            cursor.execute(f"SELECT COUNT(*) FROM `{name}`")
            count = cursor.fetchone()[0]
            print(f" • {name:<25}: {count:,} rows")
        except Exception as e:
            print(f" • {name:<25}: Error ({e})")
    conn.close()

if __name__ == '__main__':
    check_tables()
