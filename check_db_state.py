#!/usr/bin/env python3
import sqlite3
from pathlib import Path

db_path = Path('database.db')
print(f'DB exists: {db_path.exists()}')

if db_path.exists():
    print(f'DB size: {db_path.stat().st_size} bytes')
    conn = sqlite3.connect(str(db_path))
    cur = conn.cursor()
    
    # Get all tables
    cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = [t[0] for t in cur.fetchall()]
    print(f'Tables: {tables}')
    
    # Check ICS table
    if 'ics_advisories' in tables:
        cur.execute('SELECT COUNT(*) FROM ics_advisories')
        count = cur.fetchone()[0]
        print(f'ICS advisories rows: {count}')
        
        # Check schema
        cur.execute("PRAGMA table_info(ics_advisories)")
        cols = cur.fetchall()
        print(f'ICS columns: {[c[1] for c in cols]}')
    else:
        print('ICS table NOT FOUND!')
    
    conn.close()
else:
    print('Database file does not exist')
