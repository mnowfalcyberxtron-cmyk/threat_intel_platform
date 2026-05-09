import sqlite3

def clean_db():
    conn = sqlite3.connect('data/threat_intel.db')
    c = conn.cursor()
    
    print('Advisories:', c.execute('SELECT COUNT(*) FROM advisories').fetchone()[0])
    print('Feed:', c.execute('SELECT COUNT(*) FROM threat_feed').fetchone()[0])
    print('Alerts before:', c.execute('SELECT COUNT(*) FROM alerts').fetchone()[0])
    print('Victims before:', c.execute('SELECT COUNT(*) FROM ransomware_victims').fetchone()[0])
    
    # Delete dirty victims
    c.execute("DELETE FROM ransomware_victims WHERE victim_name LIKE '%@%' OR victim_name LIKE '%http%' OR victim_name LIKE '%.onion%' OR victim_name LIKE '%NEWS We will%' OR LENGTH(victim_name) > 40")
    
    # Delete all alerts and recalculate/reduce fatigue
    c.execute("DELETE FROM alerts")
    
    conn.commit()
    print('Alerts after:', c.execute('SELECT COUNT(*) FROM alerts').fetchone()[0])
    print('Victims after:', c.execute('SELECT COUNT(*) FROM ransomware_victims').fetchone()[0])
    conn.close()

if __name__ == '__main__':
    clean_db()
