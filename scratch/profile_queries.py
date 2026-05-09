
import asyncio
import aiosqlite
import time

async def profile():
    db_path = "data/threat_intel.db"
    async with aiosqlite.connect(db_path) as db:
        db.row_factory = aiosqlite.Row
        
        queries = [
            ("IOC Combined", "SELECT COUNT(*) as total, SUM(CASE WHEN confidence_label='high' THEN 1 ELSE 0 END) as high_conf, SUM(CASE WHEN updated_at >= datetime('now','-1 day') THEN 1 ELSE 0 END) as new_24h FROM iocs WHERE ioc_type <> 'onion' AND NOT (ioc_type='domain' AND ioc LIKE '%.onion%')"),
            ("Victim Combined", "SELECT COUNT(*) as total, SUM(CASE WHEN discovery_date >= datetime('now','-1 day') THEN 1 ELSE 0 END) as new_24h FROM ransomware_victims"),
            ("Alert Combined", "SELECT SUM(CASE WHEN acknowledged=0 AND alert_type NOT IN ('onion_status_change','onion_new_active','darkweb_monitor') THEN 1 ELSE 0 END) as unack_intel, SUM(CASE WHEN acknowledged=0 AND alert_type IN ('onion_status_change','onion_new_active','darkweb_monitor') THEN 1 ELSE 0 END) as unack_darkweb FROM alerts"),
            ("Top Actors", "SELECT threat_actor,COUNT(*) as cnt FROM iocs WHERE threat_actor NOT IN ('unknown','') GROUP BY threat_actor ORDER BY cnt DESC LIMIT 10"),
            ("Top Groups", "SELECT group_name,COUNT(*) as victims FROM ransomware_victims WHERE discovery_date>=datetime('now','-30 days') GROUP BY group_name ORDER BY victims DESC LIMIT 10"),
            ("Daily Activity", "SELECT date(updated_at) as day,COUNT(*) as cnt FROM iocs WHERE updated_at>=datetime('now','-7 days') AND ioc_type <> 'onion' AND NOT (ioc_type='domain' AND ioc LIKE '%.onion%') GROUP BY day ORDER BY day")
        ]
        
        for name, sql in queries:
            s = time.time()
            await db.execute(sql)
            print(f"{name}: {time.time()-s:.4f}s")

asyncio.run(profile())
