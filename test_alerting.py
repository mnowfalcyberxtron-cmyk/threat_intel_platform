import asyncio
from database.db import Database
from engine.alerting import AlertingEngine

async def main():
    db = Database()
    await db.initialize()
    alerting = AlertingEngine(db)

    # test evaluate_ioc
    record_ioc = {
        "ioc": "8.8.8.8",
        "ioc_type": "ip",
        "malware": "LockBit",
        "threat_actor": "Unknown",
        "source": "MockSource",
        "confidence": 0.95
    }
    print("Testing evaluate_ioc with high confidence...")
    await alerting.evaluate_ioc(9991, True, record_ioc)

    # test evaluate_victim
    record_vic = {
        "group_name": "MockGroup",
        "victim_name": "MockCompany",
        "country": "USA",
        "industry": "Tech",
        "source": "MockSource"
    }
    print("Testing evaluate_victim...")
    await alerting.evaluate_victim(9992, True, record_vic)

    # fetch latest alerts
    alerts = await db.get_alerts(limit=5)
    print("Latest alerts:")
    for a in alerts:
        if "Mock" in a.get("title", "") or "Mock" in a.get("description", "") or "LockBit" in a.get("title", ""):
            print(f"- {a['title']} | {a['alert_type']} | {a['severity']}")

    await db.close()

if __name__ == "__main__":
    asyncio.run(main())
