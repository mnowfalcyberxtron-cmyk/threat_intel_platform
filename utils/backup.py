#!/usr/bin/env python3
"""
utils/backup.py — Database backup and maintenance utility.
Run manually or schedule via cron.

Usage:
    python utils/backup.py backup          # Creates timestamped backup
    python utils/backup.py cleanup         # Removes old logs (>30d)
    python utils/backup.py stats           # Print DB statistics
    python utils/backup.py reset-alerts    # Clear all alerts
"""

import asyncio
import shutil
import sys
import os
from datetime import datetime, timezone, timedelta
from pathlib import Path

# Add parent to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from config import settings


async def do_backup():
    """Create a timestamped backup of the SQLite database."""
    src = Path(settings.DB_PATH)
    if not src.exists():
        print(f"[!] Database not found at {src}")
        return

    backup_dir = Path("data/backups")
    backup_dir.mkdir(parents=True, exist_ok=True)

    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    dst = backup_dir / f"threat_intel_{ts}.db"
    shutil.copy2(src, dst)

    size_mb = dst.stat().st_size / (1024 * 1024)
    print(f"[+] Backup created: {dst} ({size_mb:.1f} MB)")

    # Keep only last 7 backups
    backups = sorted(backup_dir.glob("*.db"), key=lambda f: f.stat().st_mtime)
    if len(backups) > 7:
        for old in backups[:-7]:
            old.unlink()
            print(f"[~] Removed old backup: {old.name}")


async def do_cleanup():
    """Remove old logs and low-value entries from the database."""
    import aiosqlite
    from datetime import timedelta

    db_path = settings.DB_PATH
    cutoff_30d = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()
    cutoff_90d = (datetime.now(timezone.utc) - timedelta(days=90)).isoformat()

    async with aiosqlite.connect(db_path) as conn:
        # Remove debug/info logs older than 30 days
        result = await conn.execute(
            "DELETE FROM logs WHERE timestamp < ? AND level IN ('INFO','DEBUG')",
            (cutoff_30d,)
        )
        log_deleted = result.rowcount
        await conn.commit()
        print(f"[+] Deleted {log_deleted} old log entries")

        # Remove acknowledged alerts older than 30 days
        result = await conn.execute(
            "DELETE FROM alerts WHERE acknowledged=1 AND created_at < ?",
            (cutoff_30d,)
        )
        alert_deleted = result.rowcount
        await conn.commit()
        print(f"[+] Deleted {alert_deleted} old acknowledged alerts")

        # Remove low-confidence IOCs older than 90 days with only 1 source
        result = await conn.execute(
            """DELETE FROM iocs
               WHERE confidence_label='low'
               AND source_count=1
               AND last_seen < ?""",
            (cutoff_90d,)
        )
        ioc_deleted = result.rowcount
        await conn.commit()
        print(f"[+] Pruned {ioc_deleted} stale low-confidence IOCs")

        # VACUUM to reclaim space
        await conn.execute("VACUUM")
        print("[+] Database vacuumed")


async def do_stats():
    """Print database statistics."""
    import aiosqlite

    db_path = settings.DB_PATH
    if not Path(db_path).exists():
        print("[!] Database not found")
        return

    async with aiosqlite.connect(db_path) as conn:
        conn.row_factory = aiosqlite.Row

        async def count(table, where=""):
            async with conn.execute(f"SELECT COUNT(*) FROM {table} {where}") as cur:
                return (await cur.fetchone())[0]

        print("\n=== CyberXTron TIP — Database Statistics ===\n")
        print(f"  Total IOCs:              {await count('iocs'):>8,}")
        high_conf = await count("iocs", "WHERE confidence_label='high'")
        print(f"  High-confidence IOCs:    {high_conf:>8,}")
        print(f"  Ransomware victims:      {await count('ransomware_victims'):>8,}")
        print(f"  Total alerts:            {await count('alerts'):>8,}")
        print(f"  Unacked alerts:          {await count('alerts', 'WHERE acknowledged=0'):>8,}")
        print(f"  Log entries:             {await count('logs'):>8,}")
        print(f"  Reports generated:       {await count('reports'):>8,}")

        async with conn.execute(
            "SELECT ioc_type, COUNT(*) as cnt FROM iocs GROUP BY ioc_type ORDER BY cnt DESC"
        ) as cur:
            rows = await cur.fetchall()
        print("\n  IOC Type Breakdown:")
        for row in rows:
            print(f"    {row['ioc_type']:<12} {row['cnt']:>8,}")

        db_size = Path(db_path).stat().st_size / (1024 * 1024)
        print(f"\n  Database size: {db_size:.2f} MB")
        print(f"  Path: {Path(db_path).absolute()}\n")


async def do_reset_alerts():
    """Delete all alerts."""
    import aiosqlite
    confirm = input("Are you sure you want to delete ALL alerts? (yes/no): ")
    if confirm.lower() != "yes":
        print("Aborted.")
        return
    async with aiosqlite.connect(settings.DB_PATH) as conn:
        await conn.execute("DELETE FROM alerts")
        await conn.commit()
    print("[+] All alerts deleted.")


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "stats"
    commands = {
        "backup": do_backup,
        "cleanup": do_cleanup,
        "stats": do_stats,
        "reset-alerts": do_reset_alerts,
    }
    fn = commands.get(cmd)
    if not fn:
        print(f"Unknown command: {cmd}")
        print(f"Available: {', '.join(commands)}")
        sys.exit(1)
    asyncio.run(fn())
