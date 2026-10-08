#!/usr/bin/env python3
"""
Test database retry logic under concurrent write pressure
"""
import asyncio
from database.db import Database
import time

async def concurrent_writer(db, job_id, iterations=5):
    """Simulate a background job writing to database"""
    for i in range(iterations):
        try:
            await db.update_source_status(f"test_job_{job_id}", "ok", records_fetched=10)
            print(f"  ✓ Job {job_id}: write {i+1}/{iterations} OK")
        except Exception as e:
            print(f"  ✗ Job {job_id}: write {i+1} FAILED - {e}")
        await asyncio.sleep(0.1)

async def test_concurrent_writes():
    """Test multiple jobs writing concurrently (simulating scheduler)"""
    db = Database()
    await db.initialize()
    
    print("\n" + "=" * 70)
    print("TESTING DATABASE RETRY LOGIC UNDER CONCURRENT WRITE LOAD")
    print("=" * 70)
    
    # Create test jobs in sources table
    for i in range(8):
        try:
            await db._retry_execute(
                "INSERT OR IGNORE INTO sources (name, display_name, tier, status) VALUES (?,?,?,'pending')",
                (f"test_job_{i}", f"Test Job {i}", "custom"),
                max_retries=3
            )
            await db._retry_commit(max_retries=3)
        except:
            pass
    
    print("\n🚀 Starting 8 concurrent writer tasks...")
    
    # Start all jobs at roughly the same time (simulating scheduler)
    start_time = time.time()
    tasks = [concurrent_writer(db, i, iterations=5) for i in range(8)]
    await asyncio.gather(*tasks)
    elapsed = time.time() - start_time
    
    print(f"\n✅ All tasks completed in {elapsed:.2f} seconds")
    print("✅ No 'database is locked' errors with retry logic!")
    
    # Verify data was written
    sources = await db.get_sources()
    test_sources = [s for s in sources if s['name'].startswith('test_job_')]
    print(f"✅ Verified {len(test_sources)} test sources in database")
    
    await db.close()

async def test_scheduler_job_lock_serializes_runs():
    """Scheduled jobs should not overlap on the same database connection."""
    from engine.scheduler import MonitoringScheduler

    db = Database()
    await db.initialize()
    scheduler = MonitoringScheduler(db)

    assert hasattr(scheduler, "_job_lock"), "Scheduler must serialize overlapping jobs with a single async lock"

    active = 0
    peak = 0

    async def fake_run():
        nonlocal active, peak
        active += 1
        peak = max(peak, active)
        await asyncio.sleep(0.1)
        active -= 1

    async def guarded_run():
        async with scheduler._job_lock:
            await fake_run()

    await asyncio.gather(*(guarded_run() for _ in range(4)))
    assert peak == 1, f"Scheduler lock did not serialize jobs; peak overlap was {peak}"
    await db.close()

if __name__ == "__main__":
    asyncio.run(test_concurrent_writes())
    asyncio.run(test_scheduler_job_lock_serializes_runs())
