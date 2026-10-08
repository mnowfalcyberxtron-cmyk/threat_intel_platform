#!/usr/bin/env python3
"""Test Excel export filtering for ICS advisories."""
import asyncio
import os
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

async def test_export_filters():
    from api.export import export_excel
    from database.db import Database
    from utils.excel_exporter import ExcelExporter

    db = Database()
    await db.initialize()

    # Test direct exporter filter behavior
    exporter = ExcelExporter(db, export_path="reports/test_threatintel_export.xlsx")
    path = await exporter.export(year=2026, month=5)
    print("Export path:", path)
    print("Exists:", Path(path).exists())

    # Cleanup
    if Path(path).exists():
        Path(path).unlink()
    await db.close()

if __name__ == "__main__":
    asyncio.run(test_export_filters())
