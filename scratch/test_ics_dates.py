import asyncio
import httpx
import csv
import io
import re

_ICS_CSV_URL = (
    "https://raw.githubusercontent.com/icsadvprj/ICS-Advisory-Project/main/"
    "ICS-CERT_ADV/CISA_ICS_ADV_Master.csv"
)

def _month_name_to_number(month_str: str):
    if not month_str:
        return None
    month_str = month_str.strip().lower()[:3]
    mapping = {
        "jan": 1, "feb": 2, "mar": 3, "apr": 4,
        "may": 5, "jun": 6, "jul": 7, "aug": 8,
        "sep": 9, "oct": 10, "nov": 11, "dec": 12,
    }
    return mapping.get(month_str)

def _parse_date(date_str: str):
    if not date_str:
        return None, None
    s = str(date_str).strip()
    if not s:
        return None, None
    s = s.replace("\u2013", "-").replace("\u2014", "-").replace("/", "-")
    s = re.sub(r"\s+", " ", s)
    s = s.split("T")[0]

    # Try ISO formats
    m = re.match(r"^(\d{4})-(\d{1,2})-(\d{1,2})", s)
    if m:
        return int(m.group(1)), int(m.group(2))

    # Try US-style dates
    m = re.match(r"^(\d{1,2})-(\d{1,2})-(\d{4})", s)
    if m:
        return int(m.group(3)), int(m.group(1))

    # Try month name formats
    m = re.match(r"^([A-Za-z]+)\s+(\d{1,2}),?\s+(\d{4})", s)
    if m:
        month = _month_name_to_number(m.group(1))
        if month:
            return int(m.group(3)), month
    m = re.match(r"^(\d{1,2})\s+([A-Za-z]+),?\s+(\d{4})", s)
    if m:
        month = _month_name_to_number(m.group(2))
        if month:
            return int(m.group(3)), month

    return None, None

async def main():
    async with httpx.AsyncClient() as client:
        r = await client.get(_ICS_CSV_URL)
        r.raise_for_status()
    reader = csv.DictReader(io.StringIO(r.text))
    count = 0
    parsed = 0
    unparsed = []
    for row in reader:
        count += 1
        rel_date = row.get("Original_Release_Date", "").strip()
        upd_date = row.get("Last_Updated", "").strip()
        year, month = _parse_date(rel_date or upd_date)
        if year or month:
            parsed += 1
        else:
            unparsed.append((rel_date, upd_date))
    print(f"Total: {count}, Parsed: {parsed}, Unparsed: {len(unparsed)}")
    print("Sample unparsed:")
    for item in unparsed[:20]:
        print(item)

asyncio.run(main())
