import requests
import csv
import io

url = "https://raw.githubusercontent.com/icsadvprj/ICS-Advisory-Project/main/ICS-CERT_ADV/CISA_ICS_ADV_Master.csv"
headers = {"User-Agent": "Mozilla/5.0"}

try:
    r = requests.get(url, headers=headers, stream=True, timeout=15)
    print(f"Status: {r.status_code}")
    if r.status_code == 200:
        # Read the first few chunks to parse headers and a few lines
        lines = []
        for chunk in r.iter_content(chunk_size=1024 * 50, decode_unicode=True):
            if chunk:
                lines.append(chunk)
                if len(lines) > 2: # Keep it small
                    break
        
        csv_text = "".join(lines)
        reader = csv.reader(io.StringIO(csv_text))
        headers_row = next(reader)
        print("Columns:")
        for idx, col in enumerate(headers_row):
            print(f"{idx}: {col}")
        
        # Print first actual data row
        try:
            first_row = next(reader)
            print("\nFirst row sample:")
            for col, val in zip(headers_row, first_row):
                print(f"  {col}: {val}")
        except StopIteration:
            print("No data rows read in the sample.")
    else:
        print(r.text)
except Exception as e:
    print(f"Error: {e}")
