import os

def main():
    print("Searching for spreadsheet files in workspace...")
    for root, dirs, files in os.walk('.'):
        # Skip venv
        if 'venv' in root or '.git' in root or '.pytest_cache' in root:
            continue
        for file in files:
            if file.endswith(('.xlsx', '.xls', '.csv', '.tsv')):
                path = os.path.join(root, file)
                print(f"Spreadsheet found: {path} (Size: {os.path.getsize(path)} bytes)")

if __name__ == "__main__":
    main()
