import pandas as pd

def main():
    path = "scratch/threat_intel_input.xlsx"
    xls = pd.ExcelFile(path)
    print("Sheets in Excel file:", xls.sheet_names)
    
    for sheet_name in xls.sheet_names:
        df = pd.read_excel(path, sheet_name=sheet_name)
        print(f"\n--- Sheet: {sheet_name} ---")
        print(f"Shape: {df.shape}")
        print("Columns:", df.columns.tolist())
        print("First 5 rows:")
        print(df.head(5))

if __name__ == "__main__":
    main()
