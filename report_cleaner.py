import pandas as pd

INPUT_FILE = "output.csv"  # Change to buyer's raw .csv or .xlsx file
OUTPUT_FILE = "cleaned_output.csv"
SAMPLE_FILE = "cleaned_sample_10_rows.csv"

def clean_dataset():
    # Load CSV or Excel automatically
    if INPUT_FILE.endswith((".xlsx", ".xls")):
        df = pd.read_excel(INPUT_FILE)
    else:
        df = pd.read_csv(INPUT_FILE)

    initial_rows = len(df)

    # 1. Strip extra whitespace from column names and text cells
    df.columns = [col.strip() for col in df.columns]
    for col in df.select_dtypes(include=["object", "string"]).columns:
        df[col] = df[col].astype(str).str.strip().replace({"nan": "", "None": ""})

    # 2. Drop completely empty rows and exact duplicate rows
    df = df.dropna(how="all").drop_duplicates()

    # 3. Save Excel-safe full file & 10-row sample preview
    df.to_csv(OUTPUT_FILE, index=False, encoding="utf-8-sig")
    df.head(10).to_csv(SAMPLE_FILE, index=False, encoding="utf-8-sig")

    print(f"Done! Cleaned {initial_rows} -> {len(df)} rows (removed {initial_rows - len(df)} duplicates/blanks).")
    print(f"Saved {OUTPUT_FILE} and {SAMPLE_FILE}")

if __name__ == "__main__":
    clean_dataset()
