import csv
import os

RAW_FILE = "messy_sales.csv"
CLEAN_FILE = "cleaned_sales.csv"
SUMMARY_FILE = "sales_summary.txt"


def create_sample_messy_csv():
    """Creates a realistic messy business CSV for testing."""
    sample_rows = [
        ["Order_ID", "Customer", "City", "Amount"],
        ["1001", "  thabo mokoena ", "cape town", "R1,250.00"],
        ["1002", "Sarah Jenkins", "JOHANNESBURG ", "850.50"],
        ["1001", "  thabo mokoena ", "cape town", "R1,250.00"],  # Duplicate row
        ["1003", "sipho ndlovu", "  durban", "R 2,100"],
        ["1004", "Amina Patel", "Cape Town", ""],  # Missing amount
        ["1005", "  liam smith", "pretoria", "R499.99"],
        ["1006", "", "Durban", "300"],  # Missing customer name
    ]
    with open(RAW_FILE, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerows(sample_rows)
    print(f"Created sample messy file: {RAW_FILE}")


def clean_amount(raw_val):
    """Strips 'R', spaces, and commas, then converts to float."""
    if not raw_val or not raw_val.strip():
        return None
    cleaned = raw_val.replace("R", "").replace(",", "").strip()
    try:
        return float(cleaned)
    except ValueError:
        return None


def process_report():
    if not os.path.exists(RAW_FILE):
        create_sample_messy_csv()

    seen_orders = set()
    cleaned_rows = []
    city_totals = {}
    duplicates_removed = 0
    invalid_rows_skipped = 0
    total_revenue = 0.0

    with open(RAW_FILE, "r", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            order_id = row["Order_ID"].strip()

            # 1. Skip duplicate Order IDs
            if order_id in seen_orders:
                duplicates_removed += 1
                continue

            # 2. Validate and clean the monetary amount
            amount = clean_amount(row["Amount"])
            if amount is None:
                invalid_rows_skipped += 1
                continue

            # 3. Standardize text formatting (Title Case & trimmed spaces)
            customer = row["Customer"].strip().title() or "Unknown Customer"
            city = row["City"].strip().title() or "Unspecified"

            seen_orders.add(order_id)
            total_revenue += amount
            city_totals[city] = city_totals.get(city, 0.0) + amount

            cleaned_rows.append({
                "Order_ID": order_id,
                "Customer": customer,
                "City": city,
                "Amount_ZAR": f"{amount:.2f}"
            })

    # Write cleaned CSV
    with open(CLEAN_FILE, "w", newline="") as f:
        fieldnames = ["Order_ID", "Customer", "City", "Amount_ZAR"]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(cleaned_rows)

    # Generate executive summary report
    summary_lines = [
        "--- AUTOMATED SALES DATA SUMMARY ---",
        f"Valid Orders Processed : {len(cleaned_rows)}",
        f"Duplicates Removed     : {duplicates_removed}",
        f"Incomplete Rows Skipped: {invalid_rows_skipped}",
        f"Total Clean Revenue    : R{total_revenue:,.2f}",
        "\n--- REVENUE BY CITY ---"
    ]
    for city, total in sorted(city_totals.items(), key=lambda x: x[1], reverse=True):
        summary_lines.append(f"{city:<15}: R{total:,.2f}")

    summary_text = "\n".join(summary_lines)
    with open(SUMMARY_FILE, "w") as f:
        f.write(summary_text + "\n")

    print("\n" + summary_text)
    print(f"\nSaved clean spreadsheet to: {CLEAN_FILE}")
    print(f"Saved summary report to   : {SUMMARY_FILE}")


if __name__ == "__main__":
    process_report()

