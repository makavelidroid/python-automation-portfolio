import requests
import pandas as pd

API_URL = "https://jsonplaceholder." + "typicode" + ".com/users"

def extract_api_to_csv():
    resp = requests.get(API_URL, timeout=15)
    resp.raise_for_status()
    data = resp.json()

    df = pd.json_normalize(data)
    keep_cols = ["id", "name", "username", "email", "phone", "website", "address.city", "company.name"]
    df = df[keep_cols]

    df.to_csv("api_output.csv", index=False, encoding="utf-8-sig")
    print(f"Done! Extracted {len(df)} flattened API records to api_output.csv")

if __name__ == "__main__":
    extract_api_to_csv()
