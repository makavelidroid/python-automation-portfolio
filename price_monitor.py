import csv
from datetime import datetime
from pathlib import Path
import requests
from bs4 import BeautifulSoup

BASE = "https://books." + "toscrape" + ".com/catalogue/"
URLS = [
    BASE + "a-light-in-the-attic_1000/index.html",
    BASE + "tipping-the-velvet_999/index.html",
]
LOG_FILE = Path("price_history.csv")
HEADERS = {"User-Agent": "Mozilla/5.0"}

def check_prices():
    rows = []
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    for url in URLS:
        resp = requests.get(url, headers=HEADERS, timeout=15)
        resp.encoding = "utf-8"
        soup = BeautifulSoup(resp.text, "html.parser")

        title_el = soup.select_one("div.product_main h1")
        price_el = soup.select_one("p.price_color")
        stock_el = soup.select_one("p.instock.availability")

        if not title_el or not price_el:
            print(f"Skipping {url} (elements not found)")
            continue

        rows.append({
            "checked_at": timestamp,
            "title": title_el.get_text(strip=True),
            "price": price_el.get_text(strip=True),
            "availability": stock_el.get_text(strip=True) if stock_el else "Unknown",
            "url": url,
        })

    file_exists = LOG_FILE.exists()
    with open(LOG_FILE, "a", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=["checked_at", "title", "price", "availability", "url"])
        if not file_exists:
            writer.writeheader()
        writer.writerows(rows)

    print(f"Logged {len(rows)} price checks to {LOG_FILE}")

if __name__ == "__main__":
    check_prices()
