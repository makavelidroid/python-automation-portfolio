import csv
import requests
from bs4 import BeautifulSoup

TARGET_URL = "https://books.toscrape.com"

OUTPUT_CSV = "scraped_products.csv"


def scrape_products():
    print(f"Fetching data from {TARGET_URL}...\n")
    headers = {"User-Agent": "CyberGuard-Scraper/1.0"}

    try:
        response = requests.get(TARGET_URL, headers=headers, timeout=10)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        print("Failed to fetch page:", e)
        return

    soup = BeautifulSoup(response.text, "html.parser")
    items = soup.find_all("article", class_="product_pod")

    scraped_data = []

    for item in items:
        title = item.h3.a["title"]
        price_text = item.find("p", class_="price_color").text.strip()
        # Clean currency symbols so prices are ready for Excel math
        price_clean = price_text.replace("Â£", "").replace("£", "")
        availability = item.find("p", class_="instock availability").text.strip()

        scraped_data.append({
            "Product_Title": title,
            "Price_GBP": price_clean,
            "Availability": availability
        })

    # Export to CSV
    with open(OUTPUT_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["Product_Title", "Price_GBP", "Availability"])
        writer.writeheader()
        writer.writerows(scraped_data)

    print(f"Scraped {len(scraped_data)} products successfully!")
    for product in scraped_data[:5]:
        print(f"- {product['Product_Title'][:40]:<40} | £{product['Price_GBP']} | {product['Availability']}")

    print(f"\nFull spreadsheet saved to: {OUTPUT_CSV}")


if __name__ == "__main__":
    scrape_products()
