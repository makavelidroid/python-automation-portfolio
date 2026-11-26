import csv
from playwright.sync_api import sync_playwright

TARGET_URL = "https://quotes." + "toscrape" + ".com/js/"
FIELDNAMES = ["quote", "author", "tags"]

def scrape_dynamic_site():
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        page.goto(TARGET_URL, wait_until="networkidle", timeout=30000)

        page.wait_for_selector("div.quote")
        quotes = page.query_selector_all("div.quote")
        print(f"Dynamic JS items rendered: {len(quotes)}")

        rows = []
        for q in quotes:
            text = q.query_selector("span.text").inner_text().strip()
            author = q.query_selector("small.author").inner_text().strip()
            tags = ", ".join([t.inner_text().strip() for t in q.query_selector_all("a.tag")])
            rows.append({"quote": text, "author": author, "tags": tags})

        browser.close()

    with open("dynamic_sample_10_rows.csv", "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
        writer.writeheader()
        writer.writerows(rows[:10])

    print(f"Done! Saved {len(rows[:10])} dynamic rows to dynamic_sample_10_rows.csv")

if __name__ == "__main__":
    scrape_dynamic_site()
