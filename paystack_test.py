import requests

# 1. Make sure you paste your REAL Test Secret Key from Paystack here:
SECRET_KEY = "sk_test_your_secret_key_here"

url = "https://paystack.co"

headers = {
    "Authorization": f"Bearer {SECRET_KEY}",
    "Content-Type": "application/json",
    "User-Agent": "CyberGuard-App/1.0"  # Prevents Cloudflare 403 blocks on default Python user-agents
}

payload = {
    "email": "nkululeko@example.com",
    "amount": 5000,  # R50.00 in cents
    "currency": "ZAR"
}

try:
    response = requests.post(url, json=payload, headers=headers, timeout=10)
    print(f"HTTP Status Code: {response.status_code}")

    if response.status_code == 200:
        data = response.json()
        print("Payment Link Created!")
        print(f"Reference: {data['data']['reference']}")
        print(f"Open this link to pay: {data['data']['authorization_url']}")
    else:
        print("Response Headers:", response.headers.get("Server"))
        print("Response Body:", response.text[:300] or "[Empty Body]")

except requests.exceptions.RequestException as e:
    print("Network Error:", e)
