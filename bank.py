import requests

# Replace this with your actual Test Secret Key from your Paystack dashboard
SECRET_KEY = "sk_test_your_secret_key_here"

url = "https://paystack.co"

headers = {
    "Authorization": f"Bearer {SECRET_KEY}",
    "Content-Type": "application/json"
}

# Paystack expects amounts in cents (5000 = R50.00)
payload = {
    "email": "nkululeko@example.com",
    "amount": 5000,
    "currency": "ZAR"
}

response = requests.post(url, json=payload, headers=headers)
data = response.json()

if data.get("status"):
    auth_url = data["data"]["authorization_url"]
    reference = data["data"]["reference"]
    print("Payment Link Created!")
    print(f"Reference: {reference}")
    print(f"Open this link to pay: {auth_url}")
else:
    print("Error:", data.get("message"))
import hashlib
import getpass
import json
import os
import logging

DATA_FILE = "account_data.json"
LOG_FILE = "security_audit.log"

# Configure security audit logger
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)


class BankAccount:
    def __init__(self, owner, pin, admin_key, balance=500):
        self.owner = owner
        self.pin_hash = self._hash_pin(pin)
        self.admin_hash = self._hash_pin(admin_key)
        self.balance = balance
        self.locked = False
        self.load_data()

    def _hash_pin(self, secret):
        return hashlib.sha256(secret.encode()).hexdigest()

    def load_data(self):
        if os.path.exists(DATA_FILE):
            with open(DATA_FILE, "r") as f:
                data = json.load(f)
                self.balance = data.get("balance", self.balance)
                self.locked = data.get("locked", False)

    def save_data(self):
        with open(DATA_FILE, "w") as f:
            json.dump({"balance": self.balance, "locked": self.locked}, f)

    def admin_unlock(self):
        print("\n[LOCKED] Account is locked due to multiple failed PIN attempts.")
        choice = input("Enter 'A' for Admin Unlock or any other key to exit: ").strip().upper()
        if choice == "A":
            entered_key = getpass.getpass("Enter Admin Master Key: ")
            if self._hash_pin(entered_key) == self.admin_hash:
                self.locked = False
                self.save_data()
                logging.warning(f"ADMIN OVERRIDE: Account for {self.owner} unlocked by admin.")
                print("Account successfully unlocked! Please log in again.")
            else:
                logging.critical(f"SECURITY ALERT: Failed Admin Unlock attempt on {self.owner}'s account.")
                print("Invalid Admin Key. Access denied.")

    def verify_pin(self):
        if self.locked:
            logging.warning(f"BLOCKED ACCESS: Login attempt on locked account ({self.owner}).")
            self.admin_unlock()
            return False

        attempts = 3
        while attempts > 0:
            entered_pin = getpass.getpass("Enter your 4-digit PIN: ")
            if self._hash_pin(entered_pin) == self.pin_hash:
                logging.info(f"LOGIN SUCCESS: {self.owner} authenticated.")
                print(f"\nAccess granted. Welcome, {self.owner}!")
                return True
            else:
                attempts -= 1
                logging.warning(f"FAILED LOGIN: Incorrect PIN for {self.owner}. ({attempts} attempts left)")
                print(f"Incorrect PIN. {attempts} attempt(s) remaining.")

        self.locked = True
        self.save_data()
        logging.critical(f"ACCOUNT LOCKED: {self.owner} exceeded max PIN attempts.")
        print("\n[ALERT] Account locked due to too many failed attempts.")
        return False

    def deposit(self, amount):
        if amount > 0:
            self.balance += amount
            self.save_data()
            logging.info(f"DEPOSIT: {self.owner} deposited R{amount:.2f}. Balance: R{self.balance:.2f}")
            print(f"Deposited R{amount:.2f}. New balance: R{self.balance:.2f}")
        else:
            print("Deposit must be greater than 0.")

    def withdraw(self, amount):
        if amount > self.balance:
            logging.warning(f"DECLINED WITHDRAWAL: {self.owner} tried to withdraw R{amount:.2f} (Balance: R{self.balance:.2f})")
            print("Insufficient funds.")
        elif amount <= 0:
            print("Withdrawal must be greater than 0.")
        else:
            self.balance -= amount
            self.save_data()
            logging.info(f"WITHDRAWAL: {self.owner} withdrew R{amount:.2f}. Balance: R{self.balance:.2f}")
            print(f"Withdrew R{amount:.2f}. New balance: R{self.balance:.2f}")

    def check_balance(self):
        logging.info(f"BALANCE CHECK: {self.owner} viewed balance (R{self.balance:.2f}).")
        print(f"{self.owner}'s current balance: R{self.balance:.2f}")


# --- Run Cyber-Guard ATM ---
# User PIN: 1234 | Admin Master Key: admin999
account = BankAccount("Nkululeko", "1234", "admin999", 500)

if account.verify_pin():
    while True:
        print("\n--- CYBER-GUARD ATM ---")
        print("1. Check Balance")
        print("2. Deposit")
        print("3. Withdraw")
        print("4. View Security Audit Log")
        print("5. Exit")

        choice = input("Select an option (1-5): ")

        if choice == "1":
            account.check_balance()
        elif choice == "2":
            try:
                amt = float(input("Enter deposit amount (R): "))
                account.deposit(amt)
            except ValueError:
                print("Please enter a valid number.")
        elif choice == "3":
            try:
                amt = float(input("Enter withdrawal amount (R): "))
                account.withdraw(amt)
            except ValueError:
                print("Please enter a valid number.")
        elif choice == "4":
            print("\n--- SECURITY AUDIT LOG ---")
            if os.path.exists(LOG_FILE):
                with open(LOG_FILE, "r") as log:
                    print(log.read())
        elif choice == "5":
            logging.info(f"LOGOUT: {self.owner if hasattr(account, 'owner') else 'User'} ended session.")
            print("Goodbye! Session closed.")
            break
        else:
            print("Invalid choice. Pick 1-5.")
