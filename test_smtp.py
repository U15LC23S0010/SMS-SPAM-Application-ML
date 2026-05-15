import os
import smtplib
from email.mime.text import MIMEText
from dotenv import load_dotenv

# Load credentials from .env
load_dotenv()
EMAIL_USER = os.getenv("EMAIL_USER")
EMAIL_PASS = os.getenv("EMAIL_PASS")

def test_smtp():
    print(f"Testing SMTP for {EMAIL_USER}...")
    try:
        msg = MIMEText("Hello! This is a test email from your SMS AI Platform to verify SMTP settings.")
        msg["Subject"] = "SMTP Test Connection"
        msg["From"] = EMAIL_USER
        msg["To"] = EMAIL_USER  # Send to self

        # Connect to Gmail SMTP
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            print("Connecting to smtp.gmail.com:465...")
            server.login(EMAIL_USER, EMAIL_PASS)
            print("Login successful!")
            server.send_message(msg)
            print("Test email sent successfully to itself!")
        return True
    except Exception as e:
        print(f"SMTP Test Failed: {e}")
        return False

if __name__ == "__main__":
    test_smtp()
