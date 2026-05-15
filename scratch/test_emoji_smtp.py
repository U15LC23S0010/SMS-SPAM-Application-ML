import os
import smtplib
from email.mime.text import MIMEText
from email.header import Header
from dotenv import load_dotenv

load_dotenv()
EMAIL_USER = os.getenv("EMAIL_USER")
EMAIL_PASS = os.getenv("EMAIL_PASS")

def test_emoji_subject():
    print(f"Testing SMTP with emojis for {EMAIL_USER}...")
    try:
        subject = "🚨 SECURITY ALERT: Test With Emojis"
        body = "Hello! This is a test email with emojis in the subject."
        
        msg = MIMEText(body, 'plain', 'utf-8')
        # Without Header wrapper, this might fail on some systems
        msg["Subject"] = subject 
        msg["From"] = EMAIL_USER
        msg["To"] = EMAIL_USER

        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(EMAIL_USER, EMAIL_PASS)
            server.send_message(msg)
            print("Emoji test email sent successfully!")
        return True
    except Exception as e:
        print(f"Emoji test failed: {e}")
        return False

if __name__ == "__main__":
    test_emoji_subject()
