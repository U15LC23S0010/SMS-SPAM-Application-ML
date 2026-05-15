from email.mime.text import MIMEText

try:
    body = "Hello, this is a test with Kannada characters: ಲಾಟರಿ"
    msg = MIMEText(body)
    print("MIMEText created successfully with default encoding.")
except Exception as e:
    print(f"MIMEText failed with default encoding: {e}")

try:
    msg = MIMEText(body, "plain", "utf-8")
    print("MIMEText created successfully with utf-8 encoding.")
except Exception as e:
    print(f"MIMEText failed with utf-8 encoding: {e}")
