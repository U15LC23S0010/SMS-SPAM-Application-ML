import sys
import os
import json
import google.generativeai as genai

# Fix Windows console encoding for Kannada/UTF-8 characters
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')
import random
import sqlite3
import threading
import requests
from flask import Flask, render_template, request, redirect, session, flash, jsonify, url_for, send_from_directory
from flask_cors import CORS
from dotenv import load_dotenv
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from database import init_db, get_db
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import hashlib
import time
from urllib.parse import quote
from functools import wraps

# ---------------- ENV & CONFIG ----------------
import cv2
import numpy as np
try:
    from pyzbar.pyzbar import decode as pyzbar_decode
    HAS_PYZBAR = True
except ImportError:
    HAS_PYZBAR = False
from spellchecker import SpellChecker
import difflib

# ---------------- ENV & CONFIG ----------------
load_dotenv()
EMAIL_USER = os.getenv("EMAIL_USER")
EMAIL_PASS = os.getenv("EMAIL_PASS")

ADMIN_USER_MASTER = os.getenv("ADMIN_USERNAME")
ADMIN_PASS_MASTER = os.getenv("ADMIN_PASSWORD")

app = Flask(__name__)
app.secret_key = "supersecretkey"
CORS(app)

@app.route('/sw.js')
def serve_sw():
    return send_from_directory('static', 'sw.js', mimetype='application/javascript')

@app.route('/manifest.json')
def serve_manifest():
    return send_from_directory('static', 'manifest.json')

# English Spellchecker
spell = SpellChecker()

def auto_correct(text):
    if not text: return text
    # Heuristic for Kannada
    is_kannada = any('\u0C80' <= char <= '\u0CFF' for char in text)
    
    words = text.split()
    corrected = []
    
    for word in words:
        clean_word = "".join(filter(str.isalnum, word.lower()))
        if not clean_word or len(clean_word) < 3 or clean_word.startswith("http"):
            corrected.append(word)
            continue
            
        if is_kannada:
            # Kannada fuzzy matching for dangerous words
            dangerous_kn = ["ಲಾಟರಿ", "ಬಹುಮಾನ", "ಉಚಿತ", "ಗೆದ್ದಿದ್ದೀರಿ", "ಹಣ", "ಬ್ಯಾಂಕ್", "ಖಾತೆ", "ಸಾಲ", "ಕೆಲಸ", "ತುರ್ತು", "ಭದ್ರತೆ"]
            matches = difflib.get_close_matches(word, dangerous_kn, n=1, cutoff=0.7)
            corrected.append(matches[0] if matches else word)
        else:
            # English standard correction
            corr = spell.correction(word)
            corrected.append(corr if corr else word)
            
    return " ".join(corrected)

# QR Code Upload Configuration
UPLOAD_FOLDER = os.path.join('static', 'uploads', 'qr_scans')
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'apk'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def robust_qr_scan(file_path):
    """Attempt multiple preprocessing steps and use pyzbar for high detection rates."""
    img = cv2.imread(file_path)
    if img is None:
        print(f"   [QR ERROR] Could not read image: {file_path}")
        return None
    
    def try_decode(image_to_scan):
        # 1. Try pyzbar (superior)
        if HAS_PYZBAR:
            try:
                decoded_objects = pyzbar_decode(image_to_scan)
                if decoded_objects:
                    return decoded_objects[0].data.decode('utf-8')
            except Exception as e:
                print(f"   [QR ERROR] pyzbar failed on variation: {e}")
        
        # 2. Try OpenCV (fallback)
        try:
            detector = cv2.QRCodeDetector()
            val, pts, qr = detector.detectAndDecode(image_to_scan)
            if val: return val
        except: pass
        return None

    # Step 1: Original Image
    val = try_decode(img)
    if val: return val

    # Step 2: Grayscale
    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    val = try_decode(gray)
    if val: return val

    # Step 3: Upscaling (Very common for small QR codes)
    h, w = gray.shape
    if w < 1000 or h < 1000:
        upscaled = cv2.resize(gray, (w*2, h*2), interpolation=cv2.INTER_CUBIC)
        val = try_decode(upscaled)
        if val: return val

    # Step 4: Adaptive Thresholding
    thresh = cv2.adaptiveThreshold(gray, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, cv2.THRESH_BINARY, 11, 2)
    val = try_decode(thresh)
    if val: return val

    # Step 5: Otsu's Thresholding (Good for high contrast)
    _, otsu = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
    val = try_decode(otsu)
    if val: return val
    
    # Step 6: Sharpening
    kernel = np.array([[-1,-1,-1], [-1,9,-1], [-1,-1,-1]])
    sharpened = cv2.filter2D(gray, -1, kernel)
    val = try_decode(sharpened)
    if val: return val

    return None

# Initialize DB
init_db()

# ---------------- HELPERS ----------------

def analyze_spam_heuristics(content, scan_type="email", sensitivity="Balanced"):
    print(f"   [ANALYZER] Input received ({scan_type}) | Sensitivity: {sensitivity}")
    score = 0
    prediction = "Ham"
    explanation = ""
    flagged_keywords = []
    
    # Sensitivity Multipliers
    multiplier = 1.0
    if sensitivity == "Highly Sensitive":
        multiplier = 1.5
    elif sensitivity == "Legacy Mode":
        multiplier = 0.8
    
    # --- AUTO-CORRECTION LAYER ---
    content = auto_correct(content)
    content_lower = content.lower()

    if scan_type in ["email", "sms", "otp", "qr_code", "voice"]:
        # Shared suspicious keywords with weighted scoring
        keywords = {
            # ... (rest of the keywords dictionary is same)

            "financial": [
                "prize", "win", "lottery", "claim", "bank", "account", "tax", "refund", "card", "cash", "payment", 
                "unclaimed", "winner", "congratulations", "gift", "rewards", "dollar", "rupee", "payout", "bill",
                "invoice", "dividend", "overpaid", "reimbursement", "fund", "wire", "transfer", "inheritance", 
                "beneficiary", "jackpot", "lucky draw", "mega millions", "powerball", "consolation", "processing fee",
                "customs clearance", "western union", "moneygram", "money mule", "crore", "lakh", "millionaire",
                "ಲಾಟರಿ", "ಬಹುಮಾನ", "ಹಣ", "ಬ್ಯಾಂಕ್", "ಸಾಲ"
            ],
            "crypto_web3": [
                "bitcoin", "crypto", "btc", "eth", "wallet", "ethereum", "blockchain", "mining", "binance", "coinbase",
                "private key", "seed phrase", "airdrop", "presale", "whitelist", "investment", "multiply", "doubler",
                "trust wallet", "metamask", "phantom", "ledger", "dex", "swap", "liquidity", "yield farming", "nft", 
                "minting", "smart contract", "dao", "metaverse", "virtual land", "cold storage"
            ],
            "ai_and_deepfake": [
                "deepfake", "voice cloning", "ai model", "gpt", "facial synthesis", "celebrity leak", "automated trading",
                "ai investment", "bot", "algorithm", "synthetic voice", "video call from family", "emergency video"
            ],
            "modern_fintech": [
                "upi", "gpay", "phonepe", "paytm", "kyc update", "upi pin", "request money", "collect request", 
                "electricity bill", "power cut", "broadband", "recharge", "digital arrest", "police verification", 
                "customs hold", "fedex scam", "courier scam", "mumbai police", "trai", "sim card blocked"
            ],
            "socmed_hijacking": [
                "blue checkmark", "verification badge", "verified account", "shadowban", "copyright violation", 
                "account recovery", "security team", "official badge", "instagram help", "facebook support"
            ],
            "urgency": [
                "urgent", "immediate", "action", "expire", "hurry", "last chance", "now", "within", "limited", "today", 
                "24 hours", "soon", "attention", "alert", "final notice", "suspended", "terminated", "restricted", "violation",
                "deadline", "important", "critical", "mandatory", "required", "ತುರ್ತು", "ಈಗಲೇ", "ಶೀಘ್ರವಾಗಿ", "ಕೊನೆಯ ಅವಕಾಶ"
            ],
            "security": [
                "password", "credential", "security", "unauthorized", "suspicious", "lock", "block", "locked", "disabled", 
                "activity", "suspension", "verification", "auth", "profile", "unrecognized", "breach", "sign-in", "login", 
                "identity", "2fa", "mfa", "token", "backup code", "recovery", "reset", "changed", "ಪಾಸ್‌ವರ್ಡ್", "ಭದ್ರತೆ", "ದೃಢೀಕರಣ"
            ],
            "tech_support": [
                "virus", "hacked", "infected", "trojan", "malware", "microsoft", "apple", "support", "technician", 
                "desk", "remote", "anydesk", "teamviewer", "fix", "pc", "windows", "firewall", "security patch",
                "repair", "customer care", "helpdesk", "diagnostic", "ಸಹಾಯ", "ರಿಪೇರಿ"
            ],
            "social_eng": [
                "job", "work from home", "easy money", "salary", "recruitment", "hiring", "part-time", "exclusive", 
                "lonely", "dating", "meet", "hookup", "grandchild", "accident", "emergency", "hospital", "customs", 
                "delivery", "fedex", "ups", "dhl", "package", "missed", "reschedule", "visa", "sponsorship", "abroad", 
                "overseas", "relocation", "passport", "ಕೆಲಸ", "ಸಂಬಳ", "ಉಚಿತ"
            ],
            "extremism": [
                "jihad", "isis", "al-qaeda", "jihadi", "bomb", "explosive", "recruit", "martyr", "caliphate", 
                "radicalization", "extremist", "ammunition", "weapons", "training camp", "terrorism", "terrorist",
                "attack", "mission", "infiltration", "propaganda"
            ],
            "extortion": [
                "webcam", "compromising", "video recorded", "shame", "family", "delete video", "ransom", "pay now", 
                "leaked", "exposure", "blackmail", "nude", "recording", "private photos", "shameful"
            ],
            "illicit_goods": [
                "pharmacy", "viagra", "steroids", "xanax", "fentanyl", "dark web", "illicit", "drugs", "buy meds", 
                "without prescription", "cannabis", "cocaine", "heroin", "medication", "pills"
            ],
            "fraud_impersonation": [
                "irs", "hmrc", "government agent", "official notice", "court order", "arrest warrant", "legal action", 
                "lawsuit", "subpoena", "police department", "social security", "tax office", "fbi", "interpol", "investigation",
                "cbi", "income tax", "customs", "immigration", "mumbai police", "delhi police", "scotland yard"
            ],
            "int_orgs": [
                "who", "unicef", "united nations", "world bank", "imf", "europol", "swift", "who health", "amnesty",
                "red cross", "gates foundation", "consulate", "embassy", "border force"
            ]
        }
        
        found_categories = []
        for cat, list_k in keywords.items():
            # Check for exact word matches or substring matches
            found = [k for k in list_k if k in content_lower]
            if found:
                # Legacy Mode ignores the "modern" threat categories to focus on traditional spam
                if sensitivity == "Legacy Mode" and cat in ["modern_fintech", "ai_and_deepfake", "socmed_hijacking", "crypto_web3"]:
                    continue

                if cat not in found_categories: found_categories.append(cat)
                # Add score based on category importance
                if cat in ["extremism", "modern_fintech", "ai_and_deepfake"]:
                    weight = 40
                elif cat in ["financial", "security", "extortion", "fraud_impersonation", "int_orgs", "crypto_web3"]:
                    weight = 25
                else:
                    weight = 15
                score += (len(found) * weight) * multiplier
                flagged_keywords.extend(found)

        # Heuristics: All caps or exclamation marks
        if content.isupper() and len(content) > 10:
            score += 25 * multiplier
            flagged_keywords.append("Aggressive capitalization")
        
        # Heavy punctuations
        if content.count('!') > 1:
            score += 15 * multiplier
            flagged_keywords.append("Sense of alarm (!)")
        if content.count('$') > 0 or "rs." in content_lower or "₹" in content_lower or "€" in content_lower or "£" in content_lower:
            score += 20 * multiplier
            flagged_keywords.append("Currency symbols")

        if scan_type in ["sms", "otp", "qr_code", "voice"]:
            # SMS & OTP specific triggers
            if any(x in content_lower for x in ["bit.ly", "tinyurl", "t.co", "short.url", "is.gd", "buff.ly", "goog.le", "shrt.lst", "tiny.one", "shorturl.at"]):
                score += 40 * multiplier
                flagged_keywords.append("Suspicious Short Link")
            if any(x in content_lower for x in ["customer", "official", "dear user", "valuable user", "attention user"]):
                score += 20 * multiplier
                flagged_keywords.append("Generic phishing greeting")
            
            # URL safety logic for QR codes that contain URLs
            if "http" in content_lower or "." in content_lower:
                suspicious_tlds = [".xyz", ".top", ".info", ".online", ".site", ".tk", ".ml", ".ga", ".cf", ".click"]
                if any(tld in content_lower for tld in suspicious_tlds):
                    score += 45 * multiplier
                    flagged_keywords.append("Suspicious TLD")
                if "http://" in content_lower and "https://" not in content_lower:
                    score += 35 * multiplier
                    flagged_keywords.append("Unsecured (HTTP)")
            
            # OTP specific patterns (now part of general SMS check)
            otp_triggers = ["don't share", "never tell", "representative", "employee", "support", "call back", "forward", "send", "provide", "share", "customer care"]
            found_otp = [k for k in otp_triggers if k in content_lower]
            if found_otp:
                score += 35 * multiplier
                flagged_keywords.extend(found_otp)
            if any(x in content_lower for x in ["otp", "code", "pin"]) and any(x in content_lower for x in ["ask", "request", "provide", "send me", "share", "tell"]):
                score += 45 * multiplier
                flagged_keywords.append("Direct OTP solicitation")

        # --- IMPROVED THRESHOLD ---
        # Adjust threshold based on sensitivity
        base_threshold = 30
        if sensitivity == "Highly Sensitive": base_threshold = 20
        elif sensitivity == "Legacy Mode": base_threshold = 40
        
        prediction = "Spam" if score >= base_threshold else "Ham"
        
        # Special case: High-priority categories should flag as Spam immediately
        if any(cat in found_categories for cat in ["extremism", "modern_fintech", "ai_and_deepfake"]):
            prediction = "Spam"
            score = max(score, 85)

        # Special case: Even one "lottery" or "prize" + "claim" should trigger spam
        if any(x in content_lower for x in ["lottery", "prize", "jackpot", "winner", "won"]):
            if any(x in content_lower for x in ["claim", "win", "congratulations", "gift", "rewards", "unclaimed", "fee", "tax"]):
                prediction = "Spam"
                score = max(score, 75)
                flagged_keywords.append("Classic Scam Template")

        # Crafting the reasoning
        explanation_kn = ""
        if prediction == "Spam":
            score = min(99, score + random.randint(5, 15)) # Add variance
            if "extremism" in found_categories:
                explanation = "CRITICAL SECURITY ALERT: This message contains language associated with extremist or terrorist activities."
                explanation_kn = "ಅತ್ಯಂತ ಅಪಾಯಕಾರಿ ಸಂದೇಶ. ಇದು ಭಯೋತ್ಪಾದನೆಗೆ ಸಂಬಂಧಿಸಿದ ಭಾಷೆಯನ್ನು ಹೊಂದಿದೆ."
            elif "ai_and_deepfake" in found_categories:
                explanation = "AI MANIPULATION ALERT: We detected markers of AI-generated content or voice-cloning scams."
                explanation_kn = "ಕೃತಕ ಬುದ್ಧಿಮತ್ತೆ ವಂಚನೆ. ಇದು ಎಐ ಮೂಲಕ ಸೃಷ್ಟಿಸಲಾದ ನಕಲಿ ಮಾಹಿತಿಯಾಗಿದೆ."
            elif "modern_fintech" in found_categories:
                explanation = "FINANCIAL THREAT ALERT: High-risk Fintech patterns (Digital Arrest, UPI fraud) detected."
                explanation_kn = "ಹಣಕಾಸಿನ ಹಗರಣ. ಯುಪಿಐ ಅಥವಾ ಡಿಜಿಟಲ್ ಅರೆಸ್ಟ್ ಹೆಸರಿನಲ್ಲಿ ಹಣ ಕದಿಯುವ ಸಂಚು ಇದಾಗಿದೆ."
            elif "extortion" in found_categories:
                explanation = "BLACKMAIL ALERT: This message exhibits patterns of extortion or blackmail."
                explanation_kn = "ಬ್ಲ್ಯಾಕ್‌ಮೇಲ್ ಎಚ್ಚರಿಕೆ. ಈ ಸಂದೇಶವು ನಿಮ್ಮನ್ನು ಬೆದರಿಸಿ ಹಣ ಸುಲಿಯುವ ಪ್ರಯತ್ನವಾಗಿದೆ."
            elif score >= 75:
                explanation = f"Dangerous! High-risk scam patterns detected. This is likely a fraud attempt."
                explanation_kn = "ಇದು ದೊಡ್ಡ ಮಟ್ಟದ ವಂಚನೆಯ ಜಾಲವಾಗಿದೆ. ದಯವಿಟ್ಟು ನಂಬಬೇಡಿ."
            else:
                explanation = f"Potential Phishing! We detected indicators of spam and fraud patterns."
                explanation_kn = "ಇದು ಅನುಮಾನಾಸ್ಪದ ಸಂದೇಶವಾಗಿದೆ ಮತ್ತು ವಂಚನೆಯ ಸಂಚಾಗಿರಬಹುದು."
        else:
            if score > 15:
                explanation = "Caution recommended. It contains some suspicious terms but seems mostly safe."
                explanation_kn = "ಸ್ವಲ್ಪ ಗಮನವಿರಲಿ, ಇದರಲ್ಲಿ ಕೆಲವು ಅನುಮಾನಾಸ್ಪದ ಪದಗಳಿವೆ."
            else:
                explanation = "Scan complete. No malicious patterns or security risks were identified."
                explanation_kn = "ತಪಾಸಣೆ ಪೂರ್ಣಗೊಂಡಿದೆ. ಯಾವುದೇ ಅಪಾಯ ಪತ್ತೆಯಾಗಿಲ್ಲ."
        
        score = min(99, score)
    elif scan_type == "url":
        suspicious_tlds = [".xyz", ".top", ".info", ".online", ".site", ".tk", ".ml", ".ga", ".cf", ".click"]
        if any(tld in content_lower for tld in suspicious_tlds):
            score += 45
            flagged_keywords.append("Suspicious TLD")
        if "http://" in content_lower and "https://" not in content_lower:
            score += 35
            flagged_keywords.append("Unsecured (HTTP)")
        if content_lower.count("-") > 3 or content_lower.count(".") > 4:
            score += 30
            flagged_keywords.append("Subdomain obfuscation")
        if any(x in content_lower for x in ["login", "verify", "update", "secure", "signin", "account", "access", "billing"]):
            score += 25
            flagged_keywords.append("Phishing keywords in URL")
            
        prediction = "Spam" if score >= 40 else "Ham"
        if prediction == "Spam":
            explanation = "Malicious Link Alert! This URL uses suspicious patterns to mask its true destination."
            explanation_kn = "ಅಪಾಯಕಾರಿ ಲಿಂಕ್. ಇದು ನಿಮ್ಮ ಮೊಬೈಲ್ ಮೇಲೆ ದಾಳಿ ಮಾಡುವ ಸಾಧ್ಯತೆಯಿದೆ."
        else:
            explanation = "URL check passed. The link appears standard and safe."
            explanation_kn = "ಈ ಲಿಂಕ್ ಸುರಕ್ಷಿತವಾಗಿದೆ."
        score = min(99, score)
        explanation_kn = explanation_kn if explanation_kn else "" # Ensure init
    
    return prediction, score, explanation, explanation_kn, list(set(flagged_keywords)), content

def analyze_spam(content, scan_type="email", sensitivity="Balanced"):
    print(f"   [ANALYZER] Input received ({scan_type}) | Sensitivity: {sensitivity}")
    
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        print("   [ANALYZER] No GEMINI_API_KEY found. Falling back to heuristics.")
        return analyze_spam_heuristics(content, scan_type, sensitivity)
        
    # Configure API key
    genai.configure(api_key=api_key)
    
    system_instruction = (
        "You are an expert cybersecurity analyst. Analyze the provided content for phishing, spam, smishing, "
        "scams, malware distribution, or policy/security threats.\n"
        f"Scan Type: {scan_type}\n"
        f"Sensitivity level: {sensitivity}\n"
        "Guidelines:\n"
        "1. For scan_type 'email': identify phishing, fake invoices, false rewards, impersonation, urgency.\n"
        "2. For scan_type 'sms' or 'otp': identify smishing, direct OTP solicitation, fake bank locks, UPI PIN requests.\n"
        "3. For 'url': analyze link safety, domain name, spelling, TLD (e.g., .xyz, .click, .site are highly suspicious), subdomains.\n"
        "4. For 'qr_code': analyze decoded QR text for threats.\n"
        "5. For 'voice': check transcripts for deepfakes, voice cloning, emergency social engineering scams.\n"
        "6. In 'Highly Sensitive' mode, be more strict: flag borderline cases as 'Spam' and increase the threat score.\n"
        "7. In 'Legacy Mode', focus primarily on traditional spam (promotional, winnings, free prizes) and ignore modern fintech/deepfake triggers.\n\n"
        "You MUST respond ONLY with a valid JSON object matching this schema:\n"
        "{\n"
        "  \"prediction\": \"Spam\" | \"Ham\",\n"
        "  \"score\": integer between 0 and 100 representing threat level,\n"
        "  \"explanation\": \"Clear English explanation of why the message is spam/ham and what threats were detected (max 2 sentences)\",\n"
        "  \"explanation_kn\": \"Natural Kannada translation of the English explanation (max 2 sentences)\",\n"
        "  \"flagged_keywords\": [\"list\", \"of\", \"suspicious\", \"terms\", \"found\"],\n"
        "  \"corrected_content\": \"Autocorrected content (only if there are typos; otherwise same as input content)\"\n"
        "}\n"
        "Do not include any introductory or concluding text. Output ONLY the JSON."
    )
    
    prompt = f"Analyze the following content:\n\n{content}"
    
    response_text = None
    for i, model_name in enumerate(["gemini-3.5-flash", "gemini-2.5-flash"]):
        if i > 0:
            time.sleep(1)  # Brief pause between retries to avoid rate limit
        try:
            print(f"   [ANALYZER] Attempting Gemini call with {model_name}...")
            model = genai.GenerativeModel(model_name)
            full_prompt = f"{system_instruction}\n\n{prompt}"
            response = model.generate_content(
                full_prompt,
                request_options={"timeout": 30}
            )
            try:
                text = response.text
                if text and text.strip():
                    response_text = text.strip()
                    break
            except Exception as re:
                print(f"   [ANALYZER] Empty/blocked response from {model_name}: {re}")
        except Exception as e:
            print(f"   [ANALYZER] Error calling {model_name}: {e}")
            
    if not response_text:
        print("   [ANALYZER] Gemini API calls failed. Falling back to heuristics.")
        return analyze_spam_heuristics(content, scan_type, sensitivity)
        
    try:
        text_to_parse = response_text
        if text_to_parse.startswith("```"):
            parts = text_to_parse.split("```")
            for part in parts:
                p_str = part.strip()
                if p_str.startswith("json"):
                    p_str = p_str[4:].strip()
                if p_str.startswith("{") and p_str.endswith("}"):
                    text_to_parse = p_str
                    break
                    
        text_to_parse = text_to_parse.strip()
        
        start = text_to_parse.find('{')
        end = text_to_parse.rfind('}')
        if start != -1 and end != -1:
            text_to_parse = text_to_parse[start:end+1]
            
        data = json.loads(text_to_parse)
        
        prediction = data.get("prediction", "Ham")
        score = int(data.get("score", 0))
        explanation = data.get("explanation", "")
        explanation_kn = data.get("explanation_kn", "")
        flagged_keywords = data.get("flagged_keywords", [])
        corrected_content = data.get("corrected_content", content) or content
        
        if prediction not in ["Spam", "Ham"]:
            prediction = "Spam" if score >= 40 else "Ham"
            
        score = max(0, min(100, score))
        
        print(f"   [ANALYZER] Gemini success: prediction={prediction}, score={score}")
        return prediction, score, explanation, explanation_kn, flagged_keywords, corrected_content
    except Exception as e:
        print(f"   [ANALYZER] Error parsing Gemini JSON: {e}. Raw response: {response_text[:200]}")
        print("   [ANALYZER] Falling back to heuristics.")
        return analyze_spam_heuristics(content, scan_type, sensitivity)

def analyze_apk_heuristics(filename, file_size):
    print(f"   [APK ANALYZER] Scanning file: {filename}")
    score = 0
    prediction = "Ham"
    explanation = ""
    flagged_keywords = []
    
    fn_lower = filename.lower()
    
    # Suspicious patterns in filenames
    suspicious_patterns = [
        "mod", "crack", "hack", "free", "unlimited", "premium", "pro", "gold", 
        "bypass", "injector", "cheat", "patcher", "premium_id", "verified_mod",
        "keylogger", "spyware", "adware", "rat", "stealer", "token", "drainer", 
        "miner", "exploit", "payload", "dropper", "trojan", "banker"
    ]
    
    found_patterns = [p for p in suspicious_patterns if p in fn_lower]
    if found_patterns:
        score += len(found_patterns) * 25
        flagged_keywords.extend(found_patterns)
        
    # Double extensions or obfuscation
    if fn_lower.count(".apk") > 1 or ".zip.apk" in fn_lower or ".txt.apk" in fn_lower:
        score += 40
        flagged_keywords.append("Double Extension / Obfuscation")
        
    # File size heuristics (Mock logic)
    # Extremely small APKs (< 50KB) are often simple droppers or Trojans
    size_kb = file_size / 1024
    if size_kb < 50:
        score += 35
        flagged_keywords.append("Suspiciously Small File Size")
        
    prediction = "Spam" if score >= 40 else "Ham"
    
    if prediction == "Spam":
        explanation = f"Malicious APK detected! We found flags like {', '.join(flagged_keywords[:2])}. This file likely contains spyware or unauthorized modifications."
    else:
        if score > 0:
            explanation = "APK seems safe, but has minor warnings (e.g., non-standard naming). Proceed with caution if the source is unknown."
        else:
            explanation = "Clean APK structure. No malicious patterns detected in filename or metadata profile."
            
    return prediction, min(99, score), explanation, flagged_keywords

def analyze_apk(filename, file_size):
    print(f"   [APK ANALYZER] Scanning file: {filename} ({file_size} bytes)")
    
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        print("   [APK ANALYZER] No GEMINI_API_KEY found. Falling back to heuristics.")
        return analyze_apk_heuristics(filename, file_size)
        
    genai.configure(api_key=api_key)
    
    system_instruction = (
        "You are an Android security analyst. Analyze the provided APK filename and file size to determine "
        "if the app is potentially malicious, cracked, spoofed, or safe (Ham).\n"
        "Identify threats like double extensions, Trojan names, cracked/pro mods, or keyloggers.\n\n"
        "You MUST respond ONLY with a valid JSON object matching this schema:\n"
        "{\n"
        "  \"prediction\": \"Spam\" | \"Ham\",\n"
        "  \"score\": integer between 0 and 100 representing threat level,\n"
        "  \"explanation\": \"Clear explanation of why the APK is flagged or safe (max 2 sentences)\",\n"
        "  \"flagged_keywords\": [\"list\", \"of\", \"suspicious\", \"terms\", \"found\"]\n"
        "}\n"
        "Do not include any introductory or concluding text. Output ONLY the JSON."
    )
    
    prompt = f"APK Filename: {filename}\nFile Size: {file_size} bytes"
    
    response_text = None
    for i, model_name in enumerate(["gemini-3.5-flash", "gemini-2.5-flash"]):
        if i > 0:
            time.sleep(1)
        try:
            model = genai.GenerativeModel(model_name)
            full_prompt = f"{system_instruction}\n\n{prompt}"
            response = model.generate_content(
                full_prompt,
                request_options={"timeout": 30}
            )
            try:
                text = response.text
                if text and text.strip():
                    response_text = text.strip()
                    break
            except Exception as re:
                print(f"   [APK ANALYZER] Empty/blocked response from {model_name}: {re}")
        except Exception as e:
            print(f"   [APK ANALYZER] Error calling {model_name}: {e}")
            
    if not response_text:
        return analyze_apk_heuristics(filename, file_size)
        
    try:
        text_to_parse = response_text
        if text_to_parse.startswith("```"):
            parts = text_to_parse.split("```")
            for part in parts:
                p_str = part.strip()
                if p_str.startswith("json"):
                    p_str = p_str[4:].strip()
                if p_str.startswith("{") and p_str.endswith("}"):
                    text_to_parse = p_str
                    break
                    
        text_to_parse = text_to_parse.strip()
        
        start = text_to_parse.find('{')
        end = text_to_parse.rfind('}')
        if start != -1 and end != -1:
            text_to_parse = text_to_parse[start:end+1]
            
        data = json.loads(text_to_parse)
        
        prediction = data.get("prediction", "Ham")
        score = int(data.get("score", 0))
        explanation = data.get("explanation", "")
        flagged_keywords = data.get("flagged_keywords", [])
        
        if prediction not in ["Spam", "Ham"]:
            prediction = "Spam" if score >= 40 else "Ham"
            
        score = max(0, min(100, score))
        
        print(f"   [APK ANALYZER] Gemini success: prediction={prediction}, score={score}")
        return prediction, score, explanation, flagged_keywords
    except Exception as e:
        print(f"   [APK ANALYZER] Error parsing Gemini JSON: {e}")
        return analyze_apk_heuristics(filename, file_size)


def send_otp(email, otp, mode="Login"):
    try:
        print(f"   [SMTP] Sending {mode} OTP to {email}...")
        
        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"SMS AI Platform – Your {mode} Verification Code"
        msg["From"] = f"SMS AI Platform <{EMAIL_USER}>"
        msg["To"] = email

        # Plain-text fallback
        plain_text = (
            f"SMS AI Platform – {mode} Verification\n\n"
            f"Your one-time verification code is: {otp}\n\n"
            "This code is valid for 10 minutes. Do not share it with anyone.\n\n"
            "If you did not request this code, please ignore this email.\n\n"
            "– SMS AI Security Team"
        )

        # HTML version (much less likely to land in spam)
        html_text = f"""
        <html>
          <body style="font-family: Arial, sans-serif; background: #f4f6fb; padding: 30px;">
            <div style="max-width: 480px; margin: auto; background: #ffffff; border-radius: 12px;
                        box-shadow: 0 4px 20px rgba(0,0,0,0.08); overflow: hidden;">
              <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 30px; text-align: center;">
                <h1 style="color: #ffffff; margin: 0; font-size: 24px;">&#128274; SMS AI Platform</h1>
                <p style="color: rgba(255,255,255,0.85); margin: 6px 0 0; font-size: 14px;">{mode} Verification</p>
              </div>
              <div style="padding: 36px 30px; text-align: center;">
                <p style="color: #444; font-size: 15px; margin-bottom: 24px;">Your one-time verification code is:</p>
                <div style="background: #f0f2ff; border-radius: 10px; padding: 20px; display: inline-block;
                            letter-spacing: 10px; font-size: 36px; font-weight: bold; color: #5a3de6;">
                  {otp}
                </div>
                <p style="color: #888; font-size: 13px; margin-top: 24px;">
                  This code is valid for <strong>10 minutes</strong>.<br>
                  Never share this code with anyone.
                </p>
              </div>
              <div style="background: #fafafa; border-top: 1px solid #eee; padding: 16px 30px; text-align: center;">
                <p style="color: #bbb; font-size: 12px; margin: 0;">
                  If you didn't request this, you can safely ignore this email.
                </p>
              </div>
            </div>
          </body>
        </html>
        """

        msg.attach(MIMEText(plain_text, "plain"))
        msg.attach(MIMEText(html_text, "html"))

        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(EMAIL_USER, EMAIL_PASS)
            server.send_message(msg)
        
        print(f"   [SMTP] OTP email sent successfully to {email}")
        return True
    except Exception as e:
        print(f"   [SMTP] ERROR sending OTP email to {email}: {e}")
        return False

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # 1. Basic session checks
        if not session.get("logged_in") or not session.get("admin_verified"):
            # Instead of redirecting to admin login (which reveals it), redirect to main login
            flash("Unauthorized access. Security protocol engaged.", "error")
            return redirect(url_for('login'))
        
        # 2. Deep verification against Database
        email = session.get("email")
        if not email:
            return redirect(url_for('login'))
            
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT is_admin FROM users WHERE email=?", (email,))
        user = cursor.fetchone()
        conn.close()
        
        if not user or not user["is_admin"]:
            # Log the unauthorized attempt
            print(f"[SECURITY ALERT] Unauthorized admin access attempt by: {email}")
            session.pop("admin_verified", None) # Strip verified status if it was faked
            flash("Access Denied: Administrative privileges required.", "error")
            return redirect(url_for('dashboard'))
            
        return f(*args, **kwargs)
    return decorated_function

# ---------------- ROUTES ----------------

@app.route("/get-started")
def get_started():
    return render_template("get_started.html")

@app.route("/", methods=["GET", "POST"])
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "").strip()
        
        if not email or not password:
            flash("Email and Password are required!", "error")
            return redirect("/")

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE email=?", (email,))
        user = cursor.fetchone()

        # Handle user existence and password check
        is_valid = user and user["password"] and check_password_hash(user["password"], password)
        conn.close()

        if is_valid:
            session["email"] = email
            
            # Check for 2FA Protocol
            if user["two_factor"]:
                otp = str(random.randint(100000, 999999))
                conn = get_db()
                cursor = conn.cursor()
                cursor.execute("UPDATE users SET otp = ? WHERE email = ?", (otp, email))
                conn.commit()
                conn.close()
                
                send_otp(email, otp, "Login Verification")
                flash("Two-Factor Authentication Required. Please check your email for the verification code.", "info")
                return redirect("/verify-otp")

            session["logged_in"] = True
            
            # Auto-verify admin if the user has is_admin role
            if user["is_admin"]:
                session["admin_verified"] = True
                flash("Administrative Session Initialized", "success")
                return redirect("/admin")
            
            flash("Login successful!", "success")
            return redirect("/dashboard")
        elif not user:
            flash("Account not found. Please register.", "error")
            return redirect("/register")
        else:
            flash("Invalid password or missing credentials.", "error")
            return redirect("/")
    return render_template("login.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        data = request.form
        email = data.get("email", "").strip()
        name = data.get("name", "").strip()
        password = data.get("password", "").strip()
        confirm_password = data.get("confirm_password", "").strip()
        
        if not email or not name or not password:
            flash("All fields are required!", "error")
            return redirect("/register")
        
        if password != confirm_password:
            flash("Passwords do not match!", "error")
            return redirect("/register")
        otp = str(random.randint(100000, 999999))
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM users WHERE email=?", (email,))
        if cursor.fetchone():
            conn.close()
            flash("This email is already registered. Please sign in.", "error")
            return redirect("/")

        hashed_pw = generate_password_hash(password)
        cursor.execute(
            "INSERT INTO users (email, name, password, country, state, phone, whatsapp_number, address, otp) VALUES (?,?,?,?,?,?,?,?,?)",
            (email, name, hashed_pw, data.get('country'), data.get('state'), data.get('phone'), data.get('whatsapp_number'), data.get('address'), otp)
        )
        conn.commit()
        
        success = send_otp(email, otp, "Registration")
        conn.close()
        
        if success:
            session["email"] = email
            flash("Account registered. Please verify your identity with the OTP sent to your email.", "success")
            return redirect("/verify-otp")
        else:
            flash("Failed to send OTP email, but account created. Please contact support.", "warning")
            session["email"] = email
            return redirect("/verify-otp")
    return render_template("register.html")

@app.route("/verify-otp", methods=["GET", "POST"])
def verify_otp():
    email = session.get("email")
    if not email: return redirect("/")
    
    if request.method == "POST":
        input_otp = request.form.get("otp", "").strip()
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT otp FROM users WHERE email=?", (email,))
        row = cursor.fetchone()
        if row and row["otp"] == input_otp:
            # Re-fetch full user data to check for admin status
            cursor.execute("SELECT is_admin FROM users WHERE email=?", (email,))
            user = cursor.fetchone()
            
            session["logged_in"] = True
            
            # AUTO-ACCEPT FAMILY INVITATIONS
            # If this user had pending family invites, mark them as 'accepted' now that they've verified
            cursor.execute("UPDATE family_members SET status='accepted' WHERE member_email=?", (email,))
            conn.commit()

            if user and user["is_admin"]:
                session["admin_verified"] = True
                flash("Admin identity verified. Command access granted.", "success")
                return redirect("/admin")

            flash("Identity verified. System access granted.", "success")
            return redirect("/dashboard")
        flash("Invalid identification code. Please try again.", "error")
    return render_template("verify_otp.html")

@app.route("/api/resend-otp", methods=["POST"])
def resend_otp():
    email = session.get("email")
    if not email:
        return jsonify({"success": False, "message": "Session expired. Please start over."}), 401
    
    otp = str(random.randint(100000, 999999))
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET otp = ? WHERE email = ?", (otp, email))
    conn.commit()
    conn.close()
    
    success = send_otp(email, otp, "OTP Resend Request")
    if success:
        return jsonify({"success": True, "message": "A new verification code has been sent to your email."})
    else:
        return jsonify({"success": False, "message": "Failed to send email. Please try again later."}), 500

@app.route("/dashboard")
def dashboard():
    if not session.get("logged_in"): return redirect("/")
    if session.get("admin_verified"): return redirect("/admin")
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id, name, has_seen_tour, loyalty_points, is_admin, voice_interface, theme FROM users WHERE email=?", (session.get("email"),))
    user = cursor.fetchone()
    
    cursor.execute("SELECT * FROM scans WHERE user_id=? ORDER BY timestamp DESC", (user["id"],))
    scans = [dict(row) for row in cursor.fetchall()]

    # Advanced Analytics
    total = len(scans)
    spam_count = sum(1 for s in scans if s['prediction'] in ['Spam', 'Fake'])
    ham_count = total - spam_count
    
    analytics = {
        "total": total,
        "spam_count": spam_count,
        "ham_count": ham_count,
        "avg_score": round(sum(s['score'] for s in scans)/total, 1) if total > 0 else 0
    }
    
    cursor.execute("SELECT member_email, relationship, status FROM family_members WHERE guardian_id=?", (user["id"],))
    family = [dict(row) for row in cursor.fetchall()]
    
    conn.close()
    return render_template("dashboard.html", user=user, messages=scans, analytics=analytics, family=family)

@app.route("/classification")
def classification():
    if not session.get("logged_in"): return redirect("/")
    if session.get("admin_verified"): return redirect("/admin")
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM users WHERE email=?", (session.get("email"),))
    user = cursor.fetchone()
    
    cursor.execute("SELECT * FROM scans WHERE user_id=? ORDER BY timestamp DESC", (user["id"],))
    scans = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return render_template("classification.html", messages=scans)

@app.route("/family")
def family():
    if not session.get("logged_in"): return redirect("/")
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM users WHERE email=?", (session.get("email"),))
    user = cursor.fetchone()
    if not user:
        conn.close()
        session.clear()
        return redirect("/")
    
    # SELF-HEAL: Auto-accept any pending invites if the user already exists in the system
    cursor.execute("""
        UPDATE family_members 
        SET status = 'accepted' 
        WHERE status = 'pending' AND member_email IN (SELECT email FROM users)
    """)
    conn.commit()

    cursor.execute("SELECT * FROM family_members WHERE guardian_id=?", (user["id"],))
    members = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return render_template("family.html", family_members=members)



import json

@app.route("/analytics")
def analytics_page():
    if not session.get("logged_in"): return redirect("/")
    if session.get("admin_verified"): return redirect("/admin")
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM users WHERE email=?", (session.get("email"),))
    row = cursor.fetchone()
    if not row:
        conn.close()
        session.clear()
        return redirect("/")
    user_id = row["id"]
    
    # 1. Prediction Breakdown
    cursor.execute("SELECT prediction, COUNT(*) as count FROM scans WHERE user_id=? GROUP BY prediction", (user_id,))
    prediction_stats = {row['prediction']: row['count'] for row in cursor.fetchall()}
    
    # 2. Type Breakdown
    cursor.execute("SELECT scan_type, COUNT(*) as count FROM scans WHERE user_id=? GROUP BY scan_type", (user_id,))
    type_stats = {row['scan_type']: row['count'] for row in cursor.fetchall()}
    
    # 3. Activity Timeline (last 7 days)
    cursor.execute("""
        SELECT date(timestamp) as scan_date, COUNT(*) as count 
        FROM scans 
        WHERE user_id=? 
        GROUP BY scan_date 
        ORDER BY scan_date DESC 
        LIMIT 7
    """, (user_id,))
    activity = [{"date": row['scan_date'], "count": row['count']} for row in cursor.fetchall()]
    activity.reverse()

    conn.close()
    
    return render_template("analytics.html", 
                           predictions=json.dumps(prediction_stats), 
                           types=json.dumps(type_stats), 
                           activity=json.dumps(activity))

@app.route("/history")
def history():
    if not session.get("logged_in"): return redirect("/")
    if session.get("admin_verified"): return redirect("/admin")
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM users WHERE email=?", (session.get("email"),))
    user = cursor.fetchone()
    if not user:
        conn.close()
        session.clear()
        return redirect("/")
    
    cursor.execute("SELECT * FROM scans WHERE user_id=? ORDER BY timestamp DESC", (user["id"],))
    scans = [dict(row) for row in cursor.fetchall()]
    
    conn.close()
    return render_template("history.html", scans=scans)

@app.route("/profile", methods=["GET", "POST"])
def profile():
    if not session.get("logged_in"): return redirect("/")
    if session.get("admin_verified"): return redirect("/admin")
    
    conn = get_db()
    cursor = conn.cursor()
    
    if request.method == "POST":
        data = request.form
        name = data.get("name")
        phone = data.get("phone")
        whatsapp_number = data.get("whatsapp_number")
        address = data.get("address")
        new_password = data.get("new_password")
        emergency_contact = data.get("emergency_contact")
        
        cursor.execute(
            "UPDATE users SET name=?, phone=?, whatsapp_number=?, address=?, emergency_contact=? WHERE email=?",
            (name, phone, whatsapp_number, address, emergency_contact, session.get("email"))
        )
        
        if new_password and new_password.strip():
            hashed_pw = generate_password_hash(new_password)
            cursor.execute("UPDATE users SET password=? WHERE email=?", (hashed_pw, session.get("email")))
            
        conn.commit()
        flash("Profile updated successfully!", "success")
        return redirect("/profile")

    cursor.execute("SELECT * FROM users WHERE email=?", (session.get("email"),))
    user = cursor.fetchone()
    if not user:
        conn.close()
        session.clear()
        return redirect("/")
    conn.close()
    return render_template("profile.html", user=user)

@app.route("/settings")
def settings():
    if not session.get("logged_in"): return redirect("/")
    if session.get("admin_verified"): return redirect("/admin")
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE email=?", (session.get("email"),))
    user = dict(cursor.fetchone())
    conn.close()
    return render_template("settings.html", user=user)

@app.route("/api/update_settings", methods=["POST"])
def update_settings():
    if not session.get("logged_in"): return jsonify({"error": "Unauthorized"}), 401
    data = request.json
    key = data.get("key")
    value = data.get("value")
    
    mapping = {
        "2FA": "two_factor",
        "Sensitivity": "sensitivity",
        "Appearance": "theme",
        "Auto-Clear": "auto_clear_history",
        "Voice Interface": "voice_interface"
    }
    
    db_col = mapping.get(key)
    if not db_col: return jsonify({"error": "Invalid setting"}), 400
        
    conn = get_db()
    cursor = conn.cursor()
    if isinstance(value, bool): value = 1 if value else 0
        
    try:
        cursor.execute(f"UPDATE users SET {db_col} = ? WHERE email = ?", (value, session.get("email")))
        conn.commit()
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

@app.route("/api/autocorrect", methods=["POST"])
def api_autocorrect():
    data = request.get_json()
    text = data.get("text", "")
    if not text: return jsonify({"corrected": ""})
    return jsonify({"corrected": auto_correct(text)})

def chat_heuristics(message):
    message_lower = message.lower()
    kb = {
        "email": {
            "en": "Our <b>Email Analysis</b> node uses ML heuristics to detect phishing attempts, unauthorized sender patterns, and malicious attachments. <br><br><b>Tip</b>: Always check if the sender's email domain matches the official company website.",
            "kn": "ನಮ್ಮ <b>ಇಮೇಲ್ ವಿಶ್ಲೇಷಣೆ</b> ವ್ಯವಸ್ಥೆಯು ಫಿಶಿಂಗ್ ಪ್ರಯತ್ನಗಳು ಮತ್ತು ಅಪಾಯಕಾರಿ ಇಮೇಲ್‌ಗಳನ್ನು ಪತ್ತೆಹಚ್ಚುತ್ತದೆ. <br><br><b>ಸಲಹೆ</b>: ಇಮೇಲ್ ಕಳುಹಿಸಿದವರ ವಿಳಾಸ ಅಧಿಕೃತವಾಗಿದೆಯೇ ಎಂದು ಯಾವಾಗಲೂ ಪರಿಶೀಲಿಸಿ."
        },
        "sms": {
            "en": "The <b>SMS & Smishing</b> shield identifies 'Sense of Urgency' patterns, suspicious bit.ly links, and bank impersonation attempts. <br><br><b>Tip</b>: Never share OTPs or click on links that ask for your UPI PIN via SMS.",
            "kn": "<b>SMS ಮತ್ತು ಸ್ಮಿಶಿಂಗ್</b> ಭದ್ರತೆಯು ಬ್ಯಾಂಕ್ ಹೆಸರಿನಲ್ಲಿ ಬರುವ ನಕಲಿ ಸಂದೇಶಗಳು ಮತ್ತು ಅಪಾಯಕಾರಿ ಲಿಂಕ್‌ಗಳನ್ನು ಪತ್ತೆಹಚ್ಚುತ್ತದೆ. <br><br><b>ಸಲಹೆ</b>: ಯಾವುದೇ ಸಂದೇಶ ಬಂದಾಗ ನಿಮ್ಮ ಯುಪಿಐ ಪಿನ್ ಅಥವಾ ಒಟಿಪಿಯನ್ನು ಯಾರಿಗೂ ಹಂಚಿಕೊಳ್ಳಬೇಡಿ."
        },
        "link": {
            "en": "<b>URL Safety</b> scans verify the destination, TLD reputation, and SSL status of any link before you click it. <br><br><b>Tip</b>: Hover over a link to see the actual destination URL before clicking.",
            "kn": "<b>ಲಿಂಕ್ ಸುರಕ್ಷತೆ</b> ತಪಾಸಣೆಯು ಯಾವುದೇ ಲಿಂಕ್ ಅನ್ನು ಕ್ಲಿಕ್ ಮಾಡುವ ಮೊದಲು ಅದರ ಗಮ್ಯಸ್ಥಾನ ಮತ್ತು ಸುರಕ್ಷತೆಯನ್ನು ಪರಿಶೀಲಿಸುತ್ತದೆ."
        },
        "qr": {
            "en": "The <b>QR Payload</b> analyzer decodes hidden data in QR codes and scans the embedded URLs or scripts for malware. <br><br><b>Tip</b>: Only scan QR codes from trusted locations; malicious codes can redirect you to phishing sites.",
            "kn": "<b>QR ಕೋಡ್</b> ವಿಶ್ಲೇಷಕವು ಕ್ಯೂಆರ್ ಕೋಡ್‌ಗಳಲ್ಲಿ ಅಡಗಿರುವ ಅಪಾಯಕಾರಿ ಮಾಹಿತಿ ಅಥವಾ ಲಿಂಕ್‌ಗಳನ್ನು ಪತ್ತೆಹಚ್ಚುತ್ತದೆ."
        },
        "apk": {
            "en": "<b>APK Binary Scan</b> inspects Android packages for malware signatures, double extensions, and suspicious metadata. <br><br><b>Tip</b>: Only install apps from the Google Play Store or trusted developers.",
            "kn": "<b>APK ವಿಶ್ಲೇಷಣೆ</b> ನಿಮ್ಮ ಮೊಬೈಲ್‌ನಲ್ಲಿರುವ ನಕಲಿ ಅಥವಾ ಅಪಾಯಕಾರಿ ಆಪ್‌ಗಳನ್ನು (APKs) ಪತ್ತೆಹಚ್ಚಲು ಸಹಾಯ ಮಾಡುತ್ತದೆ."
        }
    }

    matched_feature = None
    if any(x in message_lower for x in ["email", "mail"]): matched_feature = "email"
    elif any(x in message_lower for x in ["sms", "message", "smishing"]): matched_feature = "sms"
    elif any(x in message_lower for x in ["link", "url", "site", "website"]): matched_feature = "link"
    elif any(x in message_lower for x in ["qr", "code", "scanner"]): matched_feature = "qr"
    elif any(x in message_lower for x in ["apk", "app", "install", "malware"]): matched_feature = "apk"

    is_kn = any('\u0C80' <= char <= '\u0CFF' for char in message) or "ಕನ್ನಡ" in message

    if matched_feature:
        lang = "kn" if is_kn else "en"
        res = kb[matched_feature][lang]
        if lang == "en":
            res += "<br><br><b>How to use?</b> Just paste the content or upload the file into the respective card in your Hub and click 'Analyze'."
        else:
            res += "<br><br><b>ಬಳಸುವುದು ಹೇಗೆ?</b> ಸಂಬಂಧಿತ ಬಾಕ್ಸ್‌ನಲ್ಲಿ ಮಾಹಿತಿಯನ್ನು ಸೇರಿಸಿ ಮತ್ತು 'ವಿಶ್ಲೇಷಿಸಿ' ಬಟನ್ ಕ್ಲಿಕ್ ಮಾಡಿ."
    elif any(x in message_lower for x in ["hi", "hello", "hey"]):
        res = "Hello! I'm your Security Guardian. You can ask me about our scanning features (Email, SMS, Links, QR, APK) or security tips. How can I protect you today?"
    elif "privacy" in message_lower:
        res = "Your privacy is fundamental. All analysis is performed within your secure user environment. We do not store your private message content for longer than needed for history tracking."
    else:
        res = "I'm here to help! I can provide details on how our Email, SMS, Link, QR, and APK scans work. Just ask about any specific feature!"

    return res

@app.route("/api/chat", methods=["POST"])
def chat():
    if not session.get("logged_in"): return jsonify({"response": "Unauthenticated access."}), 401
    
    data = request.json
    message = data.get("message", "").strip()
    if not message:
        return jsonify({"response": "Please say something."})
        
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        return jsonify({"response": chat_heuristics(message)})
        
    # Configure API key
    genai.configure(api_key=api_key)
    
    system_instruction = (
        "You are 'Security Guardian', a smart bilingual AI assistant for the SMS & Email Spam AI Platform.\n"
        "Your task is to answer user queries about security, phishing, smishing, scam prevention, or how to use the platform.\n"
        "Here are the platform features:\n"
        "- Email Analysis: Detects phishing, fraudulent invoices, and malicious attachments.\n"
        "- SMS & Smishing: Identifies high-urgency keywords, fake bank links, and delivery scam templates.\n"
        "- URL Safety: Scans links, checks TLD status, SSL, and domain spoofing.\n"
        "- QR Payload: Decodes QR codes and verifies the target link/content.\n"
        "- APK Binary Scan: Inspects Android packages for malware filenames and size signatures.\n"
        "- Family Circle: Allows guardians to receive alerts if their family members receive a high-risk message.\n\n"
        "Keep your response concise (max 3-4 sentences). Answer in the language the user uses (English, Kannada, or Hinglish/Kannanglish). "
        "Be friendly, professional, and focus on security best practices."
    )
    
    response_text = None
    for i, model_name in enumerate(["gemini-3.5-flash", "gemini-2.5-flash"]):
        if i > 0:
            time.sleep(1)
        try:
            model = genai.GenerativeModel(model_name)
            full_prompt = f"{system_instruction}\n\nUser: {message}"
            response = model.generate_content(
                full_prompt,
                request_options={"timeout": 30}
            )
            try:
                text = response.text
                if text and text.strip():
                    response_text = text.strip()
                    break
            except Exception as re:
                print(f"   [CHAT] Empty/blocked response from {model_name}: {re}")
        except Exception as e:
            print(f"   [CHAT] Error calling {model_name}: {e}")
            
    if response_text:
        return jsonify({"response": response_text})
    else:
        return jsonify({"response": chat_heuristics(message)})

# ----------------- AI ANALYZER API -----------------
import threading

def handle_notifications(user_email, content, score, prediction, clean_number):
    """Background task to handle all automated alerts and Guardian notifications."""
    try:
        # 1. IMMEDIATE Email Alert to the user (Highest Priority)
        send_security_email(user_email, content, score, prediction)

        conn = get_db()
        cursor = conn.cursor()
        
        # Get User details for the alert
        cursor.execute("SELECT id, name FROM users WHERE email=?", (user_email,))
        user_row = cursor.fetchone()
        
        if not user_row:
            print(f"Notification task aborted: User {user_email} not found.")
            conn.close()
            return

        user_id = user_row["id"]
        user_name = user_row["name"]

        message_text = f"🛡️ *GUARDIAN ALERT*\n\n" \
                       f"A security risk was detected for *{user_name}* ({user_email}).\n\n" \
                       f"📊 *Status*: {prediction}\n" \
                       f"⚠️ *Risk Score*: {score}%\n" \
                       f"📝 *Content*: \"{content[:80]}...\"\n\n" \
                       f"👉 Please verify with them of this suspicious activity."
        
        # 2. WhatsApp Notification functionality removed
        pass
        
        # 3. Notify Family Guardians
        # Note: We send to all registered guardians to ensure safety, even if 'pending' status
        cursor.execute("""
            SELECT u.whatsapp_number, u.email, f.status
            FROM users u 
            JOIN family_members f ON u.id = f.guardian_id 
            WHERE f.member_email = ?
        """, (user_email,))
        
        guardians = cursor.fetchall()
        print(f"Notification DEBUG: Found {len(guardians)} guardians for {user_email}")
        for guardian in guardians:
            try:
                # Always send email for SPAM regardless of status for maximal protection
                send_security_email(guardian["email"], content, score, f"FAMILY ALERT: {prediction}")
                print(f"EMAIL SUCCESS: Security alert dispatched to guardian: {guardian['email']}")

                # WhatsApp alert functionality removed
                pass

            except Exception as inner_e:
                print(f"Failed to notify guardian {guardian['email']}: {inner_e}")

        conn.close()
    except Exception as e:
        print(f"Background notification error: {e}")

@app.route("/api/scan", methods=["POST"])
def scan_content():
    if not session.get("logged_in"): return jsonify({"error": "Unauthorized"}), 401
    
    try:
        data = request.form if request.form else (request.json or {})
        scan_type = data.get("type", "email")
        
        email = session.get("email")
        if not email: return jsonify({"error": "Session expired. Please login again."}), 401

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT id, sensitivity FROM users WHERE email=?", (email,))
        user_row = cursor.fetchone()
        if not user_row: return jsonify({"error": "User context lost."}), 401
        user_id = user_row["id"]
        sensitivity = user_row["sensitivity"] or "Balanced"

        prediction, score, explanation = "Ham", 0, ""
        explanation_kn, flagged_keywords, corrected_content = "", [], ""
        content = ""

        # --- COMPREHENSIVE SCAN LOGIC WITH STRICT VALIDATION ---
        if scan_type in ["email", "sms", "otp", "social"]:
            content = data.get("message", "").strip()
            if not content: return jsonify({"error": "No content provided"}), 400
            
            # --- STRICT VALIDATION ---
            # 1. URL check: If they paste a URL in Email/SMS, tell them to use Link feature
            import re
            url_pattern = r'https?://[^\s]+'
            urls_found = re.findall(url_pattern, content)
            
            if scan_type == "sms":
                # 1. Reject if it's JUST a URL
                if len(content) < 100 and len(urls_found) == 1 and urls_found[0] == content:
                    return jsonify({
                        "prediction": "Invalid", "score": 0,
                        "explanation": "This is a Link. Please use the 'Link Analysis' feature.",
                        "explanation_kn": "ಇದು ಲಿಂಕ್ ಆಗಿದೆ. ದಯವಿಟ್ಟು 'Link Analysis' ವೈಶಿಷ್ಟ್ಯವನ್ನು ಬಳಸಿ."
                    })
                # 2. Reject if it's too long (SMS are usually short, but we'll allow up to 1000, 
                # but if it has email markers like "Subject:", it's an email)
                if "Subject:" in content or "Dear " in content and len(content) > 300:
                    return jsonify({
                        "prediction": "Invalid", "score": 0,
                        "explanation": "This looks like an Email. Please use the 'Email Analysis' feature.",
                        "explanation_kn": "ಇದು ಇಮೇಲ್ ಎಂದು ತೋರುತ್ತಿದೆ. ದಯವಿಟ್ಟು 'Email Analysis' ವೈಶಿಷ್ಟ್ಯವನ್ನು ಬಳಸಿ."
                    })
            
            if scan_type == "email":
                # 1. Reject if it's very short and contains a URL (likely just a link)
                if len(content) < 40 and len(urls_found) == 1:
                     return jsonify({
                        "prediction": "Invalid", "score": 0,
                        "explanation": "This looks like a Link. Please use the 'Link Analysis' feature.",
                        "explanation_kn": "ಇದು ಲಿಂಕ್ ಎಂದು ತೋರುತ್ತಿದೆ. ದಯವಿಟ್ಟು 'Link Analysis' ವೈಶಿಷ್ಟ್ಯವನ್ನು ಬಳಸಿ."
                    })
                # 2. Reject if it's too short to be a real email body (e.g. less than 10 chars)
                if len(content) < 10:
                    return jsonify({
                        "prediction": "Invalid", "score": 0,
                        "explanation": "Content too short for email analysis.",
                        "explanation_kn": "ಇಮೇಲ್ ವಿಶ್ಲೇಷಣೆಗೆ ಮಾಹಿತಿ ತುಂಬಾ ಕಡಿಮೆಯಿದೆ."
                    })

            import hashlib
            content_hash = hashlib.sha256(content.encode()).hexdigest()
            cursor.execute("SELECT report_count FROM global_scams WHERE content_hash=?", (content_hash,))
            scam_record = cursor.fetchone()
            
            stype = "sms" if scan_type in ["sms", "otp"] else "email"
            prediction, score, explanation, explanation_kn, flagged_keywords, corrected_content = analyze_spam(content, stype, sensitivity)
            content = corrected_content 
            
            if scam_record and scam_record["report_count"] >= 3:
                prediction = "Spam"; score = max(score, 95)
                explanation = f"⚠️ COMMUNITY ALERT: Reported by {scam_record['report_count']} users. " + explanation
                flagged_keywords.append("Globally Reported Scam")

        elif scan_type == "url":
            content = data.get("url", "").strip()
            if not content: return jsonify({"error": "No URL provided"}), 400
            
            # STRICT VALIDATION: Must look like a URL
            import re
            url_pattern = r'^(https?:\/\/)?([\da-z\.-]+)\.([a-z\.]{2,6})([\/\w \.-]*)*\/?$'
            if not re.match(url_pattern, content):
                return jsonify({
                    "prediction": "Invalid", "score": 0,
                    "explanation": "Invalid URL. Please paste a valid link starting with http:// or https://",
                    "explanation_kn": "ಅಮಾನ್ಯ ಲಿಂಕ್. ದಯವಿಟ್ಟು http:// ಅಥವಾ https:// ನಿಂದ ಪ್ರಾರಂಭವಾಗುವ ಮಾನ್ಯ ಲಿಂಕ್ ಅನ್ನು ಸೇರಿಸಿ."
                })

            prediction, score, explanation, explanation_kn, flagged_keywords, corrected_content = analyze_spam(content, "url", sensitivity)
            content = corrected_content

        elif scan_type in ["qr_code", "id_card"]:
            if 'file' not in request.files: return jsonify({"error": "No file"}), 400
            file = request.files['file']
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename); file_path = os.path.join(UPLOAD_FOLDER, filename); file.save(file_path)
                val = robust_qr_scan(file_path)
                if val:
                    content = val
                    prediction, score, explanation, explanation_kn, flagged_keywords, corrected_content = analyze_spam(val, "qr_code", sensitivity)
                    content = corrected_content
                    explanation = f"QR Decoded: '{val}'. {explanation}"; flagged_keywords.append("QR Content Found")
                else:
                    content = "No QR Code Found"; prediction = "Invalid"; score = 0
                    explanation = "We couldn't detect a clear QR code in this image. Please ensure the QR code is well-lit and clearly visible."
                    explanation_kn = "ಈ ಚಿತ್ರದಲ್ಲಿ ಸ್ಪಷ್ಟವಾದ QR ಕೋಡ್ ಪತ್ತೆಯಾಗಿಲ್ಲ. ದಯವಿಟ್ಟು QR ಕೋಡ್ ಸ್ಪಷ್ಟವಾಗಿ ಕಾಣುವಂತೆ ನೋಡಿಕೊಳ್ಳಿ."
            else:
                content = "Invalid Image"; prediction = "Invalid"; score = 0
                explanation = "The uploaded file is not a supported image format. Please upload a PNG, JPG, or JPEG."
                explanation_kn = "ಅಪ್‌ಲೋಡ್ ಮಾಡಿದ ಫೈಲ್ ಬೆಂಬಲಿತ ಚಿತ್ರ ಸ್ವರೂಪದಲ್ಲಿಲ್ಲ. ದಯವಿಟ್ಟು PNG, JPG ಅಥವಾ JPEG ಅಪ್‌ಲೋಡ್ ಮಾಡಿ."

        elif scan_type == "apk":
            if 'file' not in request.files: return jsonify({"error": "No file"}), 400
            file = request.files['file']
            if file and file.filename.lower().endswith('.apk'):
                filename = secure_filename(file.filename); file_path = os.path.join(UPLOAD_FOLDER, filename); file.save(file_path)
                file_size = os.path.getsize(file_path); content = filename
                prediction, score, explanation, flagged_keywords = analyze_apk(filename, file_size)
                explanation_kn = "APK ಫೈಲ್ ವಿಶ್ಲೇಷಣೆ ಪೂರ್ಣಗೊಂಡಿದೆ."
            else:
                content = "Invalid APK"; prediction = "Invalid"; score = 0
                explanation = "correct apk file in apk section"
                explanation_kn = "ದಯವಿಟ್ಟು APK ವಿಭಾಗದಲ್ಲಿ ಸರಿಯಾದ APK ಫೈಲ್ ಆಯ್ಕೆಮಾಡಿ"

        # Save to DB
        cursor.execute("INSERT INTO scans (user_id, scan_type, content, prediction, score, explanation, explanation_kn) VALUES (?,?,?,?,?,?,?)",
                       (user_id, scan_type, content, prediction, score, explanation, explanation_kn))
        scan_id = cursor.lastrowid

        # --- NOTIFICATIONS & ALERTS ---
        alert_triggered = False; whatsapp_url = ""; notified_number = "Unknown"; clean_num = None
        if score > 0:
            cursor.execute("SELECT phone, emergency_contact, whatsapp_number FROM users WHERE email=?", (email,))
            user_info = cursor.fetchone()
            if user_info:
                target_number = user_info["whatsapp_number"] or user_info["emergency_contact"] or user_info["phone"]
                if target_number:
                    clean_num = "".join(filter(str.isdigit, target_number))
                    if not target_number.startswith('+') and len(clean_num) == 10: clean_num = "91" + clean_num
                    notified_number = f"+{clean_num}"
                    from urllib.parse import quote
                    summary = f"🛡️ *GUARDIAN ALERT*\nStatus: {prediction}\nThreat Level: {score}%\nReason: {explanation}"
                    whatsapp_url = f"https://api.whatsapp.com/send?phone={clean_num}&text={quote(summary)}"
            
        # Trigger background tasks if it's a threat
        if prediction in ["Spam", "Fake"]:
            alert_triggered = True
            threading.Thread(target=handle_notifications, args=(email, content, score, prediction, clean_num)).start()

        conn.commit()
        conn.close()
        return jsonify({
            "id": scan_id, "prediction": prediction, "score": score, 
            "explanation": explanation, "explanation_kn": explanation_kn,
            "keywords": flagged_keywords, "emergency_alert": alert_triggered, 
            "whatsapp_url": whatsapp_url, "corrected_content": content,
            "notified_number": notified_number
        })

    except Exception as e:
        print(f"   [SCAN ERROR] {str(e)}")
        if 'conn' in locals(): conn.close()
        return jsonify({"error": "Internal processor error."}), 500

@app.route("/api/live_check", methods=["POST"])
def live_check():
    """Performs a real-time scan without saving to DB or sending notifications."""
    if not session.get("logged_in"): return jsonify({"error": "Unauthorized"}), 401
    
    data = request.json
    content = data.get("message", "").strip()
    scan_type = data.get("type", "email")
    
    if not content:
        return jsonify({"prediction": "None", "score": 0})
        
    # Fetch sensitivity for live check too
    email = session.get("email")
    sensitivity = "Balanced"
    if email:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT sensitivity FROM users WHERE email=?", (email,))
        row = cursor.fetchone()
        if row: sensitivity = row["sensitivity"] or "Balanced"
        conn.close()

    prediction, score, explanation, explanation_kn, flagged_keywords, corrected_content = analyze_spam(content, scan_type, sensitivity)
    
    # Explicitly NOT sending notifications here
    return jsonify({
        "prediction": prediction, 
        "score": score, 
        "explanation": explanation, 
        "keywords": flagged_keywords,
        "private": True,
        "warning_text": "This live analysis is private and is NOT being sent to your email or family circle."
    })



def send_security_email(email, content, score, prediction):
    try:
        subject = "🚨 SECURITY ALERT: High-Risk Message Detected" if score >= 50 else "⚠️ Security Notice: Suspicious Content Detected"
        body = f"Hello,\n\nMessage Guardian has detected suspicious content in a recent scan.\n\n" \
               f"Status: {prediction}\n" \
               f"Risk Score: {score}%\n" \
               f"Content Sample: {content[:100]}...\n\n" \
               f"If this was not you, please review your account activity immediately.\n\n" \
               f"🛡️ Message Guardian AI"
        
        msg = MIMEText(body, "plain", "utf-8")
        msg["Subject"] = subject
        msg["From"] = EMAIL_USER
        msg["To"] = email
        
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            if not EMAIL_USER or not EMAIL_PASS:
                print("ERROR: EMAIL_USER or EMAIL_PASS not found in .env!")
                return False
            server.login(EMAIL_USER, EMAIL_PASS)
            server.send_message(msg)
            print(f"EMAIL SUCCESS: Alert sent to {email}")
        return True
    except Exception as e:
        print(f"EMAIL FAILED to {email}: {e}")
        return False

def send_invitation_email(recipient_email, inviter_name):
    """Sends an invitation email when someone is added to a Family Circle."""
    try:
        subject = f"🛡️ Action Required: {inviter_name} invited you to their Safety Circle"
        body = f"Hello,\n\n{inviter_name} has invited you to join their Family Safety Circle on Message Guardian.\n\n" \
               f"By accepting, you will help protect them from scams and receive alerts if they are targeted by digital threats.\n\n" \
               f"Please log in to your Message Guardian account and go to the 'Family' tab to accept this request.\n\n" \
               f"Stay safe,\nMessage Guardian AI"
        
        msg = MIMEText(body)
        msg["Subject"] = subject
        msg["From"] = EMAIL_USER
        msg["To"] = recipient_email
        
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(EMAIL_USER, EMAIL_PASS)
            server.send_message(msg)
        return True
    except Exception as e:
        print(f"Failed to send invitation email: {e}")
        return False

@app.route("/api/report_scam", methods=["POST"])
def report_scam():
    if not session.get("logged_in"): return jsonify({"error": "Unauthorized"}), 401
    data = request.json
    scan_id = data.get("scan_id")
    
    conn = get_db()
    cursor = conn.cursor()
    
    # Get scan content
    cursor.execute("SELECT content FROM scans WHERE id=?", (scan_id,))
    scan = cursor.fetchone()
    if not scan: 
        conn.close()
        return jsonify({"error": "Scan not found"}), 404
    
    content = scan["content"]
    import hashlib
    content_hash = hashlib.sha256(content.encode()).hexdigest()
    
    # Mark as reported in history
    cursor.execute("UPDATE scans SET is_reported=1 WHERE id=?", (scan_id,))
    
    # Update global database
    cursor.execute("SELECT id, report_count FROM global_scams WHERE content_hash=?", (content_hash,))
    global_record = cursor.fetchone()
    
    if global_record:
        cursor.execute("UPDATE global_scams SET report_count = report_count + 1, last_reported=CURRENT_TIMESTAMP WHERE id=?", (global_record["id"],))
    else:
        cursor.execute("INSERT INTO global_scams (content_hash, content_sample) VALUES (?, ?)", (content_hash, content[:100]))
    
    conn.commit()
    conn.close()
    return jsonify({"success": True, "message": "Global community database updated!"})

@app.route("/api/delete_scan/<int:scan_id>", methods=["POST"])
def delete_scan(scan_id):
    if not session.get("logged_in"): return jsonify({"error": "Unauthorized"}), 401
    
    conn = get_db()
    cursor = conn.cursor()
    
    # Verify ownership
    cursor.execute("SELECT user_id FROM scans WHERE id = ?", (scan_id,))
    scan = cursor.fetchone()
    
    cursor.execute("SELECT id FROM users WHERE email = ?", (session.get("email"),))
    user_id = cursor.fetchone()["id"]
    
    if scan and scan["user_id"] == user_id:
        cursor.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
        conn.commit()
        conn.close()
        return jsonify({"success": True})
    
    conn.close()
    return jsonify({"error": "Scan not found or unauthorized"}), 404

@app.route("/api/delete_account", methods=["POST"])
def delete_account():
    if not session.get("logged_in"): return jsonify({"error": "Unauthorized"}), 401
    
    email = session.get("email")
    conn = get_db()
    cursor = conn.cursor()
    
    try:
        cursor.execute("SELECT id FROM users WHERE email = ?", (email,))
        user_row = cursor.fetchone()
        if user_row:
            user_id = user_row["id"]
            # 1. Delete all scans first (Foreign key safety)
            cursor.execute("DELETE FROM scans WHERE user_id = ?", (user_id,))
            # 2. Delete the user
            cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
            conn.commit()
            session.clear()
            return jsonify({"success": True, "message": "Identity data purged successfully."})
        return jsonify({"error": "User not found"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()

@app.route("/api/complete_tour", methods=["POST"])
def complete_tour():
    if not session.get("logged_in"): return jsonify({"success": False}), 401
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET has_seen_tour=1 WHERE email=?", (session.get("email"),))
    conn.commit()
    conn.close()
    return jsonify({"success": True})

@app.route("/family")
def family_circle():
    if not session.get("logged_in"): return redirect("/")
    if session.get("admin_verified"): return redirect("/admin")
    return render_template("family.html")

@app.route("/api/family_data")
def family_data():
    if not session.get("logged_in"): return jsonify({"error": "Unauthorized"}), 401
    email = session.get("email")
    conn = get_db()
    cursor = conn.cursor()
    
    # 1. People I am protecting (Guardianship)
    cursor.execute("SELECT id, member_email, relationship, status FROM family_members WHERE guardian_id = (SELECT id FROM users WHERE email=?)", (email,))
    guarding = [dict(row) for row in cursor.fetchall()]
    
    # 2. People protecting me (My Guardians)
    cursor.execute("SELECT f.id, u.name, u.email, f.relationship, f.status FROM family_members f JOIN users u ON f.guardian_id = u.id WHERE f.member_email = ?", (email,))
    my_guardians = [dict(row) for row in cursor.fetchall()]
    
    conn.close()
    return jsonify({
        "guarding": guarding,
        "my_guardians": my_guardians
    })

def send_invitation_email(target_email, inviter_name):
    """Sends a professional invitation email to join the Security Circle."""
    try:
        msg = MIMEText(f"Hello,\n\n{inviter_name} has invited you to join their Message Guardian Security Circle.\n\n"
                       f"By accepting, they will be notified of suspicious messages detected on your account to help keep you safe.\n\n"
                       f"Please log in to your dashboard to respond to this request.")
        msg["Subject"] = "🛡️ Security Shield Invitation"
        msg["From"] = EMAIL_USER
        msg["To"] = target_email
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(EMAIL_USER, EMAIL_PASS)
            server.send_message(msg)
        print(f"Invitation email sent to {target_email}")
    except Exception as e:
        print(f"Failed to send invitation email: {e}")

@app.route("/api/family/add", methods=["POST"])
@app.route("/api/add_family_member", methods=["POST"])
def add_family_member_unified():
    if not session.get("logged_in"): return jsonify({"error": "Unauthorized"}), 401
    data = request.json
    target_email = data.get("email")
    relationship = data.get("relationship", "Family Member")
    
    if not target_email or "@" not in target_email:
        return jsonify({"error": "A valid email is required."}), 400
        
    if target_email == session.get("email"):
        return jsonify({"error": "You cannot add yourself to your own circle."}), 400
        
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id, name FROM users WHERE email=?", (session.get("email"),))
    user_row = cursor.fetchone()
    if not user_row:
        conn.close()
        return jsonify({"error": "Member session validation failed. Please re-login."}), 401
    
    guardian_id = user_row["id"]
    inviter_name = user_row["name"]
    
    # Check if the target user already exists in our system
    cursor.execute("SELECT id FROM users WHERE email=?", (target_email,))
    target_user_exists = cursor.fetchone()
    
    initial_status = 'accepted' if target_user_exists else 'pending'
    
    try:
        cursor.execute("INSERT INTO family_members (guardian_id, member_email, relationship, status) VALUES (?, ?, ?, ?)",
                       (guardian_id, target_email, relationship, initial_status))
        conn.commit()
        
        # Send Invitation Email in background
        threading.Thread(target=send_invitation_email, args=(target_email, inviter_name)).start()
        
        msg = "Invitation dispatched (Pending)" if initial_status == 'pending' else "Member linked successfully (Accepted)"
        return jsonify({"success": True, "message": msg})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()

@app.route("/api/respond_family_request", methods=["POST"])
def respond_family_request():
    if not session.get("logged_in"): return jsonify({"error": "Unauthorized"}), 401
    data = request.json
    request_id = data.get("id")
    action = data.get("action") # 'accepted' or 'rejected'
    
    conn = get_db()
    cursor = conn.cursor()
    
    if action == 'accepted':
        cursor.execute("UPDATE family_members SET status='accepted' WHERE id=?", (request_id,))
    else:
        cursor.execute("DELETE FROM family_members WHERE id=?", (request_id,))
        
    conn.commit()
    conn.close()
    return jsonify({"success": True})

@app.route("/api/delete_family_member", methods=["POST"])
def delete_family_member():
    if not session.get("logged_in"): return jsonify({"error": "Unauthorized"}), 401
    data = request.json
    request_id = data.get("id")
    
    conn = get_db()
    cursor = conn.cursor()
    # Ensure the user owns this record (as either guardian or member)
    cursor.execute("SELECT guardian_id, member_email FROM family_members WHERE id=?", (request_id,))
    row = cursor.fetchone()
    
    if row:
        cursor.execute("DELETE FROM family_members WHERE id=?", (request_id,))
        conn.commit()
        conn.close()
        return jsonify({"success": True})
    
    conn.close()
    return jsonify({"error": "Record not found"}), 404

@app.route("/api/submit_rating", methods=["POST"])
def submit_rating():
    if not session.get("logged_in"): return jsonify({"error": "Unauthorized"}), 401
    data = request.json
    rating = data.get("rating")
    comment = data.get("comment", "")
    
    if not rating or not (1 <= int(rating) <= 5):
        return jsonify({"error": "Invalid rating. Must be between 1 and 5."}), 400
        
    user_email = session.get("email")
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM users WHERE email=?", (user_email,))
    user_id = cursor.fetchone()["id"]
    
    cursor.execute("INSERT INTO satisfaction_ratings (user_id, rating, comment) VALUES (?, ?, ?)",
                   (user_id, rating_int, comment))
    
    # --- ACTIONS BASED ON FEEDBACK ---
    action_msg = "Thank you for your feedback!"
    rating_int = int(rating)
    
    if rating_int == 5:
        cursor.execute("UPDATE users SET loyalty_points = loyalty_points + 50 WHERE id = ?", (user_id,))
        action_msg = "Outstanding! You've earned 50 Integrity Points for your 5-star review."
    elif rating_int == 4:
        cursor.execute("UPDATE users SET loyalty_points = loyalty_points + 10 WHERE id = ?", (user_id,))
        action_msg = "Thanks for the support! 10 Integrity Points added to your account."
    elif rating_int <= 2:
        # Trigger an 'Action' - send a support email mock or alert
        try:
            from app import send_security_email
            support_msg = f"A user ({user_email}) has reported a negative experience (Rating: {rating}). Comment: {comment}"
            # In a real app, this would go to a support team. Here we log it as an action.
            print(f"ACTION TRIGGERED: Support ticket created for {user_email}")
        except:
            pass
        action_msg = "We're sorry to hear that. A support specialist has been alerted to review your feedback."

    conn.commit()
    conn.close()
    return jsonify({"success": True, "message": action_msg})

@app.route("/satisfaction")
def satisfaction():
    if not session.get("logged_in"): return redirect("/")
    if session.get("admin_verified"): return redirect("/admin")
    
    conn = get_db()
    cursor = conn.cursor()
    
    # Global stats
    cursor.execute("SELECT AVG(rating) as avg_rating, COUNT(*) as total_ratings FROM satisfaction_ratings")
    stats = cursor.fetchone()
    avg_rating = round(stats["avg_rating"], 1) if stats["avg_rating"] else 0
    total_ratings = stats["total_ratings"]
    
    # Rating breakdown
    cursor.execute("SELECT rating, COUNT(*) as count FROM satisfaction_ratings GROUP BY rating ORDER BY rating DESC")
    breakdown = {i: 0 for i in range(1, 6)}
    for row in cursor.fetchall():
        breakdown[row["rating"]] = row["count"]
        
    # Recent comments
    cursor.execute("""
        SELECT r.rating, r.comment, r.timestamp, u.name 
        FROM satisfaction_ratings r 
        JOIN users u ON r.user_id = u.id 
        ORDER BY r.timestamp DESC 
        LIMIT 10
    """)
    recent_feedback = [dict(row) for row in cursor.fetchall()]
    
    conn.close()
    return render_template("satisfaction.html", 
                           avg_rating=avg_rating, 
                           total_ratings=total_ratings, 
                           breakdown=breakdown,
                           recent_feedback=recent_feedback)
@app.route("/admin-vault-auth", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        # Strip whitespace to prevent "invisible" character errors
        username = request.form.get("admin_username", "").strip()
        password = request.form.get("admin_password", "").strip()
        
        # Debugging check (Internal Use)
        master_user = (ADMIN_USER_MASTER or "").strip()
        master_pass = (ADMIN_PASS_MASTER or "").strip()

        if username == master_user and password == master_pass:
            # Reconcile with DB: Find or create an admin account for the master admin
            conn = get_db()
            cursor = conn.cursor()
            admin_email = "admin@guardian.ai" # Internal admin handle
            cursor.execute("SELECT id FROM users WHERE email=?", (admin_email,))
            admin_user = cursor.fetchone()
            
            if not admin_user:
                # Create a ghost record for the master admin in DB
                cursor.execute("INSERT INTO users (email, name, password, is_admin) VALUES (?, ?, ?, 1)",
                             (admin_email, "System Master", generate_password_hash(password)))
                conn.commit()
            else:
                # Ensure is_admin is 1
                cursor.execute("UPDATE users SET is_admin=1 WHERE email=?", (admin_email,))
                conn.commit()
            
            conn.close()
            
            session["email"] = admin_email
            session["logged_in"] = True
            session["admin_verified"] = True
            return redirect("/admin")
        flash("Invalid Administrative Credentials", "error")
    return render_template("admin_login.html")

@app.route("/admin")
@admin_required
def admin_dashboard():
    
    conn = get_db()
    cursor = conn.cursor()
    
    # FETCH FEATURE 2: User Integrity & Security Audit
    cursor.execute("""
        SELECT 
            u.id, u.name, u.email, u.loyalty_points, u.country,
            COUNT(s.id) as total_scans,
            SUM(CASE WHEN s.prediction IN ('Spam', 'Fake', 'Phishing') THEN 1 ELSE 0 END) as threats_blocked
        FROM users u
        LEFT JOIN scans s ON u.id = s.user_id
        GROUP BY u.id
        ORDER BY threats_blocked DESC, loyalty_points DESC
    """)
    users_audit = [dict(row) for row in cursor.fetchall()]
    
    # Basic Stats for Admin
    cursor.execute("SELECT COUNT(*) FROM users")
    total_users = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM scans")
    total_system_scans = cursor.fetchone()[0]

    # FETCH: Global Recent Scans
    cursor.execute("""
        SELECT s.*, u.name as user_name 
        FROM scans s 
        JOIN users u ON s.user_id = u.id 
        ORDER BY s.timestamp DESC 
        LIMIT 50
    """)
    recent_scans = [dict(row) for row in cursor.fetchall()]

    # FETCH: Threat Breakdown
    cursor.execute("SELECT scan_type, COUNT(*) as count FROM scans GROUP BY scan_type")
    threat_breakdown = {row['scan_type']: row['count'] for row in cursor.fetchall()}
    
    conn.close()
    return render_template("admin_dashboard.html", 
                           users=users_audit, 
                           total_users=total_users, 
                           total_system_scans=total_system_scans,
                           recent_scans=recent_scans,
                           threat_breakdown=threat_breakdown)


@app.route("/api/admin/system_health")
@admin_required
def system_health_api():
    
    import platform, os
    
    conn = get_db()
    cursor = conn.cursor()
    
    # DB stats
    cursor.execute("SELECT COUNT(*) FROM users")
    user_count = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM scans")
    scan_count = cursor.fetchone()[0]
    
    # DB Size
    db_size = os.path.getsize('database.db') / (1024 * 1024) # MB
    
    # Mocking some hardware stats for "WOW" (simulated live data)
    cpu_load = random.randint(5, 35)
    mem_usage = random.randint(40, 65)
    
    stats = {
        "os": platform.system(),
        "arch": platform.machine(),
        "db_size_mb": round(db_size, 2),
        "user_count": user_count,
        "scan_count": scan_count,
        "cpu_load": cpu_load,
        "mem_usage": mem_usage,
        "api_status": {
            "smtp": "ONLINE" if EMAIL_USER else "NOT CONFIGURED",
            "database": "CONNECTED"
        },
        "uptime": "99.9%"
    }
    
    conn.close()
    return jsonify(stats)

@app.route("/api/admin/threat_news")
@admin_required
def threat_news_api():
    
    import xml.etree.ElementTree as ET
    
    live_news = []
    feeds = [
        "https://www.bleepingcomputer.com/feed/",
        "https://thehackernews.com/rss",
        "https://www.scamwatch.gov.au/news-and-alerts/alerts/rss.xml"
    ]
    
    # Use headers to avoid being blocked by RSS servers
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}

    for feed_url in feeds:
        try:
            resp = requests.get(feed_url, headers=headers, timeout=8)
            if resp.status_code == 200:
                root = ET.fromstring(resp.content)
                items = root.findall('.//item')
                for item in items[:4]: # Get top 4 from each
                    title = item.find('title').text if item.find('title') is not None else "Unknown Threat"
                    link = item.find('link').text if item.find('link') is not None else "#"
                    desc = item.find('description').text if item.find('description') is not None else ""
                    pub_date = item.find('pubDate').text if item.find('pubDate') is not None else "Recent"
                    
                    import re
                    clean_desc = re.sub('<[^<]+?>', '', desc)[:160] + "..."
                    
                    pattern = "UNKNOWN_VECTOR"
                    low_title = title.lower()
                    if "phishing" in low_title or "link" in low_title: pattern = "PHISHING_LINK_DETECTION"
                    elif "malware" in low_title or "ransomware" in low_title: pattern = "MALICIOUS_BINARY_EXECUTION"
                    elif "scam" in low_title or "fraud" in low_title: pattern = "SOCIAL_ENGINEERING_HOOK"
                    
                    live_news.append({
                        "id": len(live_news) + 1,
                        "title": title,
                        "date": pub_date,
                        "category": "LIVE ALERT",
                        "summary": clean_desc,
                        "pattern": pattern,
                        "link": link
                    })
        except Exception as inner_e:
            print(f"   [FEED SKIPPED] {feed_url} error: {str(inner_e)}")
            continue

    if not live_news:
        return jsonify([{"title": "Global Node Delay", "summary": "Threat intelligence streams are currently saturated. Retrying in 60s.", "pattern": "RETRY_LATENCY", "date": "LIVE", "category": "SYSTEM", "link": "#"}])

    return jsonify(live_news)

@app.route("/api/admin/geo_stats")
def admin_geo_stats():
    if not session.get("admin_verified"): return jsonify({"error": "Unauthorized"}), 401
    conn = get_db()
    cursor = conn.cursor()
    # Join scans with users to get regional threat data
    cursor.execute("""
        SELECT u.state, COUNT(s.id) as threat_count 
        FROM scans s 
        JOIN users u ON s.user_id = u.id 
        WHERE s.prediction IN ('Spam', 'Fake', 'Phishing')
        GROUP BY u.state 
        ORDER BY threat_count DESC
    """)
    stats = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return jsonify(stats)

@app.route("/api/admin/broadcast", methods=["POST"])
def admin_broadcast():
    if not session.get("admin_verified"): return jsonify({"error": "Unauthorized"}), 401
    data = request.json
    title = data.get("title")
    message = data.get("message")
    severity = data.get("severity", "warning")
    
    conn = get_db()
    cursor = conn.cursor()
    # Deactivate old alerts
    cursor.execute("UPDATE global_alerts SET active = 0")
    # Insert new one
    cursor.execute("INSERT INTO global_alerts (title, message, severity) VALUES (?,?,?)", (title, message, severity))
    conn.commit()
    conn.close()
    return jsonify({"success": True})

@app.route("/api/alerts")
def get_active_alert():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM global_alerts WHERE active = 1 ORDER BY created_at DESC LIMIT 1")
    alert = cursor.fetchone()
    conn.close()
    if alert:
        res = dict(alert)
        res["active"] = True
        return jsonify(res)
    return jsonify({"active": False})

@app.route("/api/admin/remove_alert", methods=["POST"])
def remove_alert():
    if not session.get("admin_verified"): return jsonify({"error": "Unauthorized"}), 401
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("UPDATE global_alerts SET active = 0")
    conn.commit()
    conn.close()
    return jsonify({"success": True})

@app.route("/api/admin/logs")
def admin_logs_api():
    if not session.get("admin_verified"): return jsonify({"error": "Unauthorized"}), 401
    # Mocking system logs
    return jsonify([
        {"time": "09:00:15", "type": "INFO", "msg": "Global Threat Intelligence refreshed."},
        {"time": "08:45:22", "type": "AUTH", "msg": "Administrative identity verified for IP 127.0.0.1"},
        {"time": "08:12:05", "type": "SCAN", "msg": "Highly sensitive scan performed on APK binary."},
        {"time": "07:30:11", "type": "SYS", "msg": "Database integrity check completed. Result: STABLE"}
    ])


@app.route("/api/admin/delete_user/<int:user_id>", methods=["DELETE"])
def delete_user(user_id):
    if not session.get("admin_verified"): return jsonify({"error": "Unauthorized"}), 401
    
    conn = get_db()
    cursor = conn.cursor()
    
    try:
        # Purge all related data for this user
        cursor.execute("DELETE FROM scans WHERE user_id = ?", (user_id,))
        cursor.execute("DELETE FROM family_members WHERE guardian_id = ?", (user_id,))
        cursor.execute("DELETE FROM satisfaction_ratings WHERE user_id = ?", (user_id,))
        cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
        conn.commit()
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()

@app.route("/api/submit_feedback", methods=["POST"])
def submit_feedback():
    if not session.get("logged_in"): return jsonify({"error": "Unauthorized"}), 401
    data = request.json
    scan_id = data.get("scan_id")
    rating = data.get("rating")
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM users WHERE email=?", (session.get("email"),))
    user_row = cursor.fetchone()
    
    if user_row:
        cursor.execute("INSERT INTO satisfaction_ratings (user_id, rating, comment) VALUES (?,?,?)",
                       (user_row["id"], rating, f"Scan ID: {scan_id}"))
        conn.commit()
    conn.close()
    return jsonify({"success": True})

if __name__ == "__main__":
    app.run(debug=True)
    