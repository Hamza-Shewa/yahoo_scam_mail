#!/usr/bin/env python3
"""
Yahoo Mail SMART Scanner — All-In-One
======================================
The single script for detecting, blocking, and deleting scam emails.

Features
--------
- PASS 1: Ultra-fast batched sender analysis (500 headers per IMAP command)
  • Disposable / temp-mail domain detection
  • Suspicious TLD detection
  • Pre-compiled sender-address pattern matching
  • Spam display-name keyword detection (50+ keywords)
  • Brand impersonation / typosquatting detection
  • SPF / DKIM / DMARC authentication header checks
- PASS 2: Deep content analysis ONLY on suspicious senders
  • Scam keyword scanning in body text
  • Urgency language detection
  • Suspicious URL / URL-shortener detection
  • Generic greeting detection
  • ALL-CAPS shouting detection
  • Suspicious attachment references
- ACTIONS: Block senders, delete emails, enforce block list, export reports

PRESS 'B' DURING SCAN TO STOP AND SHOW RESULTS
"""

import imaplib
import email
import os
import re
import ssl
import socket
import sys
import time
from email.header import decode_header
from getpass import getpass
from datetime import datetime
from dataclasses import dataclass, field
from typing import List, Dict, Set, Tuple, Optional
from enum import Enum
from trusted_senders import load_trusted_data, domain_in_list

# Raise IMAP literal limit so large batch responses aren't truncated
imaplib._MAXLINE = 4_000_000

# ── Optional dependencies ──────────────────────────────────────────────
try:
    from dotenv import load_dotenv
    load_dotenv()
    DOTENV_AVAILABLE = True
except ImportError:
    DOTENV_AVAILABLE = False

# Windows keyboard detection
try:
    import msvcrt
    WINDOWS = True
except ImportError:
    WINDOWS = False

# ── Pre-compiled module-level regexes ──────────────────────────────────
_FROM_RE = re.compile(r'"?([^"<>]+)"?\s*<([^>]+)>')
_IP_DOMAIN_RE = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
_EMAIL_EXTRACT_RE = re.compile(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", re.I)

# ── Data classes ───────────────────────────────────────────────────────

class AuthStatus(Enum):
    PASS = "pass"
    FAIL = "fail"
    NEUTRAL = "neutral"
    NONE = "none"
    SOFTFAIL = "softfail"


@dataclass
class ScamEmail:
    """Complete scam email report."""
    uid: str
    subject: str
    sender_display: str
    sender_email: str
    date: str
    body_preview: str
    risk_level: str        # 🔴 HIGH, 🟡 MEDIUM, 🟢 LOW
    risk_score: int        # 0-100
    reasons: List[str]
    auth_issues: List[str] = field(default_factory=list)


@dataclass
class ScamSender:
    """Aggregated info about a scam sender."""
    email: str
    display_name: str
    email_count: int
    uids: List[str]
    risk_levels: List[str]
    max_risk_score: int
    sample_subjects: List[str]


# ════════════════════════════════════════════════════════════════════════
#  SmartScanner — the unified engine
# ════════════════════════════════════════════════════════════════════════

class SmartScanner:
    """
    All-in-one Yahoo Mail scam scanner.

    Two-pass scanning:
      Pass 1 — batched header-only fetch, fast sender/auth analysis
      Pass 2 — full-body deep content analysis (only for flagged senders)
    Plus: block-list enforcement, sender blocking, email deletion.
    """

    IMAP_SERVER = "imap.mail.yahoo.com"
    IMAP_PORT = 993

    # ── Trusted data (loaded once) ─────────────────────────────────────
    TRUSTED_DATA = load_trusted_data()
    TRUSTED_SENDERS = TRUSTED_DATA["trusted_senders"]
    TRUSTED_DOMAINS = TRUSTED_DATA["trusted_domains"]
    BRAND_DOMAINS  = TRUSTED_DATA["brand_domains"]
    BRAND_KEYWORDS = TRUSTED_DATA["brand_keywords"]

    # ── Suspicious / disposable domains ────────────────────────────────
    SUSPICIOUS_DOMAINS: Set[str] = {
        # Disposable email services
        'tempmail.com', 'guerrillamail.com', '10minutemail.com',
        'mailinator.com', 'yopmail.com', 'fakeinbox.com',
        'sharklasers.com', 'getairmail.com', 'throwawaymail.com',
        'trashmail.com', 'dispostable.com', 'maildrop.cc',
        'guerrillamailblock.com', 'grr.la', 'temp-mail.org',
        'mohmal.com', 'burnermail.io', 'tempail.com',
        'emailondeck.com', 'getnada.com', 'tempr.email',
        'inboxbear.com', 'mailsac.com', 'harakirimail.com',
        # Suspicious TLDs (start with dot)
        '.tk', '.ml', '.cf', '.ga', '.gq', '.buzz', '.top',
        '.xyz', '.click', '.loan', '.work', '.date', '.racing',
        '.win', '.bid', '.stream', '.review', '.faith',
        # Classic typosquats
        'amaz0n.com', 'paypa1.com', 'applle.com', 'micr0soft.com',
        'g00gle.com', 'faceb00k.com', 'netfl1x.com',
    }

    # ── Spam display-name keywords ─────────────────────────────────────
    SPAM_DISPLAY_KEYWORDS: Set[str] = {
        # Health / pharma / weight loss / supplements
        'male enhancement', 'male-enhancement', 'erectile', 'viagra', 'cialis',
        'testosterone', 'testosterone therapy', 'sexual wellness', 'libido',
        'anti-aging', 'anti aging', 'antiaging', 'weight loss', 'weight-loss',
        'diet pill', 'keto', 'detox', 'cancer flush', 'cancer cure',
        'cbd gummies', 'cbd oil', 'hemp gummies',
        'futurhealth', 'futurehealth', 'rex md', 'rexmd',
        'glp-1', 'glp1', 'wegovy', 'ozempic', 'semaglutide', 'tirzepatide',
        'medvi', 'trimrx', 'trim rx', 'meds weight loss',
        'prostate', 'tinnitus', 'silencer', 'heart attack', 'heart - attack',
        'poop lab', 'poop relief', 'dr. poop', 'clean poop', 'pinch trick',
        'ed visit', 'ed treatment', 'discreet ed',
        'oral-b dental', 'dental kit',
        'particle for', 'eyebags', 'wrinkles',
        'lifemed', 'lifemd', 'direct meds', 'sarah from direct',
        'magic mushroom', 'cheech and chong', 'cheech & chong',
        'focus restore', 'cerebra', 'memory loss',
        'younger gut', 'flavor infusion', 'pure flavor',
        'lume deodorant', 'body odor',
        'noom', 'orangetheory',
        'sono bello', 'sonobello', 'bello body', 'body contouring',
        'liposuction', 'laser lipo',
        'hims', 'hims partner', 'hims |',
        'gravité', 'gravite', 'gravit',
        # Financial / debt / lending
        'loan connection', 'payday loan', 'fast cash', 'easy loan',
        'credit card bonus', 'creditcardbonus', 'credit score',
        'debt relief', 'debt consolidation', 'free money',
        'debt-relief', 'debt free future', 'relief team', 'relief experts',
        'bitcoin profit', 'crypto profit', 'forex signal',
        'binary option', 'investment opportunity',
        'loan approval', 'instant loan', 'loan match', 'personal loan',
        'bad credit', 'forbadcredit', 'connect to cash',
        'americor', 'americor financial',
        'aspirecard', 'aspire card', 'fortivacard', 'fortiva card',
        'credit limit',
        'annuities', 'annuity', 'annuities offer', 'annuities info',
        'reverse mortgage', 'mortgage partner', 'mortgage eligibility',
        'fha rate', 'home equity', 'point home equity',
        'roundup claims', 'compensation is waiting', 'compensation awaits',
        'jgw relief',
        # Insurance
        'auto insurance', 'car insurance', 'life insurance',
        'health insurance', 'aca plan', 'aca plans', 'medicare',
        'affordable care', 'coverly', 'healthcare.com',
        'insurance rates', 'insurance quote', 'assurerates', 'assure rates',
        'provide.auto', 'rate kick',
        'whole life insurance', 'term life insurance',
        'assurifii', 'the zebra', 'vehicle protection',
        'home insurance', 'protection plans',
        # Fake antivirus / security scams
        'norton subscription', 'norton security', 'security alert',
        'security lifecycle', 'mcafee', 'protection disabled',
        'protection has expired', 'device infected',
        'final notice', 'payment failed', 'payment_failed',
        'payment declined', 'payment_declined',
        'account suspended', 'will be suspended',
        'action required', 'restore protection',
        'license has been revoked', 'protection_',
        'subscription terminated', 'subscription expired',
        'computer security expired',
        # Marketing / ad partner
        'ad partner', 'marketing partner', 'affiliate partner',
        'blissy ad', 'rad intel', 'special partnership',
        # Home improvement / services
        'gutter guard', 'gutter offer', 'gutter savior',
        'replacement window', 'renewal by andersen', 'renewalbyandersen',
        'bath remodel', 'remodel expert', 'remodel option', 'jacuzzi bath',
        'bathroom design', 'shorehome', 'west shore', 'westshorehome',
        'roofing', 'metal roof', 'innovations partner',
        'trugreen', 'lawn service', 'local experts',
        'door-ringer', 'doorbell',
        'saatva', 'saatva_affiliate',
        'window project',
        # Product / deal spam
        'night vision', 'provision_deal', 'polorvision', 'polar vision',
        'vision pro discount',
        'grounded footwear',
        'warbyparker', 'warby parker',
        'miracle sheet', 'miracle-sheet',
        'matsato', 'chef knife', 'kitchen knife', 'chef-quality',
        'precision kitchen', 'cision kitchen',
        'derila pillow', 'derila',
        'heated vest', 'solana gear', 'thermivest', 'thermi vest',
        'laser away', 'laseraway', 'hair removal',
        'home shield', 'ahs warranty',
        'windows partner',
        'seafood ad', 'usawildseafood', 'wild sea food',
        'unlimited media', 'flixy', 'flixy rewards',
        'earncashback', 'earn cash back', 'cash back rewards',
        'peak wellbeing',
        'good chop',
        'big shoes',
        'education partner',
        # Casino / gambling
        'casino', 'free spins', 'wild250',
        # Fake rewards / surveys / prizes
        'consumer rewards', 'spices rewards', 'set rewards',
        'kobalt tool', 'free kobalt',
        'state farm rewards', 'aaa rewards',
        "oprah's favorites", 'oprah loves',
        'sam\'s club partner', 'club partner',
        'order - shipping',
        # Firearms / survivalist spam
        'protect yourself', 'firearm',
        # Clickbait content farms
        'nutrition in usa', 'frugal american', 'retired in usa',
        'psychology diary', 'animal encyclopedia', 'cute animal planet',
        'mind bending', 'behind closed door', 'hidden gems',
        'must see places', 'detangle love', 'detangle',
        'devastating disaster', 'devastating',
        'door-ringer offer',
        # Dating / adult
        'dating.com', 'datemyage', 'date my age',
        'ukrainian girl', 'ukrainian girls',
        'connections start', 'singles near', 'find your match',
        'your match is waiting', 'meet singles',
        'hot singles', 'adult friend', 'dream soulmate',
        'someone special', 'eharmony',
        'shareowner', 'timeshare',
        # Generic spam
        'act now', 'limited time', 'exclusive offer', 'congratulations',
        'you have been selected', 'claim your', 'free gift',
        'winner', 'prize', 'lottery', 'sweepstake',
        'nigerian', 'inheritance', 'beneficiary',
        'work from home', 'make money fast', 'earn extra',
        'join aarp', 'aarp opportunity', 'aarp membership',
        'rfk jr', 'liberty mutual',
        'vision plans', 'vision benefits',
        'gold ira', 'gold trust', 'investor guide',
        'emergency kit', 'car emergency',
    }
    _SPAM_DISPLAY_RE = re.compile(
        '|'.join(re.escape(kw) for kw in sorted(SPAM_DISPLAY_KEYWORDS, key=len, reverse=True)),
        re.IGNORECASE,
    )

    # ── Pre-compiled sender-address patterns ───────────────────────────0
    SENDER_PATTERNS = [
        (re.compile(r'\d{8,}@'),                                              "Random digits in email (temp)"),
        (re.compile(r'support.*@gmail\.com$', re.I),                          "Gmail claiming to be support"),
        (re.compile(r'admin.*@gmail\.com$', re.I),                            "Gmail claiming to be admin"),
        (re.compile(r'service.*@gmail\.com$', re.I),                          "Gmail claiming to be service"),
        (re.compile(r'security.*@(?!yahoo\.com|google\.com|microsoft\.com)', re.I), "Generic security@ domain"),
        (re.compile(r'no-?reply.*@(?!yahoo|google|microsoft|apple)', re.I),   "Generic noreply@ domain"),
        (re.compile(r'verify.*@', re.I),                                      "Verify@ pattern"),
        (re.compile(r'update.*@', re.I),                                      "Update@ pattern"),
        (re.compile(r'alert.*@', re.I),                                       "Alert@ pattern"),
        (re.compile(r'notify.*@', re.I),                                      "Notify@ pattern"),
        (re.compile(r'confirm.*@', re.I),                                     "Confirm@ pattern"),
        (re.compile(r'account.*@(?!yahoo|google)', re.I),                     "Generic account@ domain"),
    ]

    # ── Typosquat map ──────────────────────────────────────────────────
    _LOOKALIKES = {
        'amazon':    ('amaz0n', 'amazan', 'arnazon', 'amazom'),
        'paypal':    ('paypa1', 'paypall', 'paypaI', 'payp4l'),
        'apple':     ('applle', 'aple', 'app1e', 'appie'),
        'microsoft': ('micr0soft', 'micros0ft', 'rnicrosoft'),
        'google':    ('g00gle', 'googIe', 'goggle', 'goog1e'),
        'netflix':   ('netfl1x', 'netfllix', 'netflixx'),
        'yahoo':     ('yah00', 'yaho0', 'yah0o'),
    }

    # ── Body content scam analysis (Pass 2) ────────────────────────────
    SCAM_KEYWORDS = [
        "wire transfer", "western union", "moneygram", "send money",
        "inheritance", "next of kin", "deceased", "prince", "barrister",
        "diplomat", "confidential business", "business proposal",
        "double your money", "get rich quick",
        "act immediately", "urgent response needed", "urgent response",
        "verify account", "suspended", "click link", "click here to verify",
        "confirm your identity", "update payment", "unusual activity",
        "unusual login", "suspicious activity",
        "password expired", "will be deleted", "lose access",
        "won lottery", "cash prize", "million dollars", "free gift",
        "cryptocurrency investment", "bitcoin profit", "forex trading",
        "binary options", "work from home", "earn daily",
        "no experience needed", "guaranteed income",
        "health", "pharmacy", "viagra", "cialis", "weight loss", "diet pill",
        "insurance", "loan approval", "debt relief", "credit card",
        "bank account details", "credit card details",
        "social security", "tax refund", "government grant",
        "ssn", "passport number",
        "claim your prize", "lottery winner", "you won", "congratulations",
    ]
    URGENCY_WORDS = [
        "urgent", "immediately", "asap", "now", "limited time",
        "expires", "act now", "expires soon",
    ]

    # Pre-compiled subject patterns
    _SUBJECT_PATTERNS = [
        re.compile(p, re.I) for p in [
            r"urgent.*action.*required", r"verify.*account.*immediately",
            r"suspended.*account", r"limited.*access",
            r"\$\d+[,.]?\d*\s*(million|thousand|USD|dollars?)",
            r"won.*lottery", r"inheritance", r"prince",
            r"confidential.*proposal", r"dear.*customer",
            r"dear.*user", r"dear.*valued",
            r"click.*link.*verify", r"update.*payment.*info",
            r"unusual.*activity", r"password.*expir",
            r"free.*gift", r"act.*now", r"limited.*time",
            r"urgent.*response", r"wire.*transfer", r"bank.*verify",
            r"tax.*refund",
        ]
    ]

    # ═══════════════════════════════════════════════════════════════════
    #  Construction / connection
    # ═══════════════════════════════════════════════════════════════════

    def __init__(self, email_address: str, password: str):
        self.email_address = email_address
        self.password = password
        self.mail: Optional[imaplib.IMAP4_SSL] = None
        self.interrupted = False
        self.stats: Dict[str, int] = {
            'total_checked': 0,
            'sender_filtered': 0,
            'deep_analyzed': 0,
            'scams_found': 0,
        }
        self.scam_senders: Dict[str, ScamSender] = {}

        # Split SUSPICIOUS_DOMAINS into TLD suffixes vs exact domains
        self._suspicious_tlds: Set[str] = set()
        self._suspicious_exact: Set[str] = set()
        for d in self.SUSPICIOUS_DOMAINS:
            if d.startswith('.'):
                self._suspicious_tlds.add(d)
            else:
                self._suspicious_exact.add(d)

    # ── keyboard break ─────────────────────────────────────────────────

    def check_break_key(self) -> bool:
        if not WINDOWS:
            return False
        try:
            if msvcrt.kbhit():
                key = msvcrt.getch().decode('utf-8', errors='ignore').upper()
                if key == 'B':
                    self.interrupted = True
                    return True
        except Exception:
            pass
        return False

    # ── IMAP helpers ───────────────────────────────────────────────────

    def connect(self) -> bool:
        try:
            print(f"📡 Connecting to Yahoo IMAP {self.IMAP_SERVER}:{self.IMAP_PORT}...")
            ctx = ssl.create_default_context()
            try:
                self.mail = imaplib.IMAP4_SSL(
                    self.IMAP_SERVER, self.IMAP_PORT,
                    ssl_context=ctx, timeout=15,
                )
            except TypeError:
                self.mail = imaplib.IMAP4_SSL(self.IMAP_SERVER, self.IMAP_PORT)

            status, _ = self.mail.login(self.email_address, self.password)
            if status == "OK":
                print("✅ Connected!\n")
                return True
            return False

        except ssl.SSLError as e:
            print(f"❌ SSL error: {e}")
            try:
                s = socket.create_connection((self.IMAP_SERVER, self.IMAP_PORT), timeout=10)
                try:
                    banner = s.recv(1024)
                    if banner:
                        print(f"   Banner: {banner.decode('utf-8', errors='replace')[:200]}")
                    else:
                        print("   No banner (server likely expects SSL handshake)")
                finally:
                    s.close()
            except Exception:
                pass
            print("   Hint: check network/proxy, use a Yahoo App Password.")
            return False
        except Exception as e:
            print(f"❌ Connection failed: {e}")
            print("   Note: use Yahoo App Password, not your regular password.")
            return False

    def disconnect(self):
        if self.mail:
            try:
                self.mail.close()
            except Exception:
                pass
            try:
                self.mail.logout()
            except Exception:
                pass

    def get_spam_folder(self) -> Optional[str]:
        """Resolve the Spam/Junk folder name for this mailbox."""
        if not self.mail:
            return None
        try:
            status, data = self.mail.list()
            if status != "OK" or not data:
                return None
            mailboxes: List[str] = []
            for line in data:
                if not line:
                    continue
                decoded = line.decode('utf-8', errors='replace') if isinstance(line, bytes) else str(line)
                match = re.search(r'"([^"]+)"\s*$', decoded)
                mailboxes.append(match.group(1) if match else decoded.split(' "/" ')[-1].strip('"'))
            for name in mailboxes:
                if name.lower() == "spam":
                    return name
            for candidate in ("bulk mail", "junk", "junk e-mail", "junk email"):
                for name in mailboxes:
                    if name.lower() == candidate:
                        return name
            for name in mailboxes:
                lower = name.lower()
                if "spam" in lower or "junk" in lower or "bulk" in lower:
                    return name
            return None
        except Exception:
            return None

    # ── Header decode / extract helpers ────────────────────────────────

    def decode_str(self, s) -> str:
        if not s:
            return ""
        if isinstance(s, bytes):
            return s.decode('utf-8', errors='replace')
        parts = decode_header(s)
        result = ""
        for part, charset in parts:
            if isinstance(part, bytes):
                result += part.decode(charset or 'utf-8', errors='replace')
            else:
                result += part
        return result

    def extract_email_parts(self, from_header: str) -> Tuple[str, str]:
        """Return (display_name, email_address) from a From header."""
        from_header = self.decode_str(from_header)
        # Try standard  "Name" <email>  pattern
        m = _FROM_RE.match(from_header)
        if m:
            return m.group(1).strip(), m.group(2).strip().lower()
        # Fallback: search for <email@domain> anywhere in the string
        m2 = re.search(r'<([^<>]+@[^<>]+)>', from_header)
        if m2:
            display = from_header[:m2.start()].strip().strip('"')
            return display or m2.group(1), m2.group(1).strip().lower()
        # Fallback: extract bare email anywhere in the string
        m3 = _EMAIL_EXTRACT_RE.search(from_header)
        if m3:
            return from_header, m3.group(0).lower()
        return from_header, from_header

    @staticmethod
    def _safe_addr(addr: str) -> Optional[str]:
        """Ensure addr is pure ASCII for IMAP SEARCH. Extract email if needed."""
        try:
            addr.encode('ascii')
            return addr
        except UnicodeEncodeError:
            m = _EMAIL_EXTRACT_RE.search(addr)
            return m.group(0).lower() if m else None

    def extract_body(self, msg) -> str:
        """Extract text body (plain preferred, HTML fallback) — capped at 5 000 chars."""
        body = ""
        if msg.is_multipart():
            for part in msg.walk():
                ctype = part.get_content_type()
                disp = str(part.get("Content-Disposition", ""))
                if ctype == "text/plain" and "attachment" not in disp:
                    try:
                        payload = part.get_payload(decode=True)
                        if payload:
                            body += payload.decode(part.get_content_charset() or 'utf-8', errors='replace')
                    except Exception:
                        pass
                elif ctype == "text/html" and "attachment" not in disp and not body:
                    try:
                        payload = part.get_payload(decode=True)
                        if payload:
                            html = payload.decode(part.get_content_charset() or 'utf-8', errors='replace')
                            body = re.sub(r'<[^>]+>', ' ', html)
                            body = re.sub(r'\s+', ' ', body)
                    except Exception:
                        pass
        else:
            try:
                payload = msg.get_payload(decode=True)
                if payload:
                    body = payload.decode(msg.get_content_charset() or 'utf-8', errors='replace')
            except Exception:
                pass
        return body[:5000]

    # ── Authentication header parsing ──────────────────────────────────

    def parse_auth_header(self, header: str) -> Dict[str, str]:
        """Parse Authentication-Results → {spf, dkim, dmarc} status strings."""
        results = {'spf': 'none', 'dkim': 'none', 'dmarc': 'none'}
        if not header:
            return results
        h = header.lower()
        for check in ('spf', 'dkim', 'dmarc'):
            for result in ('pass', 'fail', 'softfail', 'neutral', 'none'):
                if f'{check}={result}' in h:
                    results[check] = result
                    break
        return results

    # ═══════════════════════════════════════════════════════════════════
    #  PASS 1  — fast batched sender + auth analysis
    # ═══════════════════════════════════════════════════════════════════

    def _analyze_sender(self, display_name: str, email_addr: str,
                        auth: Dict[str, str]) -> Tuple[List[str], List[str]]:
        """
        Analyze a sender address + auth results.
        Returns (reasons, auth_issues).
        """
        reasons: List[str] = []
        auth_issues: List[str] = []
        email_lower = email_addr.lower()
        domain = email_addr.rsplit('@', 1)[-1] if '@' in email_addr else ''
        display_lower = display_name.lower()

        # Fast-path: trusted
        if email_lower in self.TRUSTED_SENDERS or domain_in_list(domain, self.TRUSTED_DOMAINS):
            return reasons, auth_issues

        # 1) Suspicious exact domain
        if domain in self._suspicious_exact:
            reasons.append(f"Suspicious domain: {domain}")

        # 2) Suspicious TLD
        for tld in self._suspicious_tlds:
            if domain.endswith(tld):
                reasons.append(f"Suspicious TLD: {tld}")
                break

        # 3) Pre-compiled address patterns
        for pattern, reason in self.SENDER_PATTERNS:
            if pattern.search(email_lower):
                reasons.append(reason)

        # 4) Brand impersonation in display name
        for brand in self.BRAND_KEYWORDS:
            if brand in display_lower and brand not in domain:
                if not any(legit in domain for legit in [brand, 'yahoo.com', 'google.com']):
                    reasons.append(f"Possible {brand.title()} spoofing")
                    break

        # 5) Typosquatting
        for legit, fakes in self._LOOKALIKES.items():
            for fake in fakes:
                if fake in domain and legit not in domain:
                    reasons.append(f"Typosquatting: fake {legit}")
                    break

        # 6) Brand domain check with auth
        for brand, allowed_domains in self.BRAND_DOMAINS.items():
            if brand in display_lower and not domain_in_list(domain, allowed_domains):
                if auth['spf'] != 'pass' or auth['dkim'] != 'pass':
                    if f"Possible {brand.title()} spoofing" not in reasons:
                        reasons.append(f"Possible {brand.title()} spoofing (auth fail)")
                    break

        # 7) Spam display-name keywords
        spam_match = self._SPAM_DISPLAY_RE.search(display_lower)
        if spam_match:
            reasons.append(f"Spam keyword in display name: '{spam_match.group()}'")

        # 8) Subdomain / IP checks
        if domain.count('.') >= 3:
            reasons.append("Suspicious subdomain structure")
        if _IP_DOMAIN_RE.match(domain):
            reasons.append("IP address instead of domain")

        # 9) Auth failures
        if auth['spf'] == 'fail':
            auth_issues.append("SPF FAIL")
        if auth['dkim'] == 'fail':
            auth_issues.append("DKIM FAIL")
        if auth['dmarc'] == 'fail':
            auth_issues.append("DMARC FAIL")

        return reasons, auth_issues

    def pass1_sender_filter(self, folder: str, limit: int = 0) -> Dict[str, Dict]:
        """
        PASS 1: Batched header-only sender + auth analysis.
        Returns dict  {email_addr: {display, reasons, auth_issues, uids, count}}.
        """
        print(f"📁 PASS 1: Sender Analysis  ({folder})")
        print("-" * 60)
        print("   💡 Press 'B' at any time to stop and show results\n")

        status, _ = self.mail.select(folder, readonly=True)
        if status != "OK":
            print(f"   ⚠️  Could not open folder: {folder}")
            return {}

        status, data = self.mail.uid('SEARCH', None, 'ALL')
        if status != "OK":
            return {}

        uids = data[0].split()
        if limit > 0:
            uids = uids[-limit:]
        total = len(uids)
        self.stats['total_checked'] += total
        print(f"   Total emails: {total}\n")

        t0 = time.perf_counter()
        suspicious: Dict[str, Dict] = {}
        processed = 0
        batch_size = 500

        for i in range(0, total, batch_size):
            if self.check_break_key():
                print(f"\n\n⛔ STOPPED by user  ({processed}/{total} processed)")
                break

            batch = uids[i:i + batch_size]
            uid_set = b','.join(batch)

            try:
                status, response = self.mail.uid(
                    'FETCH', uid_set,
                    '(BODY.PEEK[HEADER.FIELDS (FROM AUTHENTICATION-RESULTS RETURN-PATH)])',
                )
                if status != "OK":
                    continue

                idx = 0
                while idx < len(response):
                    item = response[idx]
                    if isinstance(item, tuple) and len(item) == 2:
                        envelope, header_bytes = item
                        uid_match = re.search(rb'UID (\d+)', envelope)
                        uid_str = uid_match.group(1).decode() if uid_match else ''

                        try:
                            msg = email.message_from_bytes(header_bytes)
                            from_hdr = msg.get('From', '')
                            auth_hdr = msg.get('Authentication-Results', '')
                            return_path = msg.get('Return-Path', '')

                            if not from_hdr:
                                idx += 1
                                processed += 1
                                continue

                            display_name, email_addr = self.extract_email_parts(from_hdr)
                            auth = self.parse_auth_header(auth_hdr)
                            reasons, auth_issues = self._analyze_sender(display_name, email_addr, auth)

                            # Return-path mismatch
                            if return_path:
                                rp_match = re.search(r'<([^>]+)>', return_path)
                                rp_email = rp_match.group(1).lower() if rp_match else return_path.strip().lower()
                                if rp_email and rp_email != email_addr and auth['spf'] != 'pass':
                                    domain = email_addr.rsplit('@', 1)[-1] if '@' in email_addr else ''
                                    is_protected = any(
                                        domain_in_list(domain, doms) for doms in self.BRAND_DOMAINS.values()
                                    )
                                    if is_protected:
                                        reasons.append(f"Return-Path mismatch: {rp_email}")

                            if reasons or auth_issues:
                                self.stats['sender_filtered'] += 1
                                if email_addr not in suspicious:
                                    suspicious[email_addr] = {
                                        'display': display_name,
                                        'reasons': list(set(reasons)),
                                        'auth_issues': auth_issues,
                                        'uids': [],
                                        'count': 0,
                                    }
                                sd = suspicious[email_addr]
                                sd['count'] += 1
                                if len(sd['uids']) < 20:
                                    sd['uids'].append(uid_str)
                                # Merge new reasons
                                existing = set(sd['reasons'])
                                for r in reasons:
                                    if r not in existing:
                                        sd['reasons'].append(r)
                                        existing.add(r)
                                for a in auth_issues:
                                    if a not in sd['auth_issues']:
                                        sd['auth_issues'].append(a)

                            processed += 1
                        except Exception:
                            processed += 1
                    idx += 1

            except Exception:
                # Fallback: one-by-one for this batch
                for uid in batch:
                    if self.check_break_key():
                        break
                    try:
                        st, md = self.mail.uid(
                            'FETCH', uid,
                            '(BODY.PEEK[HEADER.FIELDS (FROM AUTHENTICATION-RESULTS RETURN-PATH)])',
                        )
                        if st != "OK" or not md[0]:
                            continue
                        msg = email.message_from_bytes(md[0][1])
                        from_hdr = msg.get('From', '')
                        if not from_hdr:
                            continue
                        display_name, email_addr = self.extract_email_parts(from_hdr)
                        auth = self.parse_auth_header(msg.get('Authentication-Results', ''))
                        reasons, auth_issues = self._analyze_sender(display_name, email_addr, auth)
                        if reasons or auth_issues:
                            self.stats['sender_filtered'] += 1
                            if email_addr not in suspicious:
                                suspicious[email_addr] = {
                                    'display': display_name,
                                    'reasons': list(set(reasons)),
                                    'auth_issues': auth_issues,
                                    'uids': [],
                                    'count': 0,
                                }
                            sd = suspicious[email_addr]
                            sd['count'] += 1
                            if len(sd['uids']) < 20:
                                sd['uids'].append(uid.decode())
                        processed += 1
                    except Exception:
                        continue

            if self.interrupted:
                break

            elapsed = time.perf_counter() - t0
            rate = processed / elapsed if elapsed > 0 else 0
            progress = min(i + batch_size, total)
            print(f"   Progress: {progress}/{total}  ({rate:.0f}/sec)  Press 'B' to stop", end='\r')

        elapsed = time.perf_counter() - t0
        rate = processed / elapsed if elapsed > 0 else 0
        print(f"   Progress: {processed}/{total}  ({elapsed:.1f}s, {rate:.0f}/sec){' ' * 20}")
        print(f"   ⚠️  {len(suspicious)} suspicious sender(s)  ({self.stats['sender_filtered']} emails)\n")
        return suspicious

    # ═══════════════════════════════════════════════════════════════════
    #  PASS 2  — deep body / content analysis
    # ═══════════════════════════════════════════════════════════════════

    def pass2_deep_analysis(self, suspicious: Dict[str, Dict]) -> List[ScamEmail]:
        """
        PASS 2: Full-body analysis only for emails from suspicious senders.
        """
        print("📁 PASS 2: Deep Content Analysis")
        print("-" * 60)

        all_uids: List[str] = []
        uid_to_sender: Dict[str, str] = {}
        for sender_email, sd in suspicious.items():
            for uid in sd['uids']:
                all_uids.append(uid)
                uid_to_sender[uid] = sender_email

        if not all_uids:
            print("   No suspicious emails to deep-analyze.\n")
            return []

        print(f"   Analyzing {len(all_uids)} email(s) from {len(suspicious)} sender(s)...\n")

        scams: List[ScamEmail] = []

        for i, uid in enumerate(all_uids, 1):
            if self.check_break_key():
                print(f"\n\n⛔ STOPPED  ({i - 1}/{len(all_uids)} analyzed)")
                break

            print(f"   Deep analysis: {i}/{len(all_uids)}  Press 'B' to stop", end='\r')

            try:
                status, msg_data = self.mail.uid('FETCH', uid.encode(), '(RFC822)')
                if status != "OK":
                    continue

                msg = email.message_from_bytes(msg_data[0][1])
                subject = self.decode_str(msg.get('Subject', '(No Subject)'))
                from_hdr = self.decode_str(msg.get('From', 'Unknown'))
                date = msg.get('Date', 'Unknown')
                display_name, email_addr = self.extract_email_parts(from_hdr)

                sender_data = suspicious.get(email_addr, {'reasons': [], 'auth_issues': []})
                body = self.extract_body(msg)
                body_lower = body.lower()
                subject_lower = subject.lower()

                content_reasons: List[str] = []
                score = len(sender_data.get('reasons', [])) * 10 + 20  # base from pass 1

                # Subject patterns
                for pat in self._SUBJECT_PATTERNS:
                    if pat.search(subject):
                        content_reasons.append(f"Suspicious subject: '{pat.pattern[:30]}…'")
                        score += 15

                # Body scam keywords
                kw_count = 0
                for kw in self.SCAM_KEYWORDS:
                    if kw in body_lower:
                        kw_count += 1
                        if kw_count <= 3:
                            content_reasons.append(f"Scam keyword: '{kw}'")
                        score += 8

                # Urgency language
                urgency_count = sum(1 for u in self.URGENCY_WORDS if u in body_lower)
                if urgency_count >= 2:
                    content_reasons.append("Excessive urgency language")
                    score += 15

                # Suspicious URLs
                if re.search(r'https?://\d{1,3}\.\d{1,3}\.', body_lower):
                    content_reasons.append("IP-based URL")
                    score += 12
                shorteners = ['bit.ly', 'tinyurl', 't.co', 'goo.gl', 'ow.ly']
                for sh in shorteners:
                    if sh in body_lower:
                        content_reasons.append("URL shortener detected")
                        score += 8
                        break
                if re.search(r'https?://[^\s]*[.-](verify|secure|login|account|update|confirm)', body_lower):
                    content_reasons.append("Suspicious URL pattern")
                    score += 12

                # ALL CAPS
                if len(re.findall(r'\b[A-Z]{6,}\b', body)) >= 4:
                    content_reasons.append("Excessive caps")
                    score += 5

                # Generic greeting
                greetings = ['dear customer', 'dear user', 'dear valued', 'dear account holder']
                if any(g in body_lower[:500] for g in greetings):
                    content_reasons.append("Generic greeting")
                    score += 8

                # Suspicious attachment reference
                if "attachment" in body_lower and any(
                    x in subject_lower for x in ("invoice", "receipt", "document", "urgent")
                ):
                    content_reasons.append("Suspicious attachment reference")
                    score += 10

                # Display name / email mismatch
                if "<" in from_hdr and ">" in from_hdr:
                    dn = from_hdr.split("<")[0].strip().strip('"').lower()
                    ep = from_hdr.split("<")[1].split(">")[0].lower()
                    if "@" in dn and dn != ep:
                        content_reasons.append("Display-name/email mismatch")
                        score += 20

                # Combine — de-duplicate while preserving order
                all_reasons = list(dict.fromkeys(
                    sender_data.get('reasons', []) + content_reasons
                ))
                score = min(score, 100)

                if score >= 25:
                    risk = "🔴 HIGH" if score >= 50 else "🟡 MEDIUM" if score >= 30 else "🟢 LOW"
                    scams.append(ScamEmail(
                        uid=uid,
                        subject=subject,
                        sender_display=display_name,
                        sender_email=email_addr,
                        date=date,
                        body_preview=body[:150].replace('\n', ' '),
                        risk_level=risk,
                        risk_score=score,
                        reasons=all_reasons[:10],
                        auth_issues=sender_data.get('auth_issues', []),
                    ))

                self.stats['deep_analyzed'] += 1

            except Exception:
                continue

        print(f"   Complete!  {self.stats['deep_analyzed']} analyzed, {len(scams)} confirmed scam(s){' ' * 20}\n")
        self.stats['scams_found'] = len(scams)
        return scams

    # ═══════════════════════════════════════════════════════════════════
    #  Aggregation helpers
    # ═══════════════════════════════════════════════════════════════════

    def aggregate_scam_senders(self, scams: List[ScamEmail]) -> Dict[str, ScamSender]:
        senders: Dict[str, ScamSender] = {}
        for scam in scams:
            if scam.sender_email not in senders:
                senders[scam.sender_email] = ScamSender(
                    email=scam.sender_email,
                    display_name=scam.sender_display,
                    email_count=0, uids=[], risk_levels=[],
                    max_risk_score=0, sample_subjects=[],
                )
            s = senders[scam.sender_email]
            s.email_count += 1
            s.uids.append(scam.uid)
            s.risk_levels.append(scam.risk_level)
            s.max_risk_score = max(s.max_risk_score, scam.risk_score)
            if len(s.sample_subjects) < 3:
                s.sample_subjects.append(scam.subject)
        return senders

    # ═══════════════════════════════════════════════════════════════════
    #  Blocking / deletion / block-list enforcement
    # ═══════════════════════════════════════════════════════════════════

    def block_senders(self, sender_dict: Dict[str, ScamSender]) -> int:
        """Move emails from scam senders to Spam + append to blocked_senders.txt."""
        if not sender_dict:
            return 0

        print("\n🛡️  Blocking Scam Senders...")
        print("-" * 60)

        # Persist to blocked_senders.txt
        try:
            with open('blocked_senders.txt', 'a', encoding='utf-8') as f:
                f.write(f"\n# Blocked on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                for addr in sender_dict:
                    f.write(f"{addr}\n")
            print(f"   ✅ Saved {len(sender_dict)} sender(s) to blocked_senders.txt")
        except Exception as e:
            print(f"   ⚠️  Could not save: {e}")

        # Also append to block_list.txt for the enforcer
        try:
            with open('block_list.txt', 'a', encoding='utf-8') as f:
                f.write(f"\n# Auto-added {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                for addr, sender in sender_dict.items():
                    reasons_short = ', '.join(sender.sample_subjects[:1]) if sender.sample_subjects else ''
                    f.write(f"{addr}  # {reasons_short}\n")
            print(f"   ✅ Appended to block_list.txt")
        except Exception as e:
            print(f"   ⚠️  Could not update block_list.txt: {e}")

        # Move to Spam
        spam_folder = self.get_spam_folder()
        if not spam_folder:
            print("   ⚠️  Spam folder not found — skipping move.")
            return 0

        moved = 0
        status, _ = self.mail.select("INBOX")
        if status != "OK":
            return 0

        for addr in sender_dict:
            safe = self._safe_addr(addr)
            if not safe:
                print(f"   ⚠️  Skipped (non-ASCII): {addr[:40]}")
                continue
            try:
                st, data = self.mail.uid('SEARCH', None, f'FROM "{safe}"')
                if st == "OK" and data[0]:
                    uid_set = data[0].replace(b' ', b',')
                    self.mail.uid('COPY', uid_set, spam_folder)
                    n = len(data[0].split())
                    moved += n
                    print(f"   📨 {safe}: {n} → {spam_folder}")
            except Exception as e:
                print(f"   ⚠️  {safe}: {e}")

        print(f"\n   ✅ {moved} email(s) moved to {spam_folder}")
        print("-" * 60)
        return moved

    def delete_scam_emails(self, sender_dict: Dict[str, ScamSender]) -> int:
        """Permanently delete all emails from scam senders (INBOX + Spam)."""
        if not sender_dict:
            return 0

        print("\n🗑️  Deleting Scam Emails...")
        print("-" * 60)

        total_deleted = 0

        for folder in ("INBOX", self.get_spam_folder() or ""):
            if not folder:
                continue
            try:
                status, _ = self.mail.select(folder)
                if status != "OK":
                    continue
                folder_del = 0
                for addr in sender_dict:
                    safe = self._safe_addr(addr)
                    if not safe:
                        continue
                    try:
                        st, data = self.mail.uid('SEARCH', None, f'FROM "{safe}"')
                        if st == "OK" and data[0]:
                            uid_set = data[0].replace(b' ', b',')
                            self.mail.uid('STORE', uid_set, '+FLAGS', '(\\Deleted)')
                            folder_del += len(data[0].split())
                    except Exception:
                        pass
                if folder_del:
                    self.mail.expunge()
                    print(f"   🗑️  {folder}: {folder_del} deleted")
                total_deleted += folder_del
            except Exception as e:
                print(f"   ⚠️  {folder}: {e}")

        print(f"\n   🗑️  Total deleted: {total_deleted}")
        print("-" * 60)
        return total_deleted

    def enforce_block_list(self, block_list_path: str = "block_list.txt") -> int:
        """
        Read block_list.txt and delete all messages from those senders.
        Scans INBOX and Spam.
        """
        print("\n🛡️  BLOCK LIST ENFORCER")
        print("-" * 60)

        senders: List[str] = []
        try:
            with open(block_list_path, 'r', encoding='utf-8') as f:
                for line in f:
                    raw = line.strip()
                    if not raw or raw.startswith('#'):
                        continue
                    entry = raw.split('#', 1)[0].strip()
                    m = _EMAIL_EXTRACT_RE.search(entry)
                    if m:
                        senders.append(m.group(0).lower())
        except FileNotFoundError:
            print(f"   ⚠️  {block_list_path} not found — skipping.")
            return 0

        senders = sorted(set(senders))
        if not senders:
            print("   No senders in block list.")
            return 0

        print(f"   📋 {len(senders)} blocked sender(s) loaded\n")

        grand_total = 0
        for folder in ("INBOX", self.get_spam_folder() or ""):
            if not folder:
                continue
            try:
                status, info = self.mail.select(folder)
                if status != "OK":
                    continue
                total_msgs = int(info[0]) if info and info[0] else 0
                print(f"   📁 {folder}  ({total_msgs} messages)")
                folder_del = 0
                for sender in senders:
                    safe = self._safe_addr(sender)
                    if not safe:
                        print(f"      ⚠️  Skipped (non-ASCII): {sender[:40]}")
                        continue
                    try:
                        st, data = self.mail.uid('SEARCH', None, f'FROM "{safe}"')
                        if st == "OK" and data[0]:
                            uid_set = data[0].replace(b' ', b',')
                            self.mail.uid('STORE', uid_set, '+FLAGS', '(\\Deleted)')
                            n = len(data[0].split())
                            folder_del += n
                            if n:
                                print(f"      🗑️  {safe}: {n}")
                    except Exception as e:
                        print(f"      ⚠️  {safe}: {e}")
                if folder_del:
                    self.mail.expunge()
                grand_total += folder_del
            except Exception as e:
                print(f"   ⚠️  {folder}: {e}")

        print(f"\n   ✅ Block-list enforced: {grand_total} email(s) deleted")
        print("-" * 60)
        return grand_total

    def export_block_list(self, sender_dict: Dict[str, ScamSender],
                          filename: str = "block_list.txt"):
        """Export / append scam senders to block_list.txt."""
        with open(filename, 'a', encoding='utf-8') as f:
            f.write(f"\n# Exported {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            for addr, sender in sender_dict.items():
                reasons_str = ', '.join(sender.sample_subjects[:1]) if sender.sample_subjects else ''
                f.write(f"{addr}  # {reasons_str}\n")
        print(f"\n📝 Exported {len(sender_dict)} sender(s) to {filename}")

    # ═══════════════════════════════════════════════════════════════════
    #  Reporting / display
    # ═══════════════════════════════════════════════════════════════════

    def print_scam_senders(self, sender_dict: Dict[str, ScamSender]):
        if not sender_dict:
            return
        print("\n" + "─" * 80)
        print("                    📧 SCAM SENDERS LIST")
        print("─" * 80)
        print(f"\n   {len(sender_dict)} unique scam sender(s):\n")
        sorted_senders = sorted(sender_dict.values(),
                                key=lambda x: x.max_risk_score, reverse=True)
        for i, s in enumerate(sorted_senders, 1):
            icon = "🔴" if s.max_risk_score >= 50 else ("🟡" if s.max_risk_score >= 30 else "🟢")
            print(f"   {i}. {icon} {s.display_name}")
            print(f"      📧 {s.email}")
            print(f"      📊 {s.email_count} email(s)  |  Risk score: {s.max_risk_score}/100")
            if s.sample_subjects:
                print(f"      📝 \"{s.sample_subjects[0][:60]}\"")
            print()
        print("─" * 80)

    def print_results(self, scams: List[ScamEmail], partial: bool = False):
        print("\n" + "=" * 80)
        if partial:
            print("                    🛡️ PARTIAL SCAN RESULTS")
            print("                    (Stopped by user)")
        else:
            print("                    🛡️ SMART SCAN RESULTS")
        print("=" * 80)

        print(f"\n📊 Statistics:")
        print(f"   • Total emails checked : {self.stats['total_checked']}")
        print(f"   • Suspicious senders   : {len(set(s.sender_email for s in scams)) if scams else 0}")
        print(f"   • Deep-analyzed        : {self.stats['deep_analyzed']}")
        print(f"   • Confirmed scams      : {self.stats['scams_found']}")

        if not scams:
            print("\n✅ No scam emails detected!")
            return

        scams.sort(key=lambda x: x.risk_score, reverse=True)
        print(f"\n⚠️  CONFIRMED SCAM EMAILS ({len(scams)}):\n")

        for i, scam in enumerate(scams, 1):
            print("─" * 80)
            print(f"  #{i}  {scam.risk_level}  Score: {scam.risk_score}/100")
            print("─" * 80)
            print(f"  From:    {scam.sender_display} <{scam.sender_email}>")
            print(f"  Subject: {scam.subject}")
            print(f"  Date:    {scam.date}")
            if scam.auth_issues:
                print(f"  Auth:    {', '.join(scam.auth_issues)}")
            print(f"\n  🚩 Risk indicators ({len(scam.reasons)}):")
            for reason in scam.reasons[:8]:
                print(f"     • {reason}")
            if len(scam.reasons) > 8:
                print(f"     … and {len(scam.reasons) - 8} more")
            if scam.body_preview:
                print(f"\n  Preview: {scam.body_preview[:100]}…")
            print()

        print("=" * 80)
        print("\n⚠️  Do NOT click links or download attachments from these emails!")
        print("=" * 80)

    def save_report(self, scams: List[ScamEmail], sender_dict: Dict[str, ScamSender]):
        report_file = f"scam_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        try:
            with open(report_file, 'w', encoding='utf-8') as f:
                f.write("YAHOO MAIL SMART SCANNER REPORT\n")
                f.write("=" * 60 + "\n\n")
                f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Scam emails: {len(scams)}\n")
                f.write(f"Scam senders: {len(sender_dict)}\n\n")
                f.write("SCAM SENDERS:\n" + "-" * 60 + "\n")
                for s in sender_dict.values():
                    f.write(f"Email: {s.email}\n")
                    f.write(f"Display: {s.display_name}\n")
                    f.write(f"Count: {s.email_count}  |  Risk: {s.max_risk_score}\n")
                    if s.sample_subjects:
                        f.write(f"Subject: {s.sample_subjects[0]}\n")
                    f.write("-" * 60 + "\n")
            print(f"\n   ✅ Report saved: {report_file}")
        except Exception as e:
            print(f"\n   ⚠️  Could not save report: {e}")

    # ═══════════════════════════════════════════════════════════════════
    #  Main scan orchestrator
    # ═══════════════════════════════════════════════════════════════════

    def scan(self, folder: str = "INBOX", limit: int = 0) -> List[ScamEmail]:
        """Run two-pass scan on a folder."""
        suspicious = self.pass1_sender_filter(folder, limit)
        if self.interrupted or not suspicious:
            return []
        return self.pass2_deep_analysis(suspicious)

    def show_action_menu(self, sender_dict: Dict[str, ScamSender]) -> str:
        if not sender_dict:
            return "none"
        print("\n" + "=" * 80)
        print("                    🛠️  ACTIONS MENU")
        print("=" * 80)
        print("\n   What would you like to do?\n")
        print("   [1] Block senders (move to Spam + add to block list)")
        print("   [2] Delete all emails from these senders")
        print("   [3] Block AND Delete (recommended)")
        print("   [4] Enforce block_list.txt (delete from blocked senders)")
        print("   [5] Save report only")
        print("   [6] Exit without action")
        print()
        while True:
            choice = input("   Enter choice (1-6): ").strip()
            if choice in ('1', '2', '3', '4', '5', '6'):
                return choice
            print("   ❌ Invalid. Enter 1-6.")


# ════════════════════════════════════════════════════════════════════════
#  CLI entry point
# ════════════════════════════════════════════════════════════════════════

def get_credentials() -> Tuple[str, str]:
    email_addr = os.getenv('YAHOO_EMAIL', '').strip()
    password = os.getenv('YAHOO_PASSWORD', '').strip()
    return email_addr, password


def main():
    print("\n" + "=" * 70)
    print("     🚀 YAHOO MAIL SMART SCANNER  (All-In-One)")
    print("     Fast sender filter → Deep content analysis → Block & Delete")
    print("=" * 70)
    print("\n   💡 Press 'B' during scan to stop and show results\n")

    email_addr, password = get_credentials()

    if email_addr and password:
        print(f"   ✅ Loaded credentials for: {email_addr}")
        if '--prompt' in sys.argv:
            email_addr = password = ''
            print("   📝 Manual input mode (--prompt)\n")
    else:
        if DOTENV_AVAILABLE:
            print("   💡 Tip: set YAHOO_EMAIL & YAHOO_PASSWORD in a .env file\n")
        else:
            print("   💡 Tip: pip install python-dotenv, then create .env\n")

    if not email_addr:
        email_addr = input("Yahoo email: ").strip()
        if not email_addr:
            return
    if not password:
        print("\n📝 Get App Password: https://login.yahoo.com/account/security")
        password = getpass("App Password: ")

    # Scan limit
    default_limit = os.getenv('DEFAULT_SCAN_LIMIT', '0')  # 0 = all
    try:
        raw = input(f"\nEmails to scan (0 = all) [{default_limit}]: ").strip()
        limit = int(raw) if raw else int(default_limit)
    except ValueError:
        limit = 0

    # Quick mode: enforce-only
    if '--enforce' in sys.argv:
        scanner = SmartScanner(email_addr, password)
        if not scanner.connect():
            return
        try:
            scanner.enforce_block_list()
        finally:
            scanner.disconnect()
        return

    print()
    scanner = SmartScanner(email_addr, password)
    if not scanner.connect():
        return

    start_time = datetime.now()
    all_scams: List[ScamEmail] = []

    try:
        # Scan INBOX
        scams = scanner.scan("INBOX", limit)
        all_scams.extend(scams)

        # Scan Spam folder if not interrupted
        if not scanner.interrupted:
            spam_folder = scanner.get_spam_folder()
            if spam_folder:
                print("-" * 70)
                print(f"\n📁 Quick check: {spam_folder}…")
                spam_limit = min(limit, 100) if limit else 100
                spam_scams = scanner.scan(spam_folder, spam_limit)
                existing_uids = {s.uid for s in all_scams}
                for s in spam_scams:
                    if s.uid not in existing_uids:
                        all_scams.append(s)

        # Aggregate
        scam_senders = scanner.aggregate_scam_senders(all_scams)
        scanner.scam_senders = scam_senders

        # Display
        scanner.print_results(all_scams, partial=scanner.interrupted)
        scanner.print_scam_senders(scam_senders)

        # Action menu
        if scam_senders:
            choice = scanner.show_action_menu(scam_senders)

            if choice == '1':
                scanner.block_senders(scam_senders)
            elif choice == '2':
                if input("\n   ⚠️  DELETE emails permanently? (yes/no): ").strip().lower() == 'yes':
                    scanner.delete_scam_emails(scam_senders)
                else:
                    print("   ❌ Cancelled.")
            elif choice == '3':
                if input("\n   ⚠️  BLOCK + DELETE? (yes/no): ").strip().lower() == 'yes':
                    scanner.block_senders(scam_senders)
                    scanner.delete_scam_emails(scam_senders)
                else:
                    print("   ❌ Cancelled.")
            elif choice == '4':
                scanner.enforce_block_list()
            elif choice == '5':
                scanner.save_report(all_scams, scam_senders)
        else:
            # Even when no scams detected, offer enforce option
            print("\n   Would you like to enforce the block list anyway?")
            if input("   Run block_list.txt enforcer? (y/n): ").strip().lower() == 'y':
                scanner.enforce_block_list()

        elapsed = (datetime.now() - start_time).total_seconds()
        print(f"\n⏱️  Total time: {elapsed:.1f}s")
        print("✅ Done!\n")

    except KeyboardInterrupt:
        print("\n\n⚠️  Interrupted by user")
        if all_scams:
            scanner.print_results(all_scams, partial=True)
    finally:
        scanner.disconnect()


if __name__ == "__main__":
    main()
