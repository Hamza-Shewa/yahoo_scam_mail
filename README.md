# Yahoo Mail Scam Filter Scripts

A collection of Python scripts to detect scam and phishing emails in Yahoo Mail.

## Quick Comparison

| Script | Speed | Accuracy | Use Case |
|--------|-------|----------|----------|
| `yahoo_fast_sender_scan.py` | ⚡⚡⚡⚡⚡ (1000+ emails/min) | Good for sender-based scams | Quick daily checks |
| `yahoo_header_spoof_detector.py` | ⚡⚡⚡⚡ (500+ emails/min) | Excellent for spoofing | Detect impersonation |
| `yahoo_smart_scanner.py` | ⚡⚡⚡ (200-300 emails/min) | Best overall | **Recommended** |
| `yahoo_scam_filter.py` | ⚡ (50-100 emails/min) | Very thorough | Deep analysis needed |

## 🎮 New: Press 'B' to Break!

All scripts now support **pressing 'B' during scanning** to immediately stop and show results:

```
Progress: 150/500 emails... (Press 'B' to stop)
[B key pressed]

⛔ STOPPED by user (B pressed)
   Processed 150 of 500 emails

[Results shown for the 150 emails that were scanned]
```

This is useful when:
- You've seen enough and want results immediately
- You need to stop mid-scan for any reason
- You want to quickly check early results

---

## 1. `yahoo_fast_sender_scan.py` ⚡

**Ultra-fast sender-only analysis** - only downloads email headers, never the body.

### What it detects:
- Suspicious domains (temp mail, .tk/.ml TLDs)
- Generic support/admin@ addresses
- Display name spoofing (e.g., "Amazon" from gmail.com)
- Typosquatting (amaz0n.com, paypa1.com)
- Pattern-based suspicious addresses

### When to use:
- Quick daily/weekly scans
- Thousands of emails to check
- You want to identify bad senders to block

### Usage:
```bash
python yahoo_fast_sender_scan.py
```

### Credentials:
- Supports `.env` with `YAHOO_EMAIL` and `YAHOO_PASSWORD`
- Use `--prompt` to force manual entry

### Trusted senders:
- Update `trusted_senders.json` to allowlist senders/domains across scanners

**During scan:** Press `B` to stop immediately and show results

### Pros:
- 🚀 **Fastest option** - checks 1000+ emails per minute
- 📊 Great for building block lists
- 💾 Minimal bandwidth usage

### Cons:
- Doesn't analyze email content
- May miss sophisticated scams from legitimate-looking addresses

---

## 2. `yahoo_header_spoof_detector.py` 🔐

**Email authentication analysis** - checks SPF, DKIM, DMARC headers.

### What it detects:
- Email spoofing (fake "From" addresses)
- Failed SPF/DKIM/DMARC authentication
- Return-Path mismatches
- Impersonation of major brands

### When to use:
- You suspect impersonation attacks
- Want to verify if emails are really from who they claim
- Technical analysis of email authenticity

### Usage:
```bash
python yahoo_header_spoof_detector.py
```

**During scan:** Press `B` to stop immediately and show results

### Pros:
- 🔒 Detects technical spoofing
- 📋 Shows authentication results clearly
- 🎯 Great for identifying phishing

### Cons:
- Doesn't check email content
- Some legitimate services may have auth issues

---

## 3. `yahoo_smart_scanner.py` 🧠 (RECOMMENDED)

**Two-pass intelligent scanning** - combines speed with thoroughness.

### How it works:
1. **PASS 1**: Fast sender filter (checks ALL emails)
2. **PASS 2**: Deep analysis ONLY on suspicious senders

### What it detects:
- Everything from sender-only scan
- Scam keywords in content
- Suspicious URLs
- Urgency tactics
- Authentication failures
- Generic greetings

### When to use:
- **This is the recommended script for most users**
- Weekly/monthly thorough checks
- Best balance of speed and accuracy

### Usage:
```bash
python yahoo_smart_scanner.py
```

**During scan:** Press `B` to stop immediately and show results

### Pros:
- ⚡ **10-50x faster** than full body scan
- 🎯 Analyzes content only when needed
- 📊 Comprehensive detection
- 🏆 Best accuracy/speed ratio

### Cons:
- Slightly slower than sender-only (but worth it)

---

## 4. `yahoo_block_list_enforcer.py` 🛡️

**Block-list enforcement** - deletes messages from senders in `block_list.txt`.

### Usage:
```bash
python yahoo_block_list_enforcer.py
```

### Requirements:
- `.env` must include `YAHOO_EMAIL` and `YAHOO_PASSWORD`
- `python-dotenv` installed (`pip install python-dotenv`)

---

## 4. `yahoo_scam_filter.py` 🔍

**Full body analysis** - downloads and analyzes every email completely.

### What it detects:
- All scam indicators
- Full content analysis
- Most thorough detection

### When to use:
- Deep investigation needed
- Small number of emails (< 100)
- Maximum accuracy required

### Usage:
```bash
python yahoo_scam_filter.py
```

**During scan:** Press `B` to stop immediately and show results

### Pros:
- 🔍 Most thorough analysis
- Checks everything

### Cons:
- 🐌 Slowest option
- Heavy bandwidth usage
- Time-consuming for large mailboxes

---

## Setup Requirements

### Prerequisites
- Python 3.7 or higher
- Yahoo Mail account

### Yahoo App Password
**Important**: You cannot use your regular Yahoo password. You must generate an App Password:

1. Go to https://login.yahoo.com/account/security
2. Enable **2-Step Verification** (if not already enabled)
3. Click **"Generate app password"**
4. Select **"Other app"** and name it (e.g., "Scam Filter")
5. Copy the generated password
6. Use this password in the scripts (not your regular password)

---

## Performance Benchmarks

On a typical internet connection:

| Script | 100 emails | 500 emails | 1000 emails |
|--------|------------|------------|-------------|
| Fast Sender | ~5 sec | ~20 sec | ~40 sec |
| Header Spoof | ~10 sec | ~45 sec | ~90 sec |
| Smart Scanner | ~15 sec | ~60 sec | ~2 min |
| Full Filter | ~2 min | ~10 min | ~20 min |

---

## Recommended Workflow

### Daily/Quick Check:
```bash
python yahoo_fast_sender_scan.py
```
- Takes 30 seconds
- Identifies new suspicious senders
- Export block list if needed

### Weekly Thorough Check:
```bash
python yahoo_smart_scanner.py
```
- Takes 2-3 minutes for 500 emails
- Comprehensive detection
- Best overall results

### When You Suspect Spoofing:
```bash
python yahoo_header_spoof_detector.py
```
- Check authentication of suspicious emails
- Verify if emails are legitimate

---

## Understanding Results

### Risk Levels
- 🔴 **HIGH**: Strong scam indicators, avoid at all costs
- 🟡 **MEDIUM**: Some suspicious signs, proceed with caution
- 🟢 **LOW**: Minor issues, but worth reviewing

### Common Indicators
| Indicator | Meaning |
|-----------|---------|
| SPF/DKIM/DMARC FAIL | Email authentication failed - likely spoofed |
| Display name spoofing | Claims to be a brand but domain doesn't match |
| Typosquatting | Domain looks like a major brand but is fake |
| Generic support@ | Common phishing pattern |
| Urgency keywords | Scammers create false urgency |
| IP-based URLs | Links to IP addresses instead of domains |

---

## Safety Tips

⚠️ **Never click links or download attachments from suspicious emails!**

If an email claims to be from a service you use:
1. Don't click any links in the email
2. Open your browser and go to the website directly
3. Log in and check for any notifications there
4. Contact the company through their official support channels

---

## Troubleshooting

### "Login failed" error
- Make sure you're using an **App Password**, not your regular password
- Check if 2-Step Verification is enabled
- Verify your email address is correct

### "Could not select folder" error
- Check if the folder name is correct (case-sensitive)
- Common folders: INBOX, Spam, Drafts, Sent

### Script is too slow
- Use `yahoo_fast_sender_scan.py` for quick checks
- Reduce the number of emails to scan
- Check your internet connection

### False positives
- No scanner is perfect
- Review flagged emails manually
- Major brands sometimes have authentication issues

---

## License

These scripts are provided as-is for personal use to help identify scam emails.

---

## Files Summary

```
yahoo_scam_mail/
├── yahoo_fast_sender_scan.py      # ⚡ Fastest - sender only
├── yahoo_header_spoof_detector.py # 🔐 Authentication check
├── yahoo_smart_scanner.py         # 🧠 RECOMMENDED - two-pass
├── yahoo_scam_filter.py           # 🔍 Full deep analysis
├── requirements.txt               # Dependencies (standard library only)
└── README.md                      # This file
```

**Recommendation**: Start with `yahoo_smart_scanner.py` for the best experience!
