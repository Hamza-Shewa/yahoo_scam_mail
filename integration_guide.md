# Yahoo Mail Connectivity Guide (for AI Agent + Dart/Flutter)

## Purpose
This guide summarizes the Yahoo Mail connection details used in this project and expands them into a complete integration reference for a Dart/Flutter client. It covers hosts, ports, protocols, authentication options, and a practical checklist.

## What This Project Uses Today (Reference)
- Protocol: IMAP over SSL/TLS
- Host: imap.mail.yahoo.com
- Port: 993
- Auth: username + app password

The current scanner connects via IMAP, fetches headers and full messages, and relies on standard RFC 822 message parsing.

## Connection Matrix (Hosts + Ports)

### IMAP (Read/Manage Mailboxes)
- Host: imap.mail.yahoo.com
- Port: 993
- Transport: SSL/TLS (implicit TLS)
- Typical use: list mailboxes, search, fetch headers, fetch message bodies

### SMTP (Send Mail)
- Host: smtp.mail.yahoo.com
- Port: 465
- Transport: SSL/TLS (implicit TLS)

- Host: smtp.mail.yahoo.com
- Port: 587
- Transport: STARTTLS (explicit TLS upgrade)

### OAuth2 Endpoints (If Using OAuth Instead of App Passwords)
- Authorization URL: https://api.login.yahoo.com/oauth2/request_auth
- Token URL: https://api.login.yahoo.com/oauth2/get_token

Note: Yahoo OAuth scopes can vary. Common mail scopes include `mail-r`, `mail-w`, and `mail-a`, but confirm the latest values in Yahoo developer docs for production.

## Authentication Options

### Option A: App Passwords (Simplest)
- Works with IMAP and SMTP using basic username/password auth.
- Requires the Yahoo account to have App Passwords enabled.
- Best for: internal tools, power users, or quick prototypes.

### Option B: OAuth2 (Recommended for production apps)
- You must register your app in Yahoo Developer to obtain a client ID/secret.
- Use OAuth2 to obtain an access token (and refresh token).
- Use XOAUTH2 with IMAP/SMTP.

XOAUTH2 string format for IMAP/SMTP:
```
user=<email>\x01auth=Bearer <access_token>\x01\x01
```
In Dart, build this string, Base64-encode it, and pass it into the IMAP/SMTP AUTH command.

## TLS / Security Notes
- Always use TLS. Do not allow plaintext IMAP/SMTP.
- Prefer app passwords over storing full account passwords.
- Store tokens and credentials in secure storage:
  - Android: EncryptedSharedPreferences or Android Keystore
  - iOS: Keychain
  - Web: use a backend and store tokens server-side
- Consider a backend proxy for OAuth if you cannot safely store a client secret on-device.

## Dart/Flutter Integration Outline

### IMAP Flow (Read/Scan)
1. Create secure TCP connection to imap.mail.yahoo.com:993 (TLS).
2. Authenticate using either:
   - LOGIN (email + app password), or
   - AUTHENTICATE XOAUTH2 (OAuth access token)
3. SELECT mailbox (INBOX, Spam, etc.).
4. SEARCH for UIDs.
5. FETCH headers or full messages.
6. Parse RFC 822 message bytes.

### SMTP Flow (Send)
1. Connect to smtp.mail.yahoo.com with TLS:
   - Port 465 (implicit TLS), or
   - Port 587 (STARTTLS)
2. AUTH with LOGIN or XOAUTH2.
3. MAIL FROM / RCPT TO / DATA.

### OAuth Flow (High-level)
1. Open auth URL in browser/webview with your client ID and redirect URI.
2. Receive authorization code at redirect URI.
3. Exchange code for access token at the token URL.
4. Use access token in XOAUTH2 for IMAP/SMTP.
5. Refresh token when access token expires.

## Example Connection Settings (for an AI Agent)
This is the minimum config your AI agent needs to implement Yahoo connectivity:

```
YAHOO_IMAP_HOST=imap.mail.yahoo.com
YAHOO_IMAP_PORT=993
YAHOO_IMAP_TLS=implicit

YAHOO_SMTP_HOST=smtp.mail.yahoo.com
YAHOO_SMTP_PORT_SSL=465
YAHOO_SMTP_PORT_STARTTLS=587
YAHOO_SMTP_TLS=implicit|starttls

YAHOO_OAUTH_AUTH_URL=https://api.login.yahoo.com/oauth2/request_auth
YAHOO_OAUTH_TOKEN_URL=https://api.login.yahoo.com/oauth2/get_token
```

## Basic Dart Pseudocode (IMAP + XOAUTH2)
```dart
final socket = await SecureSocket.connect(
  'imap.mail.yahoo.com',
  993,
  timeout: const Duration(seconds: 15),
);

// Build XOAUTH2 string
final authString = 'user=$email\x01auth=Bearer $accessToken\x01\x01';
final authB64 = base64Encode(utf8.encode(authString));

// Send IMAP AUTHENTICATE XOAUTH2 command
socket.write('a1 AUTHENTICATE XOAUTH2 $authB64\r\n');
```

## Connectivity Test Checklist
- DNS resolves for imap.mail.yahoo.com and smtp.mail.yahoo.com.
- TLS handshake succeeds on ports 993, 465, 587.
- IMAP login succeeds (app password or OAuth).
- IMAP SELECT INBOX works.
- SMTP AUTH succeeds (app password or OAuth).
- SMTP send works to a test mailbox.

## Notes for Web Clients
- Most browsers cannot open raw TCP sockets to IMAP/SMTP.
- For Flutter Web, use a backend service to handle IMAP/SMTP and expose a REST API to the client.

## Appendix: Risky Pitfalls
- Yahoo accounts may require App Passwords even if normal login works.
- Auth failures can be caused by missing SPF/DKIM alignment for SMTP send.
- If IMAP returns only 10K UIDs, use chunked UID ranges.

---
If you want, I can add concrete Dart packages, a full OAuth sample, or a Flutter Web proxy example.
