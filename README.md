# MiniWAF – Sentinel Web Application Firewall

A Flask-based web security demo that simulates a Web Application Firewall (WAF). It detects and blocks common web attacks and displays them on a security dashboard.

---

## Features

### Attack Detection & Blocking
- **SQL Injection** – Detects malicious SQL patterns like `OR 1=1`, `UNION SELECT`, `DROP TABLE`
- **XSS (Cross-Site Scripting)** – Blocks `<script>` tags, `onerror`, `alert()`, and `javascript:` payloads
- **Brute Force Protection** – Locks an account after 3 failed login attempts within 3 minutes
- **Credential Stuffing Detection** – Blocks an IP that tries 5+ different usernames within 30 seconds

### Authentication
- Secure registration with password hashing (PBKDF2)
- Password strength requirements: 8+ characters, uppercase, lowercase, number, special character
- Input validation on all fields (name, username, email, password)

### Security Dashboard
- View recent login activity (success/failed attempts)
- View blocked attack logs (type, payload, timestamp)
- Total failed login count
- Account lock status
- Change password

---

## Tech Stack

- **Backend** – Python, Flask
- **Database** – SQLite
- **Frontend** – HTML, CSS, Jinja2, JavaScript

---

## Setup & Run

1. Install dependencies:
   ```
   pip install flask werkzeug
   ```

2. Run the app:
   ```
   python app.py
   ```

3. Open in browser:
   ```
   http://127.0.0.1:5000
   ```

---

## Project Purpose

This is an academic mini project built to demonstrate how basic WAF techniques can detect and prevent common web application attacks.
