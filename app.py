import os
import sqlite3
import re
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Database Setup
DATABASE = 'miniwaf_secure.db'

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as db:
        # User Table
        db.execute('''CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            first_name TEXT NOT NULL,
            last_name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )''')
        # Login Attempt Table (for Brute Force Protection)
        db.execute('''CREATE TABLE IF NOT EXISTS login_attempts (
            username TEXT,
            ip_address TEXT,
            attempt_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            is_successful BOOLEAN
        )''')
        # Security Logs (WAF)
        db.execute('''CREATE TABLE IF NOT EXISTS security_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            attack_type TEXT,
            payload TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )''')
        db.commit()

# --- Mini WAF Logic ---
SQLI_PATTERNS = [
    r"(?i)\bOR\b\s+['\"]?\w+['\"]?\s*=\s*['\"]?\w+['\"]?",
    r"(?i)\s+UNION\s+SELECT",
    r"(?i)\s+DROP\s+TABLE",
    r"(?i)--",
    r"(?i)SELECT\s+.*\s+FROM",
]

XSS_PATTERNS = [
    r"(?i)<script.*?>",
    r"(?i)onerror=",
    r"(?i)onload=",
    r"(?i)alert\(",
    r"(?i)javascript:",
]

def check_waf(payload, user_id=None):
    """
    Checks the input payload against SQLi and XSS patterns.
    Logs the attack if matched.
    """
    if not payload:
        return True, ""

    payload_str = str(payload) if payload else ""
    
    # Check SQLi
    for pattern in SQLI_PATTERNS:
        if re.search(pattern, payload_str):
            log_attack(user_id, "SQL Injection", payload_str)
            return False, "SQL Injection attempt blocked by MiniWAF!"

    # Check XSS
    for pattern in XSS_PATTERNS:
        if re.search(pattern, payload_str):
            log_attack(user_id, "XSS Attack", payload_str)
            return False, "Cross-Site Scripting (XSS) attempt blocked by MiniWAF!"

    return True, ""

def log_attack(user_id, attack_type, payload):
    with get_db() as db:
        db.execute("INSERT INTO security_logs (user_id, attack_type, payload) VALUES (?, ?, ?)",
                   (user_id, attack_type, payload))
        db.commit()

# --- Security Helpers ---
def check_lockout_remaining(username, ip):
    """
    Checks if locked and returns REMAINING SECONDS if locked, otherwise 0.
    """
    with get_db() as db:
        # 1. Check for Credential Stuffing (5+ unique usernames from same IP in last 30s)
        stuffing_query = '''
            SELECT COUNT(DISTINCT username) as count, MAX(attempt_time) as last_time
            FROM login_attempts 
            WHERE ip_address = ? AND is_successful = 0
            AND attempt_time > datetime('now', '-30 seconds')
        '''
        row = db.execute(stuffing_query, (ip,)).fetchone()
        
        if row and row['count'] >= 5:
            last_attempt = datetime.strptime(row['last_time'], '%Y-%m-%d %H:%M:%S')
            wait_time = (last_attempt + timedelta(minutes=5)) - datetime.utcnow()
            if wait_time.total_seconds() > 0:
                msg = "🚨 Credential Stuffing Attack Detected\nIP temporarily blocked.\nLogin disabled for 5 minutes."
                return int(wait_time.total_seconds()), msg

        # 2. Check for Brute Force
        # If no username provided (GET request), check if this IP has ANY active lockout
        lookup_usernames = [username] if username else []
        if not username:
            # Find all usernames tried from this IP that might be locked
            recent_ips = db.execute("SELECT DISTINCT username FROM login_attempts WHERE ip_address = ? AND is_successful = 0 AND attempt_time > datetime('now', '-3 minutes')", (ip,)).fetchall()
            lookup_usernames = [r['username'] for r in recent_ips]

        for u in lookup_usernames:
            brute_query = '''
                SELECT attempt_time 
                FROM login_attempts 
                WHERE username = ? AND is_successful = 0 
                AND attempt_time > datetime('now', '-3 minutes')
                ORDER BY attempt_time DESC
                LIMIT 1 OFFSET 2
            '''
            third_failure = db.execute(brute_query, (u,)).fetchone()
            
            if third_failure:
                latest = db.execute('SELECT attempt_time FROM login_attempts WHERE username=? ORDER BY attempt_time DESC LIMIT 1', (u,)).fetchone()
                last_time = datetime.strptime(latest['attempt_time'], '%Y-%m-%d %H:%M:%S')
                wait_time = (last_time + timedelta(minutes=3)) - datetime.utcnow()
                if wait_time.total_seconds() > 0:
                    msg = f"🚨 Brute Force Attack Detected\nToo many failed login attempts for account '{u}'.\nLogin disabled for 3 minutes."
                    return int(wait_time.total_seconds()), msg
                
    return 0, ""

def record_attempt(username, ip, success):
    with get_db() as db:
        db.execute("INSERT INTO login_attempts (username, ip_address, is_successful) VALUES (?, ?, ?)",
                   (username, ip, 1 if success else 0))
        db.commit()

# --- Routes ---

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        first_name = request.form.get('first_name', '')
        last_name = request.form.get('last_name', '')
        email = request.form.get('email', '')
        username = request.form.get('username', '')
        password = request.form.get('password', '')

        # 1. WAF Check ALL Inputs
        for field in [first_name, last_name, email, username, password]:
            is_safe, msg = check_waf(field)
            if not is_safe and msg:
                flash(msg, 'error')
                return render_template('register.html')

        # 2. Input Validation
        if first_name and last_name and (not re.match(r'^[A-Za-z]+$', first_name) or not re.match(r'^[A-Za-z]+$', last_name)):
            flash("Names must contain only alphabets.", 'error')
            return render_template('register.html')
        
        if username and not re.match(r'^[a-zA-Z0-9_]{6,15}$', username):
            flash("Username must be 6-15 chars (alphanumeric and underscore).", 'error')
            return render_template('register.html')

        # Password Strength Check
        if password and not (len(password) >= 8 and re.search(r'[A-Z]', password) and re.search(r'[a-z]', password) and 
                re.search(r'[0-9]', password) and re.search(r'[!@#$%^&*]', password)):
            flash("Password must be 8+ chars and include upper, lower, number, and special character.", 'error')
            return render_template('register.html')

        # 3. Store User
        if password and username and email and first_name and last_name:
            hashed_pw = generate_password_hash(password)
            try:
                with get_db() as db:
                    db.execute("INSERT INTO users (first_name, last_name, email, username, password) VALUES (?, ?, ?, ?, ?)",
                               (first_name, last_name, email, username, hashed_pw))
                    db.commit()
                flash("Secure Account Created! Please login.", 'success')
                return redirect(url_for('login'))
            except sqlite3.IntegrityError:
                flash("Username or Email already exists.", 'error')
        else:
            flash("All fields are required.", 'error')
            
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    username = request.form.get('username', '') if request.method == 'POST' else ""
    ip = request.remote_addr or '0.0.0.0'

    # 🛡️ Global Security Check (Both GET and POST)
    lockout_sec, block_reason = check_lockout_remaining(username, ip)
    
    if request.method == 'POST':
        password = request.form.get('password', '')

        # 0. UI Override: If they are still locked but somehow sent a POST
        if lockout_sec > 0 and block_reason:
            flash(block_reason, 'error')
            return render_template('login.html', lockout_sec=lockout_sec, block_reason=block_reason)

        # 1. Basic Length & WAF Check
        if username and not (6 <= len(username) <= 15):
            flash("Unauthorized Username Format: Must be 6-15 characters.", "error")
            return render_template('login.html')

        for field in [username, password]:
            is_safe, msg = check_waf(field)
            if not is_safe and msg:
                flash(msg, 'error')
                return render_template('login.html')

        # 2. Authenticate
        with get_db() as db:
            user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
            if user and check_password_hash(user['password'], password):
                session['user_id'] = user['id']
                session['first_name'] = user['first_name']
                record_attempt(username, ip, True)
                return redirect(url_for('dashboard'))
            else:
                record_attempt(username, ip, False)
                
                # Check lockout again right after failure to see if we JUST triggered it
                lockout_sec, block_reason = check_lockout_remaining(username, ip)
                if lockout_sec > 0 and block_reason:
                    flash(block_reason, 'error')
                    
                    if "Stuffing" in block_reason:
                        with get_db() as db_log:
                            db_log.execute("INSERT INTO security_logs (attack_type, payload) VALUES (?, ?)", 
                                       ("Credential Stuffing", f"IP {ip} blocked for multi-user probe"))
                            db_log.commit()
                            
                    return render_template('login.html', lockout_sec=lockout_sec, block_reason=block_reason)
                
                flash("Invalid credentials.", 'error')

    # For Initial GET or failed login without trigger
    return render_template('login.html', lockout_sec=lockout_sec, block_reason=block_reason)

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    with get_db() as db:
        user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        username = user['username']

        # Get user-specific data
        history = db.execute("SELECT * FROM login_attempts WHERE username = ? ORDER BY attempt_time DESC LIMIT 5", (username,)).fetchall()
        alerts = db.execute("SELECT * FROM security_logs WHERE user_id = ? ORDER BY timestamp DESC LIMIT 3", (user_id,)).fetchall()
        failed_count = db.execute("SELECT COUNT(*) as c FROM login_attempts WHERE username = ? AND is_successful = 0", (username,)).fetchone()['c']
        last_login = db.execute("SELECT attempt_time FROM login_attempts WHERE username = ? AND is_successful = 1 ORDER BY attempt_time DESC LIMIT 1 OFFSET 1", (username,)).fetchone()
        last_login_time = last_login['attempt_time'] if last_login else "Today (New Session)"
        lockout_sec, _ = check_lockout_remaining(username, request.remote_addr)
        is_locked = lockout_sec > 0

    return render_template('dashboard.html', 
                           logged_in=True,
                           user=user, 
                           history=history, 
                           alerts=alerts, 
                           failed_count=failed_count, 
                           last_login=last_login_time,
                           is_locked=is_locked)

@app.route('/change-password', methods=['POST'])
def change_password():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    new_password = request.form.get('new_password', '')
    
    # WAF Check
    is_safe, msg = check_waf(new_password, session['user_id'])
    if not is_safe and msg:
        flash(msg, 'error')
        return redirect(url_for('dashboard'))

    # Validation
    if new_password and not (len(new_password) >= 8 and re.search(r'[A-Z]', new_password) and re.search(r'[a-z]', new_password) and 
            re.search(r'[0-9]', new_password) and re.search(r'[!@#$%^&*]', new_password)):
        flash("Password does not meet complexity requirements.", 'error')
        return redirect(url_for('dashboard'))
    
    if new_password:
        hashed_pw = generate_password_hash(new_password)
    else:
        flash("Password cannot be empty.", 'error')
        return redirect(url_for('dashboard'))
    with get_db() as db:
        db.execute("UPDATE users SET password = ? WHERE id = ?", (hashed_pw, session['user_id']))
        db.commit()
    
    flash("Password updated securely!", 'success')
    return redirect(url_for('dashboard'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
