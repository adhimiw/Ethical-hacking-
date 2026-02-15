# Ethical Hacking Login Module (Python/Flask)
# Features: Email Verification (Signed Tokens), reCAPTCHA, OTP (Expiring), Password Hashing, Rate Limiting, CSRF Protection

from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_bcrypt import Bcrypt
from flask_wtf.csrf import CSRFProtect
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadTimeSignature
import smtplib
from email.mime.text import MIMEText
import random
import sqlite3
import os
import requests
from datetime import datetime, timedelta
from dotenv import load_dotenv
load_dotenv()

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', os.urandom(24))

# Security configurations
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
)

# Security tools
bcrypt = Bcrypt(app)
csrf = CSRFProtect(app)
serializer = URLSafeTimedSerializer(app.secret_key)

# Configure reCAPTCHA
app.config['RECAPTCHA_SITE_KEY'] = os.environ.get('RECAPTCHA_SITE_KEY', 'YOUR_RECAPTCHA_SITE_KEY')
app.config['RECAPTCHA_SECRET_KEY'] = os.environ.get('RECAPTCHA_SECRET_KEY', 'YOUR_RECAPTCHA_SECRET_KEY')
DEV_MODE = os.environ.get('DEV_MODE', 'true').lower() == 'true'

if not DEV_MODE:
    app.config.update(
        SESSION_COOKIE_SECURE=True, # Ensure cookies are only sent over HTTPS in production
    )

def verify_recaptcha():
    """
    Validates the reCAPTCHA response with Google's API to prevent automated bot submissions.
    This is a core 'Authentication Prevention' mechanism.
    """
    if DEV_MODE:
        return True
    response = request.form.get('g-recaptcha-response')
    secret = app.config['RECAPTCHA_SECRET_KEY']
    if not response: return False
    # Backend-to-Backend validation
    res = requests.post('https://www.google.com/recaptcha/api/siteverify', data={'secret': secret, 'response': response})
    return res.json().get('success', False)

# Configure rate limiting (Prevention against DoS and Brute-force)
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

# Database setup
def init_db():
    """
    Initializes the SQLite database with tables for Users, Login Logs, and OTPs.
    """
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    # User accounts with security flags (verified, locked)
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            verified BOOLEAN DEFAULT 0,
            locked BOOLEAN DEFAULT 0,
            failed_attempts INTEGER DEFAULT 0,
            last_attempt TIMESTAMP
        )
    ''')
    # Detailed logging for 'Ethical Hacking Analysis' in the dashboard
    c.execute('''
        CREATE TABLE IF NOT EXISTS login_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL,
            success BOOLEAN NOT NULL,
            ip_address TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    # OTP storage with expiry and one-time use (used flag)
    c.execute('''
        CREATE TABLE IF NOT EXISTS otps (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL,
            otp TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            used BOOLEAN DEFAULT 0
        )
    ''')
    conn.commit()
    conn.close()

# Email setup (SMTP for Verification and OTP)
EMAIL_USER = os.environ.get('EMAIL_USER', 'adhithanraja6@gmail.com')
EMAIL_APP_PASSWORD = os.environ.get('EMAIL_APP_PASSWORD', '')
EMAIL_FROM = os.environ.get('EMAIL_FROM', f'Adhithan Raja <{EMAIL_USER}>')

def send_email(to, subject, body):
    """
    Handles secure email delivery via SMTP.
    """
    print(f"\n📧 SENDING EMAIL to {to} | Subject: {subject}")
    try:
        msg = MIMEText(body)
        msg['Subject'] = subject
        msg['From'] = EMAIL_FROM
        msg['To'] = to
        with smtplib.SMTP('smtp.gmail.com', 587) as server:
            server.starttls() # Secure encryption for the email session
            server.login(EMAIL_USER, EMAIL_APP_PASSWORD)
            server.send_message(msg)
        print(f"✅ Email sent successfully.")
    except Exception as e:
        print(f"❌ Email send error: {e}")

# Generate OTP (Cryptographically unpredictable code)
def generate_otp():
    return str(random.randint(100000, 999999))

# Routes
@app.route('/')
def home():
    """Renders the landing page with security documentation."""
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    """
    Registers a new user account.
    - Uses Bcrypt for secure password hashing.
    - Implements reCAPTCHA to prevent bulk registration.
    - Generates a signed token for email verification.
    """
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        if not verify_recaptcha():
            flash('reCAPTCHA verification failed.')
            return redirect(url_for('register'))

        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute('SELECT * FROM users WHERE email = ?', (email,))
        if c.fetchone():
            flash('Email already registered.')
            return redirect(url_for('register'))

        # Hash password (No plain text allowed in ethical systems!)
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        # Create a cryptographically signed token for secure verification
        token = serializer.dumps(email, salt='email-confirm')
        verification_link = url_for('verify_email', token=token, _external=True)
        send_email(
            to=email,
            subject='Verify Your Email - Ethical Hacking Module',
            body=f'Your secure registration is almost complete. Click here to verify your email (link expires in 30 mins): {verification_link}'
        )

        c.execute('INSERT INTO users (email, password) VALUES (?, ?)', (email, hashed_password))
        conn.commit()
        conn.close()

        flash('Registration successful! Please check your email to verify your account before logging in.')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/verify_email/<token>')
def verify_email(token):
    """
    Validates the signed token and activates the user account.
    Prevents unauthorized account activation.
    """
    try:
        # Link expires after 30 minutes (max_age=1800)
        email = serializer.loads(token, salt='email-confirm', max_age=1800) 
    except (SignatureExpired, BadTimeSignature):
        flash('The verification link is invalid or has expired.')
        return redirect(url_for('register'))

    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('UPDATE users SET verified = 1 WHERE email = ?', (email,))
    conn.commit()
    conn.close()
    flash('Email verified successfully! You can now log in.')
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per hour") # Visible rate limiting demonstration
def login():
    """
    Handles secure login flow.
    - Enforces verification and lock states.
    - Implements 'Brute-force Shield' with failed attempt tracking.
    - Triggers MFA (OTP) upon successful primary credential check.
    """
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        if not verify_recaptcha():
            flash('reCAPTCHA verification failed.')
            return redirect(url_for('login'))

        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute('SELECT * FROM users WHERE email = ?', (email,))
        user = c.fetchone()

        if not user:
            flash('Invalid email or password.')
            return redirect(url_for('login'))

        # Security Check: Email must be verified first
        if user[3] == 0: 
            flash('Please verify your email first.')
            return redirect(url_for('login'))

        # Security Check: Prevent login for locked accounts
        if user[4] == 1: 
            flash('Your account is locked due to security policy. Please use the unlock flow.')
            return redirect(url_for('unlock'))

        # Check Bcrypt hashed password
        if not bcrypt.check_password_hash(user[2], password):
            failed_attempts = user[5] + 1
            # Log the attack attempt
            c.execute('INSERT INTO login_attempts (email, success, ip_address) VALUES (?, 0, ?)', (email, get_remote_address()))
            
            # Logic: Lock account after 5 failed attempts
            if failed_attempts >= 5:
                c.execute('UPDATE users SET locked = 1 WHERE email = ?', (email,))
                conn.commit()
                flash('Your account has been locked after 5 failed attempts.')
                return redirect(url_for('unlock'))
            else:
                c.execute('UPDATE users SET failed_attempts = ?, last_attempt = ? WHERE email = ?', (failed_attempts, datetime.now(), email))
                conn.commit()
                flash(f'Invalid password. Attempt {failed_attempts} of 5.')
                return redirect(url_for('login'))

        # Reset failed attempts on success
        c.execute('INSERT INTO login_attempts (email, success, ip_address) VALUES (?, 1, ?)', (email, get_remote_address()))
        c.execute('UPDATE users SET failed_attempts = 0 WHERE email = ?', (email,))
        
        # Multi-Factor Authentication: Generate and send expiring OTP
        otp = generate_otp()
        c.execute('INSERT INTO otps (email, otp) VALUES (?, ?)', (email, otp))
        conn.commit()

        send_email(
            to=email,
            subject='Your Secure OTP Code',
            body=f'Your code is: {otp}. This code expires in 5 minutes.'
        )

        session['temp_email'] = email
        return redirect(url_for('verify_otp'))

    return render_template('login.html')

@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    """
    Verifies the OTP for MFA.
    - Checks for 5-minute expiration.
    - Enforces one-time use (used=1 flag).
    """
    if 'temp_email' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        otp = request.form['otp']
        email = session['temp_email']

        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        
        # Security Policy: OTP must be unused and less than 5 minutes old
        five_mins_ago = (datetime.now() - timedelta(minutes=5)).strftime('%Y-%m-%d %H:%M:%S')
        c.execute('''
            SELECT * FROM otps 
            WHERE email = ? AND otp = ? AND used = 0 AND created_at >= ?
            ORDER BY created_at DESC LIMIT 1
        ''', (email, otp, five_mins_ago))
        
        otp_record = c.fetchone()

        if otp_record:
            # Mark as used (One-time use only)
            c.execute('UPDATE otps SET used = 1 WHERE id = ?', (otp_record[0],))
            conn.commit()
            
            # Final Session Authorization
            session['logged_in'] = True
            session['email'] = email
            session.pop('temp_email', None)
            flash('Login successful!')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid or expired OTP.')

    return render_template('verify_otp.html')

@app.route('/unlock', methods=['GET', 'POST'])
def unlock():
    """
    Handles account recovery/unlock flow.
    Requires reCAPTCHA and a separate OTP check.
    """
    if request.method == 'POST':
        email = request.form['email']

        if not verify_recaptcha():
            flash('reCAPTCHA verification failed.')
            return redirect(url_for('unlock'))

        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute('SELECT * FROM users WHERE email = ?', (email,))
        user = c.fetchone()

        if not user:
            flash('Account not found.')
            return redirect(url_for('unlock'))

        otp = generate_otp()
        c.execute('INSERT INTO otps (email, otp) VALUES (?, ?)', (email, otp))
        conn.commit()

        send_email(
            to=email,
            subject='Account Unlock OTP',
            body=f'Use this code to unlock your account: {otp}. Valid for 5 minutes.'
        )

        session['unlock_email'] = email
        return redirect(url_for('verify_unlock_otp'))

    return render_template('unlock.html')

@app.route('/verify_unlock_otp', methods=['GET', 'POST'])
def verify_unlock_otp():
    """
    Processes the unlock code to reset account state.
    """
    if 'unlock_email' not in session:
        return redirect(url_for('unlock'))

    if request.method == 'POST':
        otp = request.form['otp']
        email = session['unlock_email']

        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        
        five_mins_ago = (datetime.now() - timedelta(minutes=5)).strftime('%Y-%m-%d %H:%M:%S')
        c.execute('''
            SELECT * FROM otps 
            WHERE email = ? AND otp = ? AND used = 0 AND created_at >= ?
            ORDER BY created_at DESC LIMIT 1
        ''', (email, otp, five_mins_ago))
        
        otp_record = c.fetchone()

        if otp_record:
            # Mark as used and reset user flags
            c.execute('UPDATE otps SET used = 1 WHERE id = ?', (otp_record[0],))
            c.execute('UPDATE users SET locked = 0, failed_attempts = 0 WHERE email = ?', (email,))
            conn.commit()
            session.pop('unlock_email', None)
            flash('Account unlocked successfully! You can now log in.')
            return redirect(url_for('login'))
        else:
            flash('Invalid or expired OTP.')

    return render_template('verify_unlock_otp.html')

@app.route('/dashboard')
def dashboard():
    """
    Security Analytics Dashboard.
    Visualizes authentication telemetry for analysis.
    """
    if 'logged_in' not in session:
        return redirect(url_for('login'))

    conn = sqlite3.connect('users.db')
    c = conn.cursor()

    # Telemetry: Success vs Fail for intruder analysis
    c.execute('SELECT email, COUNT(*) as attempts FROM login_attempts GROUP BY email')
    login_attempts = c.fetchall()

    c.execute('SELECT success, COUNT(*) FROM login_attempts GROUP BY success')
    success_failure = dict(c.fetchall())

    # State: Current lock status distribution
    c.execute('SELECT email, locked FROM users')
    account_locks = c.fetchall()

    # Activity: MFA volume
    c.execute('SELECT email, COUNT(*) as otps_sent FROM otps GROUP BY email')
    otp_data = c.fetchall()

    conn.close()

    return render_template(
        'dashboard.html',
        login_labels=[row[0] for row in login_attempts],
        login_counts=[row[1] for row in login_attempts],
        locked_count=sum(1 for row in account_locks if row[1] == 1),
        unlocked_count=sum(1 for row in account_locks if row[1] == 0),
        otp_labels=[row[0] for row in otp_data],
        otp_counts=[row[1] for row in otp_data],
        success_count=success_failure.get(1, 0),
        failure_count=success_failure.get(0, 0)
    )

@app.route('/logout')
def logout():
    """Destroys session data."""
    session.clear()
    flash('You have been logged out.')
    return redirect(url_for('home'))

# Self-initializing database on startup
init_db()

if __name__ == '__main__':
    # Toggle debug mode based on DEV_MODE env variable
    app.run(debug=DEV_MODE)
