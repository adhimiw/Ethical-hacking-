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

# Security tools
bcrypt = Bcrypt(app)
csrf = CSRFProtect(app)
serializer = URLSafeTimedSerializer(app.secret_key)

# Configure reCAPTCHA
app.config['RECAPTCHA_SITE_KEY'] = os.environ.get('RECAPTCHA_SITE_KEY', 'YOUR_RECAPTCHA_SITE_KEY')
app.config['RECAPTCHA_SECRET_KEY'] = os.environ.get('RECAPTCHA_SECRET_KEY', 'YOUR_RECAPTCHA_SECRET_KEY')
DEV_MODE = os.environ.get('DEV_MODE', 'true').lower() == 'true'

def verify_recaptcha():
    if DEV_MODE:
        return True
    response = request.form.get('g-recaptcha-response')
    secret = app.config['RECAPTCHA_SECRET_KEY']
    if not response: return False
    res = requests.post('https://www.google.com/recaptcha/api/siteverify', data={'secret': secret, 'response': response})
    return res.json().get('success', False)

# Configure rate limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

# Database setup
def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
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
    c.execute('''
        CREATE TABLE IF NOT EXISTS login_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL,
            success BOOLEAN NOT NULL,
            ip_address TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
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

# Email setup
EMAIL_USER = os.environ.get('EMAIL_USER', 'adhithanraja6@gmail.com')
EMAIL_APP_PASSWORD = os.environ.get('EMAIL_APP_PASSWORD', '')
EMAIL_FROM = os.environ.get('EMAIL_FROM', f'Adhithan Raja <{EMAIL_USER}>')

def send_email(to, subject, body):
    print(f"\n📧 SENDING EMAIL to {to} | Subject: {subject}")
    try:
        msg = MIMEText(body)
        msg['Subject'] = subject
        msg['From'] = EMAIL_FROM
        msg['To'] = to
        with smtplib.SMTP('smtp.gmail.com', 587) as server:
            server.starttls()
            server.login(EMAIL_USER, EMAIL_APP_PASSWORD)
            server.send_message(msg)
        print(f"✅ Email sent successfully.")
    except Exception as e:
        print(f"❌ Email send error: {e}")

# Generate OTP
def generate_otp():
    return str(random.randint(100000, 999999))

# Routes
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
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

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
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
    try:
        email = serializer.loads(token, salt='email-confirm', max_age=1800) # 30 mins
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
@limiter.limit("10 per hour")
def login():
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

        if user[3] == 0:  # Not verified
            flash('Please verify your email first.')
            return redirect(url_for('login'))

        if user[4] == 1:  # Locked
            flash('Your account is locked due to security policy. Please use the unlock flow.')
            return redirect(url_for('unlock'))

        if not bcrypt.check_password_hash(user[2], password):
            failed_attempts = user[5] + 1
            c.execute('INSERT INTO login_attempts (email, success, ip_address) VALUES (?, 0, ?)', (email, get_remote_address()))
            
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

        c.execute('INSERT INTO login_attempts (email, success, ip_address) VALUES (?, 1, ?)', (email, get_remote_address()))
        c.execute('UPDATE users SET failed_attempts = 0 WHERE email = ?', (email,))
        
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
    if 'temp_email' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        otp = request.form['otp']
        email = session['temp_email']

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
            c.execute('UPDATE otps SET used = 1 WHERE id = ?', (otp_record[0],))
            conn.commit()
            
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
    if 'logged_in' not in session:
        return redirect(url_for('login'))

    conn = sqlite3.connect('users.db')
    c = conn.cursor()

    c.execute('SELECT email, COUNT(*) as attempts FROM login_attempts GROUP BY email')
    login_attempts = c.fetchall()

    c.execute('SELECT success, COUNT(*) FROM login_attempts GROUP BY success')
    success_failure = dict(c.fetchall())

    c.execute('SELECT email, locked FROM users')
    account_locks = c.fetchall()

    c.execute('SELECT email, COUNT(*) as otps_sent FROM otps GROUP BY email')
    otp_data = c.fetchall()

    conn.close()

    login_labels = [row[0] for row in login_attempts]
    login_counts = [row[1] for row in login_attempts]
    locked_count = sum(1 for row in account_locks if row[1] == 1)
    unlocked_count = sum(1 for row in account_locks if row[1] == 0)
    otp_labels = [row[0] for row in otp_data]
    otp_counts = [row[1] for row in otp_data]

    return render_template(
        'dashboard.html',
        login_labels=login_labels,
        login_counts=login_counts,
        locked_count=locked_count,
        unlocked_count=unlocked_count,
        otp_labels=otp_labels,
        otp_counts=otp_counts,
        success_count=success_failure.get(1, 0),
        failure_count=success_failure.get(0, 0)
    )

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.')
    return redirect(url_for('home'))

init_db()

if __name__ == '__main__':
    app.run(debug=DEV_MODE)
