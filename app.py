# Ethical Hacking Login Module (Python/Flask)
# Features: Email Verification, Captcha, OTP, Password Attempt Limits, Rate Limiting

from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
try:
    from flask_recaptcha import ReCaptcha
    HAS_RECAPTCHA = True
except ImportError:
    HAS_RECAPTCHA = False
import smtplib
from email.mime.text import MIMEText
import random
import sqlite3
import os
from datetime import datetime, timedelta
from dotenv import load_dotenv
load_dotenv()

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.urandom(24)

# Configure reCAPTCHA
app.config['RECAPTCHA_SITE_KEY'] = os.environ.get('RECAPTCHA_SITE_KEY', 'YOUR_RECAPTCHA_SITE_KEY')
app.config['RECAPTCHA_SECRET_KEY'] = os.environ.get('RECAPTCHA_SECRET_KEY', 'YOUR_RECAPTCHA_SECRET_KEY')
DEV_MODE = os.environ.get('DEV_MODE', 'true').lower() == 'true'
if HAS_RECAPTCHA and not DEV_MODE:
    recaptcha = ReCaptcha(app)
else:
    class FakeRecaptcha:
        def verify(self): return True
    recaptcha = FakeRecaptcha()

# Configure rate limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["10 per hour"]
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
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()

# Email setup
EMAIL_USER = os.environ.get('EMAIL_USER', 'adhithanraja6@gmail.com')
EMAIL_APP_PASSWORD = os.environ.get('EMAIL_APP_PASSWORD', '')
EMAIL_FROM = os.environ.get('EMAIL_FROM', f'Adhithan Raja <{EMAIL_USER}>')

def send_email(to, subject, body):
    print(f"\n{'='*50}")
    print(f"📧 SENDING EMAIL")
    print(f"To: {to}")
    print(f"Subject: {subject}")
    print(f"Body: {body}")
    print(f"{'='*50}\n")
    try:
        msg = MIMEText(body)
        msg['Subject'] = subject
        msg['From'] = EMAIL_FROM
        msg['To'] = to
        with smtplib.SMTP('smtp.gmail.com', 587) as server:
            server.starttls()
            server.login(EMAIL_USER, EMAIL_APP_PASSWORD)
            server.send_message(msg)
        print(f"✅ Email sent successfully to {to}")
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

        if not recaptcha.verify():
            flash('reCAPTCHA verification failed.')
            return redirect(url_for('register'))

        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute('SELECT * FROM users WHERE email = ?', (email,))
        if c.fetchone():
            flash('Email already registered.')
            return redirect(url_for('register'))

        # Send verification email
        verification_link = url_for('verify_email', email=email, _external=True)
        send_email(
            to=email,
            subject='Verify Your Email',
            body=f'Click here to verify your email: {verification_link}'
        )

        c.execute('INSERT INTO users (email, password) VALUES (?, ?)', (email, password))
        conn.commit()
        conn.close()

        flash('Registration successful! Check your email for verification.')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/verify_email/<email>')
def verify_email(email):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('UPDATE users SET verified = 1 WHERE email = ?', (email,))
    conn.commit()
    conn.close()
    flash('Email verified successfully!')
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per hour")
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        if not recaptcha.verify():
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
            flash('Your account is locked. Please unlock it.')
            return redirect(url_for('unlock'))

        if user[2] != password:
            c.execute('INSERT INTO login_attempts (email, success, ip_address) VALUES (?, 0, ?)', (email, get_remote_address()))
            failed_attempts = user[5] + 1
            if failed_attempts >= 5:
                c.execute('UPDATE users SET locked = 1 WHERE email = ?', (email,))
                conn.commit()
                flash('Your account is locked due to too many failed attempts.')
                return redirect(url_for('unlock'))
            else:
                c.execute('UPDATE users SET failed_attempts = ?, last_attempt = ? WHERE email = ?', (failed_attempts, datetime.now(), email))
                conn.commit()
                flash('Invalid password.')
                return redirect(url_for('login'))

        # Generate and send OTP
        otp = generate_otp()
        c.execute('INSERT INTO login_attempts (email, success, ip_address) VALUES (?, 1, ?)', (email, get_remote_address()))
        c.execute('INSERT INTO otps (email, otp) VALUES (?, ?)', (email, otp))
        conn.commit()

        send_email(
            to=email,
            subject='Your OTP Code',
            body=f'Your OTP code is: {otp}'
        )

        session['email'] = email
        return redirect(url_for('verify_otp'))

    return render_template('login.html')

@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    if 'email' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        otp = request.form['otp']
        email = session['email']

        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute('SELECT * FROM otps WHERE email = ? AND otp = ? ORDER BY created_at DESC LIMIT 1', (email, otp))
        otp_record = c.fetchone()

        if otp_record:
            # OTP is valid, log the user in
            session['logged_in'] = True
            flash('Login successful!')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid OTP.')

    return render_template('verify_otp.html')

@app.route('/unlock', methods=['GET', 'POST'])
def unlock():
    if request.method == 'POST':
        email = request.form['email']

        if not recaptcha.verify():
            flash('reCAPTCHA verification failed.')
            return redirect(url_for('unlock'))

        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute('SELECT * FROM users WHERE email = ?', (email,))
        user = c.fetchone()

        if not user:
            flash('Invalid email.')
            return redirect(url_for('unlock'))

        # Generate and send unlock OTP
        otp = generate_otp()
        c.execute('INSERT INTO otps (email, otp) VALUES (?, ?)', (email, otp))
        conn.commit()

        send_email(
            to=email,
            subject='Your Unlock OTP Code',
            body=f'Your unlock OTP code is: {otp}'
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
        c.execute('SELECT * FROM otps WHERE email = ? AND otp = ? ORDER BY created_at DESC LIMIT 1', (email, otp))
        otp_record = c.fetchone()

        if otp_record:
            c.execute('UPDATE users SET locked = 0, failed_attempts = 0 WHERE email = ?', (email,))
            conn.commit()
            flash('Account unlocked successfully!')
            return redirect(url_for('login'))
        else:
            flash('Invalid OTP.')

    return render_template('verify_unlock_otp.html')

@app.route('/dashboard')
def dashboard():
    if 'logged_in' not in session:
        return redirect(url_for('login'))

    conn = sqlite3.connect('users.db')
    c = conn.cursor()

    # Fetch login attempts data (actual history)
    c.execute('SELECT email, COUNT(*) as attempts FROM login_attempts GROUP BY email')
    login_attempts = c.fetchall()

    # Fetch success vs failure for extra signal
    c.execute('SELECT success, COUNT(*) FROM login_attempts GROUP BY success')
    success_failure = dict(c.fetchall())

    # Fetch account locks data
    c.execute('SELECT email, locked FROM users')
    account_locks = c.fetchall()

    # Fetch OTP data
    c.execute('SELECT email, COUNT(*) as otps_sent FROM otps GROUP BY email')
    otp_data = c.fetchall()

    conn.close()

    # Prepare chart-friendly data
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

# Initialize database
init_db()

if __name__ == '__main__':
    app.run(debug=True)
