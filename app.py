# Ethical Hacking Login Module (Python/Flask)
# Features: Email Verification, Captcha, OTP, Password Attempt Limits, Rate Limiting

from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_recaptcha import ReCaptcha
import smtplib
from email.mime.text import MIMEText
import random
import sqlite3
import os
from datetime import datetime, timedelta

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.urandom(24)

# Configure reCAPTCHA
app.config['RECAPTCHA_SITE_KEY'] = 'YOUR_RECAPTCHA_SITE_KEY'
app.config['RECAPTCHA_SECRET_KEY'] = 'YOUR_RECAPTCHA_SECRET_KEY'
recaptcha = ReCaptcha(app)

# Configure rate limiting
limiter = Limiter(
    app,
    key_func=get_remote_address,
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
def send_email(to, subject, body):
    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = 'your-email@example.com'
    msg['To'] = to

    with smtplib.SMTP('smtp.example.com', 587) as server:
        server.starttls()
        server.login('your-email@example.com', 'your-password')
        server.send_message(msg)

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
            failed_attempts = user[5] + 1
            if failed_attempts >= 5:
                c.execute('UPDATE users SET locked = 1 WHERE email = ?', (email,))
                flash('Your account is locked due to too many failed attempts.')
                return redirect(url_for('unlock'))
            else:
                c.execute('UPDATE users SET failed_attempts = ?, last_attempt = ? WHERE email = ?', (failed_attempts, datetime.now(), email))
                flash('Invalid password.')
                return redirect(url_for('login'))

        # Generate and send OTP
        otp = generate_otp()
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

    # Fetch login attempts data
    c.execute('SELECT email, COUNT(*) as attempts, MAX(CASE WHEN password = (SELECT password FROM users WHERE email = users.email) THEN 1 ELSE 0 END) as success FROM users GROUP BY email')
    login_attempts = c.fetchall()

    # Fetch account locks data
    c.execute('SELECT email, locked FROM users')
    account_locks = c.fetchall()

    # Fetch OTP data
    c.execute('SELECT email, COUNT(*) as otps_sent FROM otps GROUP BY email')
    otp_data = c.fetchall()

    conn.close()

    return render_template('dashboard.html', login_attempts=login_attempts, account_locks=account_locks, otp_data=otp_data)

# Initialize database
init_db()

if __name__ == '__main__':
    app.run(debug=True)