# Ethical Hacking Login Module (Python/Flask)

A secure login system with email verification, Captcha, OTP, password attempt limits, and rate limiting.

## Features
- **Email Verification**: Users must verify their email to activate their account.
- **Captcha**: Google reCAPTCHA on login/registration forms.
- **OTP (2FA)**: One-Time Password sent via email for two-factor authentication.
- **Password Attempt Limits**: Account locks after 5 failed attempts.
- **Rate Limiting**: 10 login attempts per hour per IP.
- **Dashboard**: Visualize login attempts, account locks, and OTP status.

## Setup

### Prerequisites
- Python 3.8 or later
- Flask
- SQLite (included with Python)
- Google reCAPTCHA API keys (for production)

### Installation
1. Clone the repository:
   ```bash
   git clone <repository-url>
   cd ethical-hacking-login-module-python
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Create a `.env` file based on `.env.example` and fill in your credentials:
   ```env
   # Email configuration (for sending OTPs/verification links)
   EMAIL_SERVICE=smtp.example.com
   EMAIL_USER=your-email@example.com
   EMAIL_PASSWORD=your-email-password

   # reCAPTCHA keys
   RECAPTCHA_SITE_KEY=your-site-key
   RECAPTCHA_SECRET_KEY=your-secret-key

   # Server configuration
   PORT=5000
   ```

4. Start the server:
   ```bash
   python app.py
   ```

5. Open your browser and navigate to:
   - Home: `http://localhost:5000/`
   - Registration: `http://localhost:5000/register`
   - Login: `http://localhost:5000/login`
   - Dashboard: `http://localhost:5000/dashboard`

## Demo Script

1. **Register a new user**:
   - Go to `http://localhost:5000/register`.
   - Fill in your email and password, then solve the Captcha.
   - Check your email for the verification link and click it to activate your account.

2. **Login with OTP**:
   - Go to `http://localhost:5000/login`.
   - Enter your email and password, then solve the Captcha.
   - You’ll receive an OTP via email. Enter it to complete login.

3. **Test security features**:
   - Try logging in with the wrong password 5 times to trigger an account lock.
   - Attempt more than 10 logins in an hour to hit the rate limit.

4. **Unlock your account (if locked)**:
   - Go to `http://localhost:5000/unlock`.
   - Enter your email, solve the Captcha, and request an unlock OTP.
   - Enter the OTP to unlock your account.

5. **View the dashboard**:
   - Go to `http://localhost:5000/dashboard` to see visualizations of login attempts, account locks, and OTP status.

## License
This project is licensed under the MIT License.