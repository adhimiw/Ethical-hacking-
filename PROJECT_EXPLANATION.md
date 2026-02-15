# Secure Authentication Module - Technical Explanation

This document explains the security mechanisms implemented in the **Ethical Hacking Login Module** to prevent unauthorized access and bot activities.

## 1. reCAPTCHA (Authentication Prevention)
- **Functionality**: We use Google's reCAPTCHA to distinguish between human users and automated bots.
- **How it works**: Before the form is submitted, the user must solve a challenge. The frontend sends a token to our Flask backend, which then validates it with Google's servers.
- **Security Goal**: Prevents "Credential Stuffing" attacks where bots try thousands of leaked email/password combinations automatically.

## 2. Password Attempt Limits & Account Locking
- **Functionality**: The system tracks failed login attempts for each email address.
- **How it works**: 
    - Each failed login increments a `failed_attempts` counter in the SQLite database.
    - If the counter reaches **5**, the `locked` status is set to `1`.
    - Once locked, the user cannot log in even with the correct password until they go through the **Unlock Flow**.
- **Security Goal**: Prevents "Brute-force Attacks" where an attacker tries to guess a password by repeatedly trying different combinations.

## 3. Email Verification
- **Functionality**: New accounts are inactive until the email owner clicks a verification link.
- **How it works**: 
    - Upon registration, the system generates a unique verification link (`/verify_email/<email>`).
    - The `verified` field in the database starts at `0`.
    - Login is only allowed if `verified == 1`.
- **Security Goal**: Ensures the user owns the email address they registered with and prevents bulk fake account creation.

## 4. OTP (One-Time Password) / 2FA
- **Functionality**: A second layer of security after the password check.
- **How it works**:
    - After entering the correct password, the system generates a random 6-digit code.
    - This code is stored in the `otps` table and emailed to the user.
    - The user must enter this code within the same session to access the dashboard.
- **Security Goal**: Implements "Multi-Factor Authentication" (MFA). Even if an attacker steals the password, they cannot enter the account without access to the user's email inbox.

## 5. "Hold to Submit" Security Button
- **Functionality**: A physical interaction delay for form submission.
- **How it works**:
    - The submit button requires a continuous **1.5-second hold** (mouse click or touch).
    - A visual progress bar fills inside the button during the hold.
    - If the user lets go early, the timer resets and the form is **not** submitted.
- **Security Goal**: 
    - Adds a layer of "User Intent" verification.
    - Prevents accidental submissions.
    - Disrupts simple click-automation scripts that don't simulate long-press events.

## 6. Security Analytics Dashboard
- **Functionality**: Real-time monitoring of authentication events.
- **How it works**:
    - Every login attempt (success or failure) is logged in the `login_attempts` table with the user's IP address.
    - The dashboard uses **Chart.js** to visualize these logs, showing patterns of failed attempts or account locks across the system.
- **Security Goal**: Provides "Intrusion Detection" capabilities. Administrators can spot patterns of attacks (e.g., many failures from one IP) and take action.
