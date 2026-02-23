# Quick Start: Deploy to Render in 5 Minutes

## Prerequisites
- GitHub account with this repository
- Render account (https://render.com)
- Gmail account with App Password

## Step 1: Get Your Credentials (2 min)

### Gmail App Password
1. Go to https://myaccount.google.com/apppasswords
2. Select "Mail" and "Windows Computer"
3. Copy the 16-character password

### reCAPTCHA Keys
1. Go to https://www.google.com/recaptcha/admin
2. Create new site with reCAPTCHA v2 (Checkbox)
3. Add domain: `*.onrender.com`
4. Copy Site Key and Secret Key

### Secret Key (Generate)
```bash
python -c "import os; print(os.urandom(32).hex())"
```

## Step 2: Create Render Service (2 min)

1. Go to https://dashboard.render.com
2. Click "New +" → "Web Service"
3. Select your GitHub repository
4. Fill in:
   - **Name**: `ethical-hacking-login`
   - **Runtime**: Python 3.11
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `gunicorn --workers 4 --worker-class sync --bind 0.0.0.0:$PORT --timeout 120 app:app`

## Step 3: Add Environment Variables (1 min)

In Render dashboard → Your Service → Environment, add:

```
DEV_MODE=false
SECRET_KEY=<your-generated-secret-key>
EMAIL_USER=<your-gmail@gmail.com>
EMAIL_APP_PASSWORD=<your-16-char-app-password>
EMAIL_FROM=Ethical Hacking Module <your-email@gmail.com>
RECAPTCHA_SITE_KEY=<your-site-key>
RECAPTCHA_SECRET_KEY=<your-secret-key>
```

## Step 4: Create Persistent Disk (1 min)

1. In Render dashboard → Your Service → Disks
2. Click "Create Disk"
3. Configure:
   - **Name**: `sqlite-db`
   - **Mount Path**: `/var/data`
   - **Size**: 1 GB

## Step 5: Deploy! (Click Deploy)

Your app will be live at: `https://<service-name>.onrender.com`

## Test It
- Home: `https://<service-name>.onrender.com/`
- Register: `https://<service-name>.onrender.com/register`
- Login: `https://<service-name>.onrender.com/login`

## Issues?
See `RENDER_DEPLOYMENT.md` for detailed troubleshooting.
