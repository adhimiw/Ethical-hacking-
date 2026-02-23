# Quick Start: Deploy to Render Free Tier in 5 Minutes

## Prerequisites
- GitHub account with this repository
- Render account (https://render.com) - FREE TIER
- Gmail account with App Password

## Important Note: Free Tier Limitations
- Database resets on service redeploy
- Service spins down after 15 minutes of inactivity
- Shared ephemeral filesystem (no persistent storage)
- Perfect for testing and development!

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

## Step 4: Deploy! (Click Deploy)

Your app will be live at: `https://<service-name>.onrender.com`

## Test It
- Home: `https://<service-name>.onrender.com/`
- Register: `https://<service-name>.onrender.com/register`
- Login: `https://<service-name>.onrender.com/login`

## Important: Free Tier Behavior

**Database Reset:**
- Database resets when you redeploy
- Database resets after 15 minutes of inactivity (service spins down)
- This is normal for free tier - perfect for testing!

**For Production with Persistent Storage:**
- Upgrade to Render's paid tier
- Add persistent disk configuration
- See RENDER_DEPLOYMENT.md for paid tier setup

## Troubleshooting

### Service Won't Start
- Check logs in Render dashboard
- Verify all environment variables are set
- Ensure requirements.txt has all dependencies

### Email Not Sending
- Verify Gmail App Password (not regular password)
- Check Render logs for SMTP errors

### reCAPTCHA Issues
- Add `*.onrender.com` to reCAPTCHA domains
- Verify keys are correct

## Next Steps

For more details, see:
- RENDER_DEPLOYMENT.md - Full guide with paid tier options
- FIXES_SUMMARY.md - Technical details
- README.md - Project overview
