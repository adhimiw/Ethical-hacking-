# Render Deployment Guide

This guide explains how to deploy the Ethical Hacking Login Module to Render.

## Prerequisites

1. A Render account (https://render.com)
2. A GitHub repository with this code
3. Gmail account with App Password for email functionality
4. reCAPTCHA keys from Google

## Step 1: Prepare Environment Variables

Before deploying, gather these values:

### Email Configuration
- **EMAIL_USER**: Your Gmail address (e.g., `your-email@gmail.com`)
- **EMAIL_APP_PASSWORD**: Gmail App Password (NOT your regular password)
  - Go to https://myaccount.google.com/apppasswords
  - Select "Mail" and "Windows Computer" (or your device)
  - Generate and copy the 16-character password
- **EMAIL_FROM**: Display name (e.g., `Ethical Hacking Module <your-email@gmail.com>`)

### reCAPTCHA Configuration
- **RECAPTCHA_SITE_KEY**: Public key from Google reCAPTCHA
- **RECAPTCHA_SECRET_KEY**: Secret key from Google reCAPTCHA
- Go to https://www.google.com/recaptcha/admin
- Create a new site with reCAPTCHA v2 (Checkbox)
- Add your Render domain: `*.onrender.com`

### Security Configuration
- **SECRET_KEY**: Generate a strong random key (use `python -c "import os; print(os.urandom(32).hex())"`)
- **DEV_MODE**: Set to `false` for production

## Step 2: Create Render Web Service

1. Go to https://dashboard.render.com
2. Click "New +" → "Web Service"
3. Connect your GitHub repository
4. Fill in the configuration:
   - **Name**: `ethical-hacking-login` (or your preferred name)
   - **Runtime**: Python 3.11
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `gunicorn --workers 4 --worker-class sync --bind 0.0.0.0:$PORT --timeout 120 app:app`
   - **Plan**: Free or Paid (Free tier works for testing)

## Step 3: Configure Environment Variables

In Render dashboard, go to your service → Environment:

Add these environment variables:

```
DEV_MODE=false
SECRET_KEY=<your-generated-secret-key>
EMAIL_USER=<your-gmail@gmail.com>
EMAIL_APP_PASSWORD=<your-16-char-app-password>
EMAIL_FROM=Ethical Hacking Module <your-email@gmail.com>
RECAPTCHA_SITE_KEY=<your-recaptcha-site-key>
RECAPTCHA_SECRET_KEY=<your-recaptcha-secret-key>
```

## Step 4: Configure Persistent Disk (Important!)

The database needs persistent storage to survive deployments:

1. In Render dashboard → Your Service → Disks
2. Click "Create Disk"
3. Configure:
   - **Name**: `sqlite-db`
   - **Mount Path**: `/var/data`
   - **Size**: 1 GB (sufficient for testing)

## Step 5: Deploy

1. Click "Deploy" in Render dashboard
2. Monitor the deployment logs
3. Once deployed, your app will be available at: `https://<service-name>.onrender.com`

## Troubleshooting

### Database Not Persisting
- Ensure you've created a persistent disk at `/var/data`
- Check that `RENDER=true` is set (Render sets this automatically)

### Email Not Sending
- Verify Gmail App Password is correct (not your regular password)
- Check that "Less secure app access" is enabled if using regular password
- Look at logs for SMTP errors

### reCAPTCHA Showing Test Banner
- Ensure your Render domain is added to reCAPTCHA settings
- Verify `RECAPTCHA_SITE_KEY` and `RECAPTCHA_SECRET_KEY` are correct
- If using test keys, the banner will show (this is normal for testing)

### Port Issues
- Render automatically sets the `PORT` environment variable
- The app uses `$PORT` from environment, so no manual configuration needed

### Application Crashes on Startup
- Check logs for database permission errors
- Verify all required environment variables are set
- Ensure persistent disk is mounted at `/var/data`

## Monitoring

After deployment:

1. Check **Logs** tab for any errors
2. Monitor **Metrics** for CPU/Memory usage
3. Test the application at your Render URL
4. Use the **Shell** tab to debug if needed

## Updating the Application

To update your application:

1. Push changes to your GitHub repository
2. Render will automatically redeploy (if auto-deploy is enabled)
3. Or manually click "Deploy" in Render dashboard

## Cost Considerations

- **Free Tier**: Limited resources, services spin down after 15 minutes of inactivity
- **Paid Tier**: Always-on service, better performance
- **Persistent Disk**: Costs $0.25/GB/month

## Additional Resources

- [Render Documentation](https://render.com/docs)
- [Flask Deployment Guide](https://flask.palletsprojects.com/deployment/)
- [Gunicorn Documentation](https://gunicorn.org/)
