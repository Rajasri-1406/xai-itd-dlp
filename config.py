import os
from dotenv import load_dotenv

# load_dotenv only fills values NOT already set in environment.
# On Render, env vars are injected before app starts so load_dotenv
# will not override them. Locally it reads from .env file as normal.
load_dotenv(override=False)

# MongoDB
MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017/")
DB_NAME   = os.getenv("DB_NAME", "xai_itd_dlp")

# SMTP
SMTP_SERVER   = os.getenv("SMTP_SERVER", "smtp.gmail.com")
SMTP_PORT     = int(os.getenv("SMTP_PORT", 587))
SMTP_EMAIL    = os.getenv("SMTP_EMAIL", "your_email@gmail.com")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "your_app_password")

# OTP redirect — all OTPs go to this email
OTP_REDIRECT_EMAIL = os.getenv("OTP_REDIRECT_EMAIL", SMTP_EMAIL)

# App
SECRET_KEY         = os.getenv("SECRET_KEY", "xai-itd-dlp-secret-2025")
OTP_EXPIRY_SECONDS = 120

# Environment
FLASK_ENV     = os.getenv("FLASK_ENV", "development")
IS_PRODUCTION = FLASK_ENV == "production"

# Startup debug — confirms which values are loaded on Render
print("[CONFIG] FLASK_ENV :", FLASK_ENV)
print("[CONFIG] MONGO_URI :", MONGO_URI[:45] + "..." if len(MONGO_URI) > 45 else MONGO_URI)
print("[CONFIG] DB_NAME   :", DB_NAME)