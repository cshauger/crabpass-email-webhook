"""
Email + OAuth Webhook Service for CrabPass
- Receives inbound emails via SendGrid
- Sends outbound emails via SendGrid
- Handles Google Drive OAuth flow
"""
import os
import re
import json
import logging
import secrets
from urllib.parse import urlencode
from flask import Flask, request, jsonify, redirect
import psycopg2
from psycopg2.extras import RealDictCursor
import requests

app = Flask(__name__)

DATABASE_URL = os.environ.get("DATABASE_URL")
SENDGRID_API_KEY = os.environ.get("SENDGRID_API_KEY")

# Google OAuth settings
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET")
OAUTH_REDIRECT_URI = os.environ.get("OAUTH_REDIRECT_URI", "https://email-webhook-production-887d.up.railway.app/oauth/callback")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def get_db():
    return psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)


def ensure_tables():
    """Create tables if they don't exist"""
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS emails (
                    id SERIAL PRIMARY KEY,
                    bot_id INTEGER REFERENCES bots(id),
                    from_email TEXT NOT NULL,
                    to_email TEXT NOT NULL,
                    subject TEXT,
                    body_plain TEXT,
                    body_html TEXT,
                    received_at TIMESTAMP DEFAULT NOW(),
                    read BOOLEAN DEFAULT FALSE,
                    notified BOOLEAN DEFAULT FALSE
                )
            """)
            
            cur.execute("""
                CREATE TABLE IF NOT EXISTS sent_emails (
                    id SERIAL PRIMARY KEY,
                    bot_id INTEGER REFERENCES bots(id),
                    from_email TEXT NOT NULL,
                    to_email TEXT NOT NULL,
                    subject TEXT,
                    body_plain TEXT,
                    body_html TEXT,
                    sent_at TIMESTAMP DEFAULT NOW(),
                    status TEXT DEFAULT 'sent'
                )
            """)
            
            cur.execute("""
                CREATE TABLE IF NOT EXISTS oauth_tokens (
                    id SERIAL PRIMARY KEY,
                    bot_id INTEGER REFERENCES bots(id),
                    user_id BIGINT NOT NULL,
                    provider TEXT NOT NULL,
                    access_token TEXT NOT NULL,
                    refresh_token TEXT,
                    expires_at TIMESTAMP,
                    scope TEXT,
                    created_at TIMESTAMP DEFAULT NOW(),
                    updated_at TIMESTAMP DEFAULT NOW(),
                    UNIQUE(bot_id, user_id, provider)
                )
            """)
            
            cur.execute("""
                CREATE TABLE IF NOT EXISTS oauth_state (
                    state TEXT PRIMARY KEY,
                    bot_id INTEGER NOT NULL,
                    user_id BIGINT NOT NULL,
                    provider TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT NOW()
                )
            """)
            
            conn.commit()
    logger.info("Tables ready")


def extract_bot_address(to_field):
    match = re.search(r'[\w.-]+@crabpass\.ai', to_field.lower())
    return match.group(0) if match else None


def find_bot_by_email(email_address):
    if not email_address:
        return None
    username = email_address.split('@')[0].lower()
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM bots WHERE LOWER(bot_username) = %s AND is_active = true", (username,))
            row = cur.fetchone()
            return row['id'] if row else None


def find_bot_by_username(username):
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id, bot_username FROM bots WHERE LOWER(bot_username) = %s AND is_active = true", (username.lower(),))
            return cur.fetchone()


def store_email(bot_id, from_email, to_email, subject, body_plain, body_html):
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """INSERT INTO emails (bot_id, from_email, to_email, subject, body_plain, body_html)
                   VALUES (%s, %s, %s, %s, %s, %s) RETURNING id""",
                (bot_id, from_email, to_email, subject, body_plain, body_html)
            )
            email_id = cur.fetchone()['id']
            conn.commit()
            return email_id


def store_sent_email(bot_id, from_email, to_email, subject, body_plain, body_html, status='sent'):
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """INSERT INTO sent_emails (bot_id, from_email, to_email, subject, body_plain, body_html, status)
                   VALUES (%s, %s, %s, %s, %s, %s, %s) RETURNING id""",
                (bot_id, from_email, to_email, subject, body_plain, body_html, status)
            )
            email_id = cur.fetchone()['id']
            conn.commit()
            return email_id


def send_email_via_sendgrid(from_email, from_name, to_email, subject, body_plain, body_html=None):
    if not SENDGRID_API_KEY:
        return False, "SendGrid API key not configured"
    
    payload = {
        "personalizations": [{"to": [{"email": to_email}]}],
        "from": {"email": from_email, "name": from_name},
        "subject": subject,
        "content": []
    }
    
    if body_plain:
        payload["content"].append({"type": "text/plain", "value": body_plain})
    if body_html:
        payload["content"].append({"type": "text/html", "value": body_html})
    if not payload["content"]:
        payload["content"].append({"type": "text/plain", "value": ""})
    
    try:
        response = requests.post(
            "https://api.sendgrid.com/v3/mail/send",
            headers={"Authorization": f"Bearer {SENDGRID_API_KEY}", "Content-Type": "application/json"},
            json=payload
        )
        if response.status_code in [200, 201, 202]:
            return True, "sent"
        logger.error(f"SendGrid error: {response.status_code} - {response.text}")
        return False, f"SendGrid error: {response.status_code}"
    except Exception as e:
        logger.error(f"SendGrid exception: {e}")
        return False, str(e)
