"""
Email Webhook Service for CrabPass
Receives inbound emails via SendGrid and routes to bots
"""
import os
import re
import logging
from flask import Flask, request, jsonify
import psycopg2
from datetime import datetime

app = Flask(__name__)

DATABASE_URL = os.environ.get("DATABASE_URL")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def get_db():
    return psycopg2.connect(DATABASE_URL)


def ensure_tables():
    """Create emails table if it doesn't exist"""
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
                    read BOOLEAN DEFAULT FALSE
                )
            """)
            conn.commit()
    logger.info("Emails table ready")


def extract_bot_address(to_field):
    """Extract the bot email address from the To field"""
    match = re.search(r'[\w.-]+@crabpass\.ai', to_field.lower())
    if match:
        return match.group(0)
    return None


def find_bot_by_email(email_address):
    """Find bot by email address - flexible matching"""
    if not email_address:
        return None
    
    # Extract username part (before @)
    username = email_address.split('@')[0].lower()
    
    with get_db() as conn:
        with conn.cursor() as cur:
            # Try multiple matching strategies:
            # 1. Exact match (case insensitive)
            # 2. Username matches start of bot_username (shog99 matches Shog99Bot)
            # 3. bot_username without "bot" suffix
            
            cur.execute("""
                SELECT id FROM bots 
                WHERE is_active = true 
                AND (
                    LOWER(bot_username) = %s
                    OR LOWER(bot_username) = %s
                    OR LOWER(REPLACE(bot_username, 'Bot', '')) = %s
                    OR LOWER(REPLACE(bot_username, 'bot', '')) = %s
                    OR %s = LOWER(REPLACE(bot_username, 'Bot', ''))
                    OR %s = LOWER(REPLACE(bot_username, 'bot', ''))
                )
                LIMIT 1
            """, (username, username + 'bot', username, username, username, username))
            
            row = cur.fetchone()
            if row:
                logger.info(f"Found bot ID {row[0]} for email {email_address}")
                return row[0]
            
            # Fallback: try LIKE match
            cur.execute("""
                SELECT id FROM bots 
                WHERE is_active = true 
                AND LOWER(bot_username) LIKE %s
                LIMIT 1
            """, (username + '%',))
            
            row = cur.fetchone()
            if row:
                logger.info(f"Found bot ID {row[0]} via LIKE for email {email_address}")
                return row[0]
            
            logger.warning(f"No bot found for email: {email_address} (username: {username})")
            return None


def store_email(bot_id, from_email, to_email, subject, body_plain, body_html):
    """Store email in database"""
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """INSERT INTO emails (bot_id, from_email, to_email, subject, body_plain, body_html)
                   VALUES (%s, %s, %s, %s, %s, %s) RETURNING id""",
                (bot_id, from_email, to_email, subject, body_plain, body_html)
            )
            email_id = cur.fetchone()[0]
            conn.commit()
            return email_id


@app.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "ok"})


@app.route('/inbound-email', methods=['POST'])
def inbound_email():
    """Handle inbound email from SendGrid"""
    try:
        # SendGrid sends form data
        from_email = request.form.get('from', '')
        to_email = request.form.get('to', '')
        subject = request.form.get('subject', '')
        body_plain = request.form.get('text', '')
        body_html = request.form.get('html', '')
        
        logger.info(f"Received email: from={from_email}, to={to_email}, subject={subject}")
        
        # Extract bot email address
        bot_address = extract_bot_address(to_email)
        if not bot_address:
            logger.warning(f"No valid crabpass.ai address found in: {to_email}")
            return jsonify({"status": "ignored", "reason": "no valid address"}), 200
        
        # Find the bot
        bot_id = find_bot_by_email(bot_address)
        if not bot_id:
            logger.warning(f"No bot found for address: {bot_address}")
            return jsonify({"status": "ignored", "reason": "bot not found"}), 200
        
        # Store the email
        email_id = store_email(bot_id, from_email, to_email, subject, body_plain, body_html)
        logger.info(f"Stored email {email_id} for bot {bot_id}")
        
        return jsonify({"status": "ok", "email_id": email_id}), 200
        
    except Exception as e:
        logger.error(f"Error processing email: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500


if __name__ == '__main__':
    logger.info("Starting email webhook service...")
    ensure_tables()
    port = int(os.environ.get('PORT', 8080))
    app.run(host='0.0.0.0', port=port)
