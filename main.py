"""
Email + OAuth Webhook Service for CrabPass
- Receives inbound emails via SendGrid
- Handles Google Drive OAuth flow
- Special handling for check@crabpass.ai (Check's inbox)
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

# Check's special email address
CHECK_EMAIL = "check@crabpass.ai"

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def get_db():
    return psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)


def ensure_tables():
    """Create tables if they don't exist"""
    with get_db() as conn:
        with conn.cursor() as cur:
            # Emails table - bot_id is nullable for check@crabpass.ai
            cur.execute("""
                CREATE TABLE IF NOT EXISTS emails (
                    id SERIAL PRIMARY KEY,
                    bot_id INTEGER REFERENCES bots(id),
                    from_email TEXT NOT NULL,
                    to_email TEXT NOT NULL,
                    subject TEXT,
                    body_plain TEXT,
                    body_html TEXT,
                    read BOOLEAN DEFAULT FALSE,
                    received_at TIMESTAMP DEFAULT NOW()
                )
            """)
            
            # Make bot_id nullable if it isn't already
            
            # Add source column to track which bot created each registration
            cur.execute("""
                ALTER TABLE bots ADD COLUMN IF NOT EXISTS source TEXT
            """)
            
            # Add deleted_at timestamp for cleanup tracking
            cur.execute("""
                ALTER TABLE bots ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMP
            
            # Config management columns
            cur.execute("""
                ALTER TABLE bots ADD COLUMN IF NOT EXISTS config JSONB DEFAULT '{}'
            """)
            cur.execute("""
                ALTER TABLE bots ADD COLUMN IF NOT EXISTS tier VARCHAR(20) DEFAULT 'free'
            """)
            cur.execute("""
                ALTER TABLE bots ADD COLUMN IF NOT EXISTS features JSONB DEFAULT '{}'
            """)
            
            # Future cert fields (reserved for ClawSign)
            cur.execute("""
                ALTER TABLE bots ADD COLUMN IF NOT EXISTS cert_fingerprint VARCHAR(64)
            """)
            cur.execute("""
                ALTER TABLE bots ADD COLUMN IF NOT EXISTS cert_issued_at TIMESTAMP
            """)
            cur.execute("""
                ALTER TABLE bots ADD COLUMN IF NOT EXISTS cert_expires_at TIMESTAMP
            """)
            cur.execute("""
                ALTER TABLE bots ADD COLUMN IF NOT EXISTS cert_data TEXT
            """)
            """)
            cur.execute("""
                ALTER TABLE emails ALTER COLUMN bot_id DROP NOT NULL
            """)
            
            # Index for fast bot email lookup
            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_emails_bot_id ON emails(bot_id)
            """)
            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_emails_unread ON emails(bot_id, read) WHERE read = FALSE
            """)
            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_emails_check ON emails(to_email) WHERE bot_id IS NULL
            """)
            
            # OAuth tokens table
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
            
            # OAuth state table (for CSRF protection)
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
    logger.info("Tables ready (emails with nullable bot_id, oauth_tokens, oauth_state)")


# ============== EMAIL FUNCTIONS ==============

def extract_bot_address(to_field):
    """Extract the bot email address from the To field"""
    match = re.search(r'[\w.-]+@crabpass\.ai', to_field.lower())
    if match:
        return match.group(0)
    return None


def is_check_email(email_address):
    """Check if this is Check's special email"""
    return email_address and email_address.lower() == CHECK_EMAIL


def find_bot_by_email(email_address):
    """Find bot by email address"""
    if not email_address:
        return None
    
    username = email_address.split('@')[0].lower()
    
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id FROM bots WHERE LOWER(bot_username) = %s AND is_active = true",
                (username,)
            )
            row = cur.fetchone()
            return row['id'] if row else None


def store_email(bot_id, from_email, to_email, subject, body_plain, body_html):
    """Store email in database - bot_id can be None for check@crabpass.ai"""
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


# ============== OAUTH FUNCTIONS ==============

def create_oauth_state(bot_id, user_id, provider):
    """Create a state token for OAuth CSRF protection"""
    state = secrets.token_urlsafe(32)
    
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM oauth_state WHERE created_at < NOW() - INTERVAL '10 minutes'")
            cur.execute(
                "INSERT INTO oauth_state (state, bot_id, user_id, provider) VALUES (%s, %s, %s, %s)",
                (state, bot_id, user_id, provider)
            )
            conn.commit()
    
    return state


def verify_oauth_state(state):
    """Verify and consume OAuth state token"""
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT bot_id, user_id, provider FROM oauth_state WHERE state = %s AND created_at > NOW() - INTERVAL '10 minutes'",
                (state,)
            )
            row = cur.fetchone()
            
            if row:
                cur.execute("DELETE FROM oauth_state WHERE state = %s", (state,))
                conn.commit()
                return row
            
            return None


def store_oauth_token(bot_id, user_id, provider, access_token, refresh_token, expires_in, scope):
    """Store or update OAuth token"""
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO oauth_tokens (bot_id, user_id, provider, access_token, refresh_token, expires_at, scope)
                VALUES (%s, %s, %s, %s, %s, NOW() + INTERVAL '%s seconds', %s)
                ON CONFLICT (bot_id, user_id, provider)
                DO UPDATE SET 
                    access_token = EXCLUDED.access_token,
                    refresh_token = COALESCE(EXCLUDED.refresh_token, oauth_tokens.refresh_token),
                    expires_at = EXCLUDED.expires_at,
                    scope = EXCLUDED.scope,
                    updated_at = NOW()
            """, (bot_id, user_id, provider, access_token, refresh_token, expires_in or 3600, scope))
            conn.commit()


def get_oauth_token(bot_id, user_id, provider):
    """Get OAuth token, refreshing if needed"""
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT * FROM oauth_tokens WHERE bot_id = %s AND user_id = %s AND provider = %s",
                (bot_id, user_id, provider)
            )
            token = cur.fetchone()
            
            if not token:
                return None
            
            cur.execute(
                "SELECT expires_at < NOW() + INTERVAL '5 minutes' as needs_refresh FROM oauth_tokens WHERE id = %s",
                (token['id'],)
            )
            needs_refresh = cur.fetchone()['needs_refresh']
            
            if needs_refresh and token['refresh_token']:
                new_token = refresh_google_token(token['refresh_token'])
                if new_token:
                    store_oauth_token(
                        bot_id, user_id, provider,
                        new_token['access_token'],
                        new_token.get('refresh_token'),
                        new_token.get('expires_in'),
                        token['scope']
                    )
                    return new_token['access_token']
            
            return token['access_token']


def refresh_google_token(refresh_token):
    """Refresh a Google OAuth token"""
    try:
        response = requests.post('https://oauth2.googleapis.com/token', data={
            'client_id': GOOGLE_CLIENT_ID,
            'client_secret': GOOGLE_CLIENT_SECRET,
            'refresh_token': refresh_token,
            'grant_type': 'refresh_token'
        })
        
        if response.status_code == 200:
            return response.json()
        else:
            logger.error(f"Token refresh failed: {response.text}")
            return None
    except Exception as e:
        logger.error(f"Token refresh error: {e}")
        return None


def get_google_auth_url(bot_id, user_id):
    """Generate Google OAuth URL"""
    state = create_oauth_state(bot_id, user_id, 'google')
    
    params = {
        'client_id': GOOGLE_CLIENT_ID,
        'redirect_uri': OAUTH_REDIRECT_URI,
        'response_type': 'code',
        'scope': 'https://www.googleapis.com/auth/drive.file',
        'access_type': 'offline',
        'prompt': 'consent',
        'state': state
    }
    
    return 'https://accounts.google.com/o/oauth2/v2/auth?' + urlencode(params)


# ============== ROUTES ==============

@app.route('/', methods=['GET'])
def root():
    return jsonify({"service": "CrabPass Email Webhook", "status": "ok"})


@app.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "ok"})


@app.route('/inbound-email', methods=['POST'])
def inbound_email():
    """Handle inbound email from SendGrid"""
    try:
        from_email = request.form.get('from', '')
        to_email = request.form.get('to', '')
        subject = request.form.get('subject', '')
        body_plain = request.form.get('text', '')
        body_html = request.form.get('html', '')
        
        logger.info(f"Received email: from={from_email}, to={to_email}, subject={subject}")
        
        bot_address = extract_bot_address(to_email)
        if not bot_address:
            logger.warning(f"No valid crabpass.ai address found in: {to_email}")
            return jsonify({"status": "ignored", "reason": "no valid address"}), 200
        
        # Special handling for Check's email
        if is_check_email(bot_address):
            email_id = store_email(None, from_email, to_email, subject, body_plain, body_html)
            logger.info(f"Stored email {email_id} for Check (check@crabpass.ai)")
            return jsonify({"status": "ok", "email_id": email_id, "recipient": "check"}), 200
        
        bot_id = find_bot_by_email(bot_address)
        if not bot_id:
            logger.warning(f"No bot found for address: {bot_address}")
            return jsonify({"status": "ignored", "reason": "bot not found"}), 200
        
        email_id = store_email(bot_id, from_email, to_email, subject, body_plain, body_html)
        logger.info(f"Stored email {email_id} for bot {bot_id}")
        
        return jsonify({"status": "ok", "email_id": email_id}), 200
        
    except Exception as e:
        logger.error(f"Error processing email: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route('/emails/recent', methods=['GET'])
def recent_emails():
    """Get recent emails - for debugging"""
    try:
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT id, bot_id, from_email, to_email, subject, body_plain, received_at 
                    FROM emails ORDER BY id DESC LIMIT 10
                """)
                emails = [dict(row) for row in cur.fetchall()]
                return jsonify({"emails": emails})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/check/emails', methods=['GET'])
def check_emails():
    """Get Check's emails (check@crabpass.ai)"""
    try:
        unread_only = request.args.get('unread', 'false').lower() == 'true'
        limit = int(request.args.get('limit', 20))
        
        with get_db() as conn:
            with conn.cursor() as cur:
                if unread_only:
                    cur.execute("""
                        SELECT id, from_email, to_email, subject, body_plain, read, received_at 
                        FROM emails 
                        WHERE bot_id IS NULL AND read = FALSE
                        ORDER BY id DESC LIMIT %s
                    """, (limit,))
                else:
                    cur.execute("""
                        SELECT id, from_email, to_email, subject, body_plain, read, received_at 
                        FROM emails 
                        WHERE bot_id IS NULL
                        ORDER BY id DESC LIMIT %s
                    """, (limit,))
                
                emails = [dict(row) for row in cur.fetchall()]
                return jsonify({"emails": emails, "count": len(emails)})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/check/emails/<int:email_id>/read', methods=['POST'])
def mark_check_email_read(email_id):
    """Mark one of Check's emails as read"""
    try:
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    UPDATE emails SET read = TRUE 
                    WHERE id = %s AND bot_id IS NULL
                    RETURNING id
                """, (email_id,))
                result = cur.fetchone()
                conn.commit()
                
                if result:
                    return jsonify({"status": "ok", "marked_read": email_id})
                else:
                    return jsonify({"error": "Email not found or not Check's"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/oauth/start', methods=['GET'])
def oauth_start():
    """Start OAuth flow - returns URL for bot to send to user"""
    bot_id = request.args.get('bot_id')
    user_id = request.args.get('user_id')
    provider = request.args.get('provider', 'google')
    
    if not bot_id or not user_id:
        return jsonify({"error": "Missing bot_id or user_id"}), 400
    
    if provider == 'google':
        if not GOOGLE_CLIENT_ID:
            return jsonify({"error": "Google OAuth not configured"}), 500
        
        auth_url = get_google_auth_url(int(bot_id), int(user_id))
        return jsonify({"auth_url": auth_url})
    
    return jsonify({"error": f"Unknown provider: {provider}"}), 400


@app.route('/oauth/callback', methods=['GET'])
def oauth_callback():
    """Handle OAuth callback from Google"""
    code = request.args.get('code')
    state = request.args.get('state')
    error = request.args.get('error')
    
    if error:
        return f"""
        <html><body style="font-family: sans-serif; text-align: center; padding-top: 50px;">
        <h1>Connection Failed</h1>
        <p>Error: {error}</p>
        <p>You can close this window.</p>
        </body></html>
        """, 400
    
    if not code or not state:
        return "Missing code or state", 400
    
    state_data = verify_oauth_state(state)
    if not state_data:
        return "Invalid or expired state", 400
    
    bot_id = state_data['bot_id']
    user_id = state_data['user_id']
    provider = state_data['provider']
    
    try:
        response = requests.post('https://oauth2.googleapis.com/token', data={
            'client_id': GOOGLE_CLIENT_ID,
            'client_secret': GOOGLE_CLIENT_SECRET,
            'code': code,
            'grant_type': 'authorization_code',
            'redirect_uri': OAUTH_REDIRECT_URI
        })
        
        if response.status_code != 200:
            logger.error(f"Token exchange failed: {response.text}")
            return f"Token exchange failed: {response.text}", 400
        
        token_data = response.json()
        
        store_oauth_token(
            bot_id, user_id, provider,
            token_data['access_token'],
            token_data.get('refresh_token'),
            token_data.get('expires_in'),
            token_data.get('scope', '')
        )
        
        logger.info(f"OAuth complete for bot {bot_id}, user {user_id}")
        
        return """
        <html><body style="font-family: sans-serif; text-align: center; padding-top: 50px;">
        <h1>Google Drive Connected!</h1>
        <p>You can now send files to your bot and they'll be saved to your Google Drive.</p>
        <p>You can close this window and return to Telegram.</p>
        </body></html>
        """
        
    except Exception as e:
        logger.error(f"OAuth error: {e}")
        return f"Error: {e}", 500


@app.route('/oauth/status', methods=['GET'])
def oauth_status():
    """Check if user has connected their account"""
    bot_id = request.args.get('bot_id')
    user_id = request.args.get('user_id')
    provider = request.args.get('provider', 'google')
    
    if not bot_id or not user_id:
        return jsonify({"error": "Missing bot_id or user_id"}), 400
    
    token = get_oauth_token(int(bot_id), int(user_id), provider)
    
    return jsonify({
        "connected": token is not None,
        "provider": provider
    })


@app.route('/drive/upload', methods=['POST'])
def drive_upload():
    """Upload a file to user's Google Drive"""
    data = request.json
    bot_id = data.get('bot_id')
    user_id = data.get('user_id')
    file_name = data.get('file_name')
    file_content_b64 = data.get('file_content')
    folder_name = data.get('folder_name', 'CrabPass')
    
    if not all([bot_id, user_id, file_name, file_content_b64]):
        return jsonify({"error": "Missing required fields"}), 400
    
    token = get_oauth_token(int(bot_id), int(user_id), 'google')
    if not token:
        return jsonify({"error": "Not connected to Google Drive"}), 401
    
    try:
        import base64
        file_content = base64.b64decode(file_content_b64)
        
        headers = {'Authorization': f'Bearer {token}'}
        
        folder_query = f"name='{folder_name}' and mimeType='application/vnd.google-apps.folder' and trashed=false"
        folder_response = requests.get(
            f"https://www.googleapis.com/drive/v3/files",
            headers=headers,
            params={'q': folder_query}
        )
        
        folders = folder_response.json().get('files', [])
        
        if folders:
            folder_id = folders[0]['id']
        else:
            folder_metadata = {
                'name': folder_name,
                'mimeType': 'application/vnd.google-apps.folder'
            }
            folder_create = requests.post(
                'https://www.googleapis.com/drive/v3/files',
                headers={**headers, 'Content-Type': 'application/json'},
                json=folder_metadata
            )
            folder_id = folder_create.json()['id']
        
        metadata = json.dumps({
            'name': file_name,
            'parents': [folder_id]
        })
        
        boundary = '----CrabPassBoundary'
        body = (
            f'--{boundary}\r\n'
            f'Content-Type: application/json; charset=UTF-8\r\n\r\n'
            f'{metadata}\r\n'
            f'--{boundary}\r\n'
            f'Content-Type: application/octet-stream\r\n\r\n'
        ).encode('utf-8') + file_content + f'\r\n--{boundary}--\r\n'.encode('utf-8')
        
        upload_response = requests.post(
            'https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart',
            headers={
                **headers,
                'Content-Type': f'multipart/related; boundary={boundary}'
            },
            data=body
        )
        
        if upload_response.status_code in [200, 201]:
            file_data = upload_response.json()
            
            requests.post(
                f"https://www.googleapis.com/drive/v3/files/{file_data['id']}/permissions",
                headers={**headers, 'Content-Type': 'application/json'},
                json={'type': 'anyone', 'role': 'reader'}
            )
            
            web_link = f"https://drive.google.com/file/d/{file_data['id']}/view"
            
            return jsonify({
                "status": "ok",
                "file_id": file_data['id'],
                "file_name": file_data.get('name'),
                "web_link": web_link
            })
        else:
            logger.error(f"Upload failed: {upload_response.text}")
            return jsonify({"error": "Upload failed", "details": upload_response.text}), 500
            
    except Exception as e:
        logger.error(f"Drive upload error: {e}")
        return jsonify({"error": str(e)}), 500



@app.route('/bots', methods=['GET'])
def list_bots():
    """List all registered bots"""
    try:
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT id, bot_username, user_id, is_active, created_at, source 
                    FROM bots ORDER BY id DESC
                """)
                bots = [dict(row) for row in cur.fetchall()]
                return jsonify({"bots": bots, "count": len(bots)})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/admin/backfill-sources', methods=['POST'])
def backfill_sources():
    """One-time backfill of source data"""
    try:
        with get_db() as conn:
            with conn.cursor() as cur:
                # Jetha99Bot from BotMaker
                cur.execute("UPDATE bots SET source = 'BotMaker' WHERE bot_username = 'Jetha99Bot'")
                # Rest from CrabPass Bot
                cur.execute("UPDATE bots SET source = 'CrabPass Bot' WHERE source IS NULL")
                conn.commit()
                return jsonify({"status": "ok", "message": "Sources backfilled"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/admin/nuke-bot/<int:bot_id>', methods=['DELETE'])
def nuke_bot(bot_id):
    """Deactivate a bot and optionally clean up its data"""
    cleanup = request.args.get('cleanup', 'false').lower() == 'true'
    
    try:
        with get_db() as conn:
            with conn.cursor() as cur:
                # Get bot info first
                cur.execute("SELECT bot_username FROM bots WHERE id = %s", (bot_id,))
                bot = cur.fetchone()
                if not bot:
                    return jsonify({"error": "Bot not found"}), 404
                
                bot_username = bot['bot_username']
                
                # Deactivate the bot
                cur.execute("UPDATE bots SET is_active = false, deleted_at = NOW() WHERE id = %s", (bot_id,))
                
                deleted = {"bot": bot_username, "deactivated": True}
                
                if cleanup:
                    # Delete related emails
                    cur.execute("DELETE FROM emails WHERE bot_id = %s", (bot_id,))
                    deleted["emails_deleted"] = cur.rowcount
                    
                    # Delete OAuth tokens
                    cur.execute("DELETE FROM oauth_tokens WHERE bot_id = %s", (bot_id,))
                    deleted["oauth_deleted"] = cur.rowcount
                
                conn.commit()
                return jsonify({"status": "ok", "deleted": deleted})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/admin/nuke-bot-by-name/<bot_username>', methods=['DELETE'])
def nuke_bot_by_name(bot_username):
    """Deactivate a bot by username"""
    cleanup = request.args.get('cleanup', 'false').lower() == 'true'
    
    try:
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT id FROM bots WHERE LOWER(bot_username) = LOWER(%s)", (bot_username,))
                bot = cur.fetchone()
                if not bot:
                    return jsonify({"error": "Bot not found"}), 404
                
                # Redirect to the ID-based endpoint logic
                bot_id = bot['id']
                
                cur.execute("UPDATE bots SET is_active = false, deleted_at = NOW() WHERE id = %s", (bot_id,))
                deleted = {"bot": bot_username, "deactivated": True}
                
                if cleanup:
                    cur.execute("DELETE FROM emails WHERE bot_id = %s", (bot_id,))
                    deleted["emails_deleted"] = cur.rowcount
                    cur.execute("DELETE FROM oauth_tokens WHERE bot_id = %s", (bot_id,))
                    deleted["oauth_deleted"] = cur.rowcount
                
                conn.commit()
                return jsonify({"status": "ok", "deleted": deleted})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/admin/cleanup-bots', methods=['POST'])
def cleanup_bots():
    """Purge bots that have been inactive for 30+ days"""
    days = int(request.args.get('days', 30))
    dry_run = request.args.get('dry_run', 'false').lower() == 'true'
    
    try:
        with get_db() as conn:
            with conn.cursor() as cur:
                # Find bots to purge
                cur.execute("""
                    SELECT id, bot_username, deleted_at 
                    FROM bots 
                    WHERE is_active = false 
                    AND deleted_at IS NOT NULL 
                    AND deleted_at < NOW() - INTERVAL '%s days'
                """, (days,))
                to_purge = cur.fetchall()
                
                if dry_run:
                    return jsonify({
                        "dry_run": True,
                        "would_purge": [{"id": b["id"], "username": b["bot_username"]} for b in to_purge]
                    })
                
                purged = []
                for bot in to_purge:
                    bot_id = bot["id"]
                    # Delete associated data
                    cur.execute("DELETE FROM emails WHERE bot_id = %s", (bot_id,))
                    cur.execute("DELETE FROM oauth_tokens WHERE bot_id = %s", (bot_id,))
                    # Delete the bot record
                    cur.execute("DELETE FROM bots WHERE id = %s", (bot_id,))
                    purged.append(bot["bot_username"])
                
                conn.commit()
                return jsonify({
                    "status": "ok",
                    "purged_count": len(purged),
                    "purged_bots": purged
                })
    except Exception as e:
        return jsonify({"error": str(e)}), 500
try:
    ensure_tables()
except Exception as e:
    logger.error(f"Failed to init tables: {e}")

if __name__ == "__main__":
    logger.info("Starting webhook service...")
    ensure_tables()
    port = int(os.environ.get('PORT', 8080))
    app.run(host='0.0.0.0', port=port)
