"""
Email + OAuth Webhook Service for CrabPass
- Receives inbound emails via SendGrid
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
            # Emails table
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
    logger.info("Tables ready")


# ============== EMAIL FUNCTIONS ==============

def extract_bot_address(to_field):
    """Extract the bot email address from the To field"""
    match = re.search(r'[\w.-]+@crabpass\.ai', to_field.lower())
    if match:
        return match.group(0)
    return None


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
    """Store email in database"""
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
            # Clean up old states (older than 10 minutes)
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
            
            # Check if token is expired or about to expire
            cur.execute(
                "SELECT expires_at < NOW() + INTERVAL '5 minutes' as needs_refresh FROM oauth_tokens WHERE id = %s",
                (token['id'],)
            )
            needs_refresh = cur.fetchone()['needs_refresh']
            
            if needs_refresh and token['refresh_token']:
                # Refresh the token
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

@app.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "ok"})


@app.route('/bots', methods=['GET'])
def list_bots():
    """List all registered bots"""
    try:
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT id, bot_username, owner_id, is_active, created_at FROM bots ORDER BY id")
                bots = cur.fetchall()
                return jsonify({"bots": [dict(b) for b in bots]})
    except Exception as e:
        logger.error(f"Error listing bots: {e}")
        return jsonify({"error": str(e)}), 500


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
        <h1>❌ Connection Failed</h1>
        <p>Error: {error}</p>
        <p>You can close this window.</p>
        </body></html>
        """, 400
    
    if not code or not state:
        return "Missing code or state", 400
    
    # Verify state
    state_data = verify_oauth_state(state)
    if not state_data:
        return "Invalid or expired state", 400
    
    bot_id = state_data['bot_id']
    user_id = state_data['user_id']
    provider = state_data['provider']
    
    # Exchange code for token
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
        <h1>✅ Google Drive Connected!</h1>
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
    file_url = data.get('file_url')  # Telegram file URL
    folder_name = data.get('folder_name', 'CrabPass')
    
    if not all([bot_id, user_id, file_name, file_url]):
        return jsonify({"error": "Missing required fields"}), 400
    
    token = get_oauth_token(int(bot_id), int(user_id), 'google')
    if not token:
        return jsonify({"error": "Not connected to Google Drive"}), 401
    
    try:
        # Download file from Telegram
        file_response = requests.get(file_url)
        if file_response.status_code != 200:
            return jsonify({"error": "Failed to download file"}), 400
        
        file_content = file_response.content
        
        headers = {'Authorization': f'Bearer {token}'}
        
        # Find or create folder
        folder_query = f"name='{folder_name}' and mimeType='application/vnd.google-apps.folder' and trashed=false"
        folder_response = requests.get(
            f"https://www.googleapis.com/drive/v3/files?q={folder_query}",
            headers=headers
        )
        
        folders = folder_response.json().get('files', [])
        
        if folders:
            folder_id = folders[0]['id']
        else:
            # Create folder
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
        
        # Upload file
        metadata = {
            'name': file_name,
            'parents': [folder_id]
        }
        
        # Simple upload for files < 5MB
        if len(file_content) < 5 * 1024 * 1024:
            # Use simple upload
            upload_response = requests.post(
                'https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart',
                headers=headers,
                files={
                    'metadata': ('metadata', json.dumps(metadata), 'application/json'),
                    'file': (file_name, file_content)
                }
            )
        else:
            # For larger files, use resumable upload (simplified)
            upload_response = requests.post(
                'https://www.googleapis.com/upload/drive/v3/files?uploadType=media',
                headers={**headers, 'Content-Type': 'application/octet-stream'},
                data=file_content,
                params={'name': file_name, 'parents': folder_id}
            )
        
        if upload_response.status_code in [200, 201]:
            file_data = upload_response.json()
            
            # Make file accessible via link
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
            return jsonify({"error": "Upload failed"}), 500
            
    except Exception as e:
        logger.error(f"Drive upload error: {e}")
        return jsonify({"error": str(e)}), 500


if __name__ == '__main__':
    logger.info("Starting webhook service...")
    ensure_tables()
    port = int(os.environ.get('PORT', 8080))
    app.run(host='0.0.0.0', port=port)
