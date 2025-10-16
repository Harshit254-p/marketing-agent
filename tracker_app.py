from fastapi import FastAPI, Request, Response, HTTPException
from urllib.parse import unquote_plus
import sqlite3
from datetime import datetime
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Use the DB_NAME from .env, defaulting to 'automation_platform.db' if not set
# The .env file should explicitly set this to "user_data/automation_platform.db" for your setup.
DB_NAME = os.getenv("DB_NAME", "automation_platform.db")

# --- DEBUGGING AID: Print DB path FastAPI is using ---
print(f"FastAPI is configured to use DB: {DB_NAME}")
# ----------------------------------------------------

app = FastAPI(title="Email Tracking Backend")

def get_db_connection():
    # Ensure foreign_keys are enabled for CASCADE deletes
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

@app.get("/")
async def read_root():
    """Root endpoint to check if the tracker is running."""
    return {"message": "Email Tracker is running"}

@app.get("/track/open/{email_log_id}")
async def track_open(email_log_id: int, request: Request):
    """Endpoint for tracking email open events."""
    ip_address = request.client.host
    user_agent = request.headers.get("User-Agent", "Unknown")

    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        # Get lead_id from email_logs to associate tracking event
        email_log_entry = cursor.execute("SELECT lead_id FROM email_logs WHERE id = ?", (email_log_id,)).fetchone()
        if not email_log_entry:
            # It's crucial for the email_log_id to exist. If not, it's a broken link or old log.
            raise HTTPException(status_code=404, detail="Email log not found for open tracking")

        lead_id = email_log_entry['lead_id']

        cursor.execute(
            "INSERT INTO tracking_events (event_type, lead_id, email_log_id, timestamp, ip_address, user_agent) VALUES (?, ?, ?, ?, ?, ?)",
            ("open", lead_id, email_log_id, datetime.now().isoformat(), ip_address, user_agent)
        )
        conn.commit()
        print(f"TRACKING: Open event recorded for email_log_id {email_log_id}, lead_id {lead_id} from {ip_address}")
    except HTTPException as http_e:
        print(f"WARNING: {http_e.detail} (email_log_id: {email_log_id})")
        # Re-raise for FastAPI to handle the 404
        raise
    except Exception as e:
        # Log the error detailed in the FastAPI terminal
        print(f"ERROR: Failed to track open event for email_log_id {email_log_id}: {e}")
        # Consider more robust error handling for production (e.g., logging to file, Sentry)
    finally:
        conn.close()

    # Return a 1x1 transparent GIF (bytes) to avoid broken image icons and ensure silent tracking.
    # This is a standard transparent GIF.
    transparent_gif_bytes = b"\x47\x49\x46\x38\x39\x61\x01\x00\x01\x00\xf0\x01\x00\xff\xff\xff\x00\x00\x00\x21\xf9\x04\x01\x0a\x00\x00\x00\x2c\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02\x4c\x01\x00\x3b"
    return Response(content=transparent_gif_bytes, media_type="image/gif")


@app.get("/track/click/{email_log_id}")
async def track_click(email_log_id: int, target_url: str, request: Request):
    """Endpoint for tracking email click events and redirecting to the target URL."""
    ip_address = request.client.host
    user_agent = request.headers.get("User-Agent", "Unknown")
    decoded_target_url = unquote_plus(target_url)

    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        # Get lead_id from email_logs to associate tracking event
        email_log_entry = cursor.execute("SELECT lead_id FROM email_logs WHERE id = ?", (email_log_id,)).fetchone()
        if not email_log_entry:
            raise HTTPException(status_code=404, detail="Email log not found for click tracking")

        lead_id = email_log_entry['lead_id']

        cursor.execute(
            "INSERT INTO tracking_events (event_type, lead_id, email_log_id, timestamp, ip_address, user_agent, target_url) VALUES (?, ?, ?, ?, ?, ?, ?)",
            ("click", lead_id, email_log_id, datetime.now().isoformat(), ip_address, user_agent, decoded_target_url)
        )
        conn.commit()
        print(f"TRACKING: Click event recorded for email_log_id {email_log_id}, lead_id {lead_id} to {decoded_target_url} from {ip_address}")
    except HTTPException as http_e:
        print(f"WARNING: {http_e.detail} (email_log_id: {email_log_id})")
        # Re-raise for FastAPI to handle the 404
        raise
    except Exception as e:
        print(f"ERROR: Failed to track click event for email_log_id {email_log_id}: {e}")
    finally:
        conn.close()

    # Redirect the user to the actual target URL
    return Response(status_code=307, headers={"Location": decoded_target_url})