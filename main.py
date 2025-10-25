import streamlit as st 
import os
import json
import requests
import sqlite3
import re
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
from datetime import datetime, timedelta
from dotenv import load_dotenv
import google.generativeai as genai
from urllib.parse import urlparse, quote_plus
import pandas as pd
import bcrypt # For password hashing
import uuid # For generating unique tokens
import shutil # For deleting user data directories
import smtplib # For sending emails
import traceback # For detailed error logging

# --- CONFIGURATION & INITIALIZATION ---
load_dotenv()

# Environment Variables
# SMTP settings
SMTP_SERVER_CONFIG = os.getenv("SMTP_SERVER_CONFIG")
SMTP_PORT_CONFIG = os.getenv("SMTP_PORT_CONFIG")
SMTP_USERNAME_CONFIG = os.getenv("SMTP_USERNAME_CONFIG")
SMTP_PASSWORD_CONFIG = os.getenv("SMTP_PASSWORD_CONFIG")
SENDER_EMAIL = os.getenv("SENDER_EMAIL")

GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")
HUNTER_API_KEY = os.getenv("HUNTER_API_KEY")
DATA_DIR = os.getenv("DATA_DIR", "user_data")
DB_NAME = os.getenv("DB_NAME", "automation_platform.db") # This will be updated by .env

# !!! IMPORTANT: This MUST match the URL where your FastAPI tracker_app is running !!!
# For local testing, this will typically be "http://localhost:8000" if FastAPI is on 8000
# For deployment, it will be your public domain/IP:port, e.g., "https://yourdomain.com"
BASE_TRACKING_URL = os.getenv("BASE_TRACKING_URL")
if not BASE_TRACKING_URL:
    st.error("BASE_TRACKING_URL not set in .env. Email tracking and CTA links will not work correctly.")

STRATEGYHUB_URL = "https://www.strategyhub.in"

# Define the PDF filename and construct its path relative to the project root
DEMO_REPORT_PDF_FILENAME = "Sample_Report_Strategyhub.pdf"
# Corrected path for portability
DEMO_REPORT_PDF_PATH = os.path.join("static", DEMO_REPORT_PDF_FILENAME)


# Initialize Gemini Model
gemini_model = None
if GOOGLE_API_KEY:
    try:
        genai.configure(api_key=GOOGLE_API_KEY)
        gemini_model = genai.GenerativeModel("gemini-1.5-flash-latest")
    except Exception as e:
        st.error(f"Failed to configure Gemini API: {e}")
else:
    st.warning("Google API Key not found. Email composition will be limited to templates.")

TARGET_DESIGNATIONS = [
    "Director", "Chairman", "CEO", "CFO", "COO", "CTO", "CMO",
    "Personal Assistant", "Executive Assistant", "PA to CEO", "EA to Director",
    "Head of Sales", "Head of Marketing", "Head of Engineering", "VP Engineering", "VP Sales",
    "Head of Product", "Head of HR", "Department Head", "Head of Department"
]

# --- DATABASE HELPER FUNCTIONS ---
def init_db():
    os.makedirs(DATA_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_NAME) # Use DB_NAME from .env
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP ) ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS leads (
            id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL,
            company_input TEXT NOT NULL, lead_name TEXT, lead_email TEXT NOT NULL,
            lead_role TEXT, hunter_data TEXT,
            initial_email_subject TEXT, initial_email_body TEXT,
            initial_email_sent_timestamp TEXT, initial_email_status TEXT DEFAULT 'PENDING',
            initial_email_error TEXT, last_follow_up_type TEXT,
            last_follow_up_timestamp TEXT, follow_up_count INTEGER DEFAULT 0,
            strategyhub_used INTEGER DEFAULT 2, responded INTEGER DEFAULT 0,
            cta_clicked INTEGER DEFAULT 0, next_follow_up_due TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            UNIQUE (user_id, lead_email),
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE ) ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS email_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL,
            lead_id INTEGER NOT NULL, email_type TEXT NOT NULL, subject TEXT,
            body TEXT, status TEXT NOT NULL, error_message TEXT,
            timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
            FOREIGN KEY (lead_id) REFERENCES leads (id) ON DELETE CASCADE ) ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS tracking_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type TEXT NOT NULL, -- 'open' or 'click'
            lead_id INTEGER NOT NULL,
            email_log_id INTEGER NOT NULL, -- References email_logs.id
            timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
            ip_address TEXT,
            user_agent TEXT,
            target_url TEXT, -- For click events, stores the URL that was clicked
            FOREIGN KEY (lead_id) REFERENCES leads (id) ON DELETE CASCADE,
            FOREIGN KEY (email_log_id) REFERENCES email_logs (id) ON DELETE CASCADE
        )
    ''')
    conn.commit()
    conn.close()

def get_db_connection():
    conn = sqlite3.connect(DB_NAME) # Use DB_NAME from .env
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

# --- CSV EXPORT FUNCTIONS ---
def get_user_data_dir(user_id):
    return os.path.join(DATA_DIR, f"user_{user_id}")

def update_user_csv(user_id):
    if not user_id:
        return
    user_dir = get_user_data_dir(user_id)
    os.makedirs(user_dir, exist_ok=True)
    conn = get_db_connection()
    try:
        leads_df = pd.read_sql_query(f"SELECT * FROM leads WHERE user_id = {user_id}", conn)
        if not leads_df.empty:
            strategyhub_map = {0: "No", 1: "Yes", 2: "Unknown", 3: "Paid"}
            cta_clicked_map = {0: "No", 1: "Yes"}
            leads_df['strategyhub_used_text'] = leads_df['strategyhub_used'].map(strategyhub_map).fillna("Unknown")
            leads_df['cta_clicked_text'] = leads_df['cta_clicked'].map(cta_clicked_map).fillna("No")
        leads_df.to_csv(os.path.join(user_dir, "leads.csv"), index=False)

        email_logs_df = pd.read_sql_query(f"SELECT * FROM email_logs WHERE user_id = {user_id}", conn)
        email_logs_df.to_csv(os.path.join(user_dir, "email_logs.csv"), index=False)

        # Export tracking events
        tracking_events_df = pd.read_sql_query(f"""
            SELECT te.id as event_id, te.event_type, te.lead_id, l.lead_email,
                   te.email_log_id, el.subject as email_subject,
                   te.timestamp, te.ip_address, te.user_agent, te.target_url
            FROM tracking_events te
            JOIN leads l ON te.lead_id = l.id
            JOIN email_logs el ON te.email_log_id = el.id
            WHERE l.user_id = {user_id}
            ORDER BY te.timestamp DESC
        """, conn)
        tracking_events_df.to_csv(os.path.join(user_dir, "tracking_events.csv"), index=False)

    except Exception as e:
        st.error(f"Error updating CSVs for user {user_id}: {e}")
    finally:
        conn.close()

# --- USER AUTHENTICATION ---
def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def check_password(password, hashed):
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

def register_user(username, email, password):
    if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        st.error("Invalid email format.")
        return None
    if len(password) < 6:
        st.error("Password must be at least 6 characters long.")
        return None

    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        hashed_pw = hash_password(password)
        cursor.execute("INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
                       (username, email, hashed_pw))
        user_id = cursor.lastrowid
        conn.commit()
        os.makedirs(get_user_data_dir(user_id), exist_ok=True)
        update_user_csv(user_id)
        st.success("Registration successful! Please log in.")
        return user_id
    except sqlite3.IntegrityError:
        st.error("Username or email already exists.")
        return None
    finally:
        conn.close()

def login_user(email, password):
    conn = get_db_connection()
    user_data = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
    conn.close()
    if user_data and check_password(password, user_data['password_hash']):
        st.session_state.user = {"id": user_data['id'], "username": user_data['username'], "email": user_data['email']}
        init_mcp()
        update_user_csv(user_data['id'])
        return True
    st.error("Invalid email or password.")
    return False

def delete_user_account(user_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
        conn.commit()
        user_dir = get_user_data_dir(user_id)
        if os.path.exists(user_dir):
            shutil.rmtree(user_dir)

        ui_related_keys = [k for k in st.session_state if k.startswith(('fu_subj_', 'fu_body_', 'edit_s_', 'edit_b_', 'send_s_', 'send_b_', 'compose_s_', 'compose_b_', 'pending_', 'lead_id_for_'))]
        core_session_keys = ['user', 'mcp', 'current_page', 'confirm_delete_account']
        keys_to_delete = core_session_keys + ui_related_keys

        for key in keys_to_delete:
            if key in st.session_state:
                del st.session_state[key]
        st.success("Account deleted successfully. You have been logged out.")
        return True
    except Exception as e:
        st.error(f"Error deleting account: {e}")
        return False
    finally:
        conn.close()


# --- LEAD & EMAIL DB FUNCTIONS (User-Specific) ---
def add_lead_to_db(user_id, mcp_lead_data):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute('''
            INSERT INTO leads (user_id, company_input, lead_name, lead_email, lead_role, hunter_data, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (user_id, mcp_lead_data.get('company_input'), mcp_lead_data.get('name'),
              mcp_lead_data.get('email'), mcp_lead_data.get('role'),
              json.dumps(mcp_lead_data.get('hunter_raw')),
              datetime.now().isoformat()))
        lead_id = cursor.lastrowid
        conn.commit()
        update_user_csv(user_id)
        return lead_id
    except sqlite3.IntegrityError:
        st.toast(f"Lead with email {mcp_lead_data.get('email')} already exists for your account.", icon="⚠️")
        existing_lead = conn.execute("SELECT id FROM leads WHERE user_id = ? AND lead_email = ?", (user_id, mcp_lead_data.get('email'))).fetchone()
        return existing_lead['id'] if existing_lead else None
    finally:
        conn.close()

def update_lead_email_draft(user_id, lead_id, subject, body):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE leads SET initial_email_subject = ?, initial_email_body = ?, initial_email_status = 'DRAFTED' WHERE id = ? AND user_id = ?",
                   (subject, body, lead_id, user_id))
    conn.commit()
    conn.close()
    update_user_csv(user_id)

def update_lead_initial_email_sent_status(user_id, lead_id, status, error=None):
    conn = get_db_connection()
    cursor = conn.cursor()
    now_iso = datetime.now().isoformat()
    if status == "SENT":
        cursor.execute("UPDATE leads SET initial_email_sent_timestamp = ?, initial_email_status = ?, initial_email_error = NULL, next_follow_up_due = datetime(?, '+3 days') WHERE id = ? AND user_id = ?",
                       (now_iso, status, now_iso, lead_id, user_id))
    else:
        cursor.execute("UPDATE leads SET initial_email_status = ?, initial_email_error = ? WHERE id = ? AND user_id = ?",
                       (status, error, lead_id, user_id))
    conn.commit()
    conn.close()
    update_user_csv(user_id)

def insert_email_log_for_tracking(user_id, lead_id, email_type, subject, body, status, error=None):
    """
    Inserts an email log entry and returns its ID. This is crucial for tracking events.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO email_logs (user_id, lead_id, email_type, subject, body, status, error_message, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                   (user_id, lead_id, email_type, subject, body, status, error, datetime.now().isoformat()))
    email_log_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return email_log_id

def update_email_log_status_and_body(email_log_id, status, body=None, error_message=None):
    """
    Updates the status, body, and error message of an existing email_log entry.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    if body and error_message:
        cursor.execute("UPDATE email_logs SET status = ?, body = ?, error_message = ? WHERE id = ?", (status, body, error_message, email_log_id))
    elif body:
        cursor.execute("UPDATE email_logs SET status = ?, body = ?, error_message = NULL WHERE id = ?", (status, body, email_log_id))
    elif error_message:
        cursor.execute("UPDATE email_logs SET status = ?, error_message = ? WHERE id = ?", (status, error_message, email_log_id))
    else:
        cursor.execute("UPDATE email_logs SET status = ? WHERE id = ?", (status, email_log_id))
    conn.commit()
    conn.close()


def update_follow_up_db_status(user_id, lead_id, follow_up_type, status):
    conn = get_db_connection()
    cursor = conn.cursor()
    now_iso = datetime.now().isoformat()
    if status != "SENT":
        conn.close()
        return

    next_due_interval = ""
    if follow_up_type == 'VISIT_PROMO_DAY3':
        next_due_interval = '+2 days'
    elif follow_up_type == 'PAYMENT_PROMO_DAY5':
        next_due_interval = '+2 days'

    if next_due_interval:
        sql = f"UPDATE leads SET last_follow_up_type = ?, last_follow_up_timestamp = ?, follow_up_count = follow_up_count + 1, next_follow_up_due = datetime(?, '{next_due_interval}') WHERE id = ? AND user_id = ?"
        params = (follow_up_type, now_iso, now_iso, lead_id, user_id)
    else:
        sql = "UPDATE leads SET last_follow_up_type = ?, last_follow_up_timestamp = ?, follow_up_count = follow_up_count + 1, next_follow_up_due = NULL WHERE id = ? AND user_id = ?"
        params = (follow_up_type, now_iso, lead_id, user_id)
    cursor.execute(sql, params)
    conn.commit()
    conn.close()
    update_user_csv(user_id)

def get_all_leads(user_id):
    conn = get_db_connection()
    leads_data = conn.execute("SELECT * FROM leads WHERE user_id = ? ORDER BY created_at DESC", (user_id,)).fetchall()
    conn.close()
    return [dict(row) for row in leads_data]

def get_lead_by_id(user_id, lead_id):
    conn = get_db_connection()
    lead_data = conn.execute("SELECT * FROM leads WHERE id = ? AND user_id = ?", (lead_id, user_id)).fetchone()
    conn.close()
    return dict(lead_data) if lead_data else None

def set_lead_responded_status(user_id, lead_id, responded_status=1):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE leads SET responded = ?, next_follow_up_due = CASE WHEN ? = 1 THEN NULL ELSE next_follow_up_due END WHERE id = ? AND user_id = ?",
                   (responded_status, responded_status, lead_id, user_id))
    conn.commit()
    conn.close()
    update_user_csv(user_id)
    st.toast(f"Lead {lead_id} marked as {'responded' if responded_status else 'not responded'}.", icon="💬")

def set_strategyhub_used_status(user_id, lead_id, used_status):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE leads SET strategyhub_used = ?, next_follow_up_due = CASE WHEN ? = 3 THEN NULL ELSE next_follow_up_due END WHERE id = ? AND user_id = ?",
                   (used_status, used_status, lead_id, user_id))
    conn.commit()
    conn.close()
    update_user_csv(user_id)
    status_text = {0: "No", 1: "Yes", 2: "Unknown", 3: "Paid"}.get(used_status, "Unknown")
    st.toast(f"Lead {lead_id} StrategyHub usage set to {status_text}.", icon="🛠️")

def update_lead_details_in_db(user_id, lead_id, name, email, role, company_input):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        # Check for email conflict first, excluding the current lead
        existing_email_check = cursor.execute("SELECT id FROM leads WHERE user_id = ? AND lead_email = ? AND id != ?", (user_id, email, lead_id)).fetchone()
        if existing_email_check:
            st.error(f"Error: A lead with email '{email}' already exists for your account.")
            return False

        cursor.execute('''
            UPDATE leads
            SET lead_name = ?, lead_email = ?, lead_role = ?, company_input = ?
            WHERE id = ? AND user_id = ?
        ''', (name, email, role, company_input, lead_id, user_id))
        conn.commit()
        update_user_csv(user_id)
        st.toast(f"Lead ID {lead_id} updated successfully.", icon="✏️")
        return True
    except sqlite3.Error as e:
        st.error(f"Error updating lead {lead_id}: {e}")
        return False
    finally:
        conn.close()

def delete_lead_from_db(user_id, lead_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        # The 'ON DELETE CASCADE' in your schema handles associated email_logs and tracking_events
        cursor.execute("DELETE FROM leads WHERE id = ? AND user_id = ?", (lead_id, user_id))
        conn.commit()
        update_user_csv(user_id)
        st.toast(f"Lead ID {lead_id} deleted successfully.", icon="🗑️")
        return True
    except sqlite3.Error as e:
        st.error(f"Error deleting lead {lead_id}: {e}")
        return False
    finally:
        conn.close()

# --- CUSTOM TRACKING HELPER FUNCTIONS ---
def generate_custom_tracked_link(email_log_id, original_url):
    """
    Generates a link that first hits our FastAPI tracker before redirecting.
    """
    if not BASE_TRACKING_URL:
        # Fallback to original URL if tracking is not configured
        return original_url
    encoded_original_url = quote_plus(original_url)
    return f"{BASE_TRACKING_URL}/track/click/{email_log_id}?target_url={encoded_original_url}"

def generate_open_tracking_pixel_html(email_log_id):
    """
    Generates the HTML for a 1x1 tracking pixel.
    """
    if not BASE_TRACKING_URL:
        return ""
    return f'<img src="{BASE_TRACKING_URL}/track/open/{email_log_id}" width="1" height="1" border="0" alt="" style="height:1px !important;width:1px !important;border-width:0 !important;margin-top:0 !important;margin-bottom:0 !important;margin-right:0 !important;margin-left:0 !important;padding-top:0 !important;padding-bottom:0 !important;padding-right:0 !important;padding-left:0 !important;">'


# --- MCP ---
def init_mcp():
    if 'mcp' not in st.session_state:
        st.session_state.mcp = {}

    st.session_state.mcp.setdefault("company_input", None)
    st.session_state.mcp.setdefault("leads_found_this_session", [])
    st.session_state.mcp.setdefault("email_drafts_this_session", {})
    st.session_state.mcp.setdefault("current_step", "input")

# --- HELPER ---
def extract_domain(input_str):
    if not input_str: return None
    input_str = input_str.strip().lower()
    if not input_str.startswith(('http://', 'https://')):
        input_str = 'https://' + input_str # Default to https
    try:
        parsed_url = urlparse(input_str)
        domain = parsed_url.netloc
        if domain.startswith('www.'):
            domain = domain[4:]
        return domain.split(':')[0] if domain else None
    except Exception:
        return None

def generate_unsubscribe_link(lead_email):
    encoded_email = quote_plus(lead_email)
    return f"mailto:{SENDER_EMAIL}?subject=Unsubscribe&body=Please unsubscribe {encoded_email}"


# --- AGENT 1: Lead Finder (Hunter.io Integration) ---
def agent_lead_finder(user_id, user_input_str):
    st.session_state.mcp["leads_found_this_session"] = []
    st.session_state.mcp["email_drafts_this_session"] = {}
    st.session_state.mcp["current_step"] = "input"

    if not HUNTER_API_KEY:
        st.error("Hunter.io API Key is missing.")
        return False

    st.session_state.mcp["company_input"] = user_input_str
    domain_to_search = extract_domain(user_input_str)
    search_payload = {}
    search_type_message = ""
    hunter_api_url = "https://api.hunter.io/v2/domain-search"

    if domain_to_search:
        st.info(f"Attempting Hunter.io domain search for: {domain_to_search}")
        search_payload = {'domain': domain_to_search, 'api_key': HUNTER_API_KEY}
        search_type_message = f"domain '{domain_to_search}'"
    else:
        st.info(f"No clear domain. Attempting Hunter.io company name search: {user_input_str}")
        search_payload = {'company': user_input_str, 'api_key': HUNTER_API_KEY}
        search_type_message = f"company name '{user_input_str}'"

    try:
        response = requests.get(hunter_api_url, params=search_payload, timeout=20)
        if response.status_code != 200:
            st.error(f"Hunter.io API error (Status {response.status_code}) for {search_type_message}.")
            try:
                error_data = response.json()
                st.error(f"Hunter.io Details: {error_data.get('errors', [{}])[0].get('details', response.text)}")
            except requests.exceptions.JSONDecodeError: st.text(f"Raw error: {response.text}")
            return False

        data = response.json().get('data', {})
        hunter_emails_raw = data.get('emails', [])
        actual_company_name = data.get('organization', user_input_str)
        actual_domain_found = data.get('domain', domain_to_search if domain_to_search else "N/A")

        if not hunter_emails_raw:
            st.warning(f"No emails found by Hunter.io for {search_type_message}. Company: '{actual_company_name}', Domain: '{actual_domain_found}'.")
            return False

        st.success(f"Hunter.io found {len(hunter_emails_raw)} email(s) for {search_type_message}. Company: '{actual_company_name}', Domain: '{actual_domain_found}'.")
        processed_leads_for_mcp = []

        with st.expander(f"All Emails Found ({len(hunter_emails_raw)}) - Processing...", expanded=True):
            display_all_found_list = []
            for email_info_item in hunter_emails_raw:
                email_val = email_info_item.get('value')
                if not email_val: continue

                name_val_parts = [email_info_item.get('first_name'), email_info_item.get('last_name')]
                name_val = " ".join(filter(None, name_val_parts)).strip() or "Valued Professional"
                role_val = email_info_item.get('position', 'N/A')
                if not isinstance(role_val, str): role_val = "N/A"
                is_target_role = any(designation.lower() in role_val.lower() for designation in TARGET_DESIGNATIONS)

                display_all_found_list.append({
                    "Email": email_val, "Name": name_val, "Role": role_val,
                    "Verification": email_info_item.get('verification', {}).get('status', 'N/A'),
                    "Target Role?": "Yes" if is_target_role else "No"
                })
                mcp_formatted_lead_item = {
                    "company_input": actual_company_name, "name": name_val, "email": email_val, "role": role_val,
                    "hunter_raw": email_info_item, # Storing raw Hunter data
                    "verification_status": email_info_item.get('verification', {}).get('status', 'N/A'),
                    "is_target_role": is_target_role,
                }
                processed_leads_for_mcp.append(mcp_formatted_lead_item)
            if display_all_found_list: st.dataframe(pd.DataFrame(display_all_found_list))
            else: st.info("No valid email entries from Hunter.io response.")

        if not processed_leads_for_mcp:
            st.warning(f"No leads processed from {len(hunter_emails_raw)} Hunter.io emails for {search_type_message}.")
            return False

        st.session_state.mcp["leads_found_this_session"] = processed_leads_for_mcp
        st.session_state.mcp["current_step"] = "leads_found"
        st.success(f"Processed {len(processed_leads_for_mcp)} emails from Hunter.io for '{actual_company_name}'.")
        return True
    except requests.exceptions.Timeout: st.error(f"Hunter.io request timed out for {search_type_message}.")
    except requests.exceptions.RequestException as e_req: st.error(f"Network error with Hunter.io: {e_req}")
    except json.JSONDecodeError as e_json:
        st.error(f"JSON decode error from Hunter.io: {e_json}")
        if 'response' in locals() and response: st.text(f"Raw response snippet: {response.text[:500]}")
    except Exception as e_gen:
        st.error(f"Unexpected error in Lead Finder: {e_gen}")
        st.error(traceback.format_exc())
    return False


# --- AGENT 2: Email Composer ---
def agent_email_composer(user_id):
    if not st.session_state.mcp.get("leads_found_this_session"):
        st.info("No new leads this session. Please find leads first.")
        return False

    leads_to_compose_for_db_objects = []
    for lead_data_mcp in st.session_state.mcp["leads_found_this_session"]:
        lead_id = add_lead_to_db(user_id, lead_data_mcp)
        if lead_id:
            db_lead = get_lead_by_id(user_id, lead_id)
            if db_lead and db_lead['initial_email_status'] in ['PENDING', 'DRAFTED']:
                leads_to_compose_for_db_objects.append(db_lead)
            elif db_lead: st.info(f"Skipping composition for {db_lead['lead_email']} (status {db_lead['initial_email_status']}).")
        else: st.warning(f"Could not add/retrieve lead {lead_data_mcp.get('email')}. Skipping.")

    if not leads_to_compose_for_db_objects:
        st.info("All found leads processed or couldn't be added. No new emails to compose.")
        st.session_state.mcp["leads_found_this_session"] = []
        return False

    st.session_state.mcp["email_drafts_this_session"] = {}
    progress_bar = st.progress(0)
    total_leads_to_compose = len(leads_to_compose_for_db_objects)
    # The unsubscribe link will be a mailto, but if we wanted to track it, it would be wrapped too.
    email_footer_template = f"\n\n---\nTo unsubscribe, click here: {{UNSUBSCRIBE_LINK_PLACEHOLDER}}"
    email_json_str = ""
    strategyhub_description_for_gemini = """
    StrategyHub.in empowers businesses with AI-generated strategic evaluation reports across all key functions. By answering a detailed questionnaire, companies receive a custom diagnostic report.

    **A sample of this comprehensive report, which is ATTACHED to this email, typically includes:**
    1.  **Executive Summary:** A top-level overview of key findings and strategic imperatives.
    2.  **SWOT Analysis:** Identifying strengths, weaknesses, opportunities, and threats.
    3.  **Department-wise Performance Breakdown:** In-depth analysis for:
        *   Marketing
        *   Strategy
        *   Operations
        *   Human Resources
        *   Finance
        *   Legal
        *   Technology
    4.  **Benchmarking:** Comparison against industry peers (where applicable).
    5.  **Immediate Next-Step Recommendations:** Actionable insights to improve growth, profitability, and investor confidence.

    StrategyHub.in helps startups, SMEs, and mid-size enterprises identify critical gaps, uncover hidden opportunities, and build a solid, data-driven roadmap for execution. The attached demo report will give you a clear idea of the depth and value we provide.
    """

    for i, lead in enumerate(leads_to_compose_for_db_objects):
        company_name = lead.get("company_input", "their company")
        lead_name = lead.get("lead_name", "Valued Professional")
        lead_role = lead.get("lead_role", "N/A")
        prompt = f"""
        You are an expert B2B outreach specialist. Your goal is to compose a professional, personalized, and urgent-toned email for StrategyHub.in outreach.
        **About StrategyHub.in (Understand this deeply and really refer to the ATTACHED sample report when explaining value):**
        {strategyhub_description_for_gemini}

        **Recipient Details:**
        - Name: {lead_name} - Role/Designation: {lead_role} - Company: {company_name}

        **Your Task:**
        1. Compose an email from "Rishabh, StrategyHub / Strategic Execution Consultants".
        2. **Crucially, tailor the message to the recipient's role ({lead_role}).**
           - Explain how reviewing the **attached sample StrategyHub.in report** will specifically help a '{lead_role}' at '{company_name}' understand their potential strategic gaps and opportunities (e.g., for a CEO: overall strategic health; for a Head of Marketing: marketing effectiveness and alignment, etc., referencing sections like SWOT or departmental analysis from the attached report).
           - Emphasize that the attached report is a demo of what they can get for their own company.
        3. Concise email (max 3-4 short paragraphs), create value, and encourage them to check the attachment.
        4. **CTA:** Encourage a visit to StrategyHub.in to learn more after they've seen the value in the attached demo. Use `{{{{MAIN_CTA_TRACKED_LINK_PLACEHOLDER}}}}`.
        5. **Footer:** Include *exactly*: "{email_footer_template.strip()}" (Replace `{{{{UNSUBSCRIBE_LINK_PLACEHOLDER}}}}` with `[UNSUBSCRIBE_LINK]`)
        6. **Output:** JSON: {{"subject": "Relevant Subject for {lead_role} (mentioning Report/Insights)", "body": "Personalized body, referencing the attached sample report and {{MAIN_CTA_TRACKED_LINK_PLACEHOLDER}}..."}}
        """
        draft_content = None
        if gemini_model:
            try:
                response = gemini_model.generate_content(prompt)
                email_json_str = response.text.strip()
                match = re.search(r"```json\s*([\s\S]+?)\s*```", email_json_str, re.DOTALL)
                clean_json_str = match.group(1).strip() if match else email_json_str
                json_start = clean_json_str.find('{'); json_end = clean_json_str.rfind('}')
                if json_start != -1 and json_end != -1 and json_end > json_start:
                    clean_json_str = clean_json_str[json_start : json_end+1]
                else: raise json.JSONDecodeError("No valid JSON object", clean_json_str, 0)
                email_content_val = json.loads(clean_json_str)
                subject = email_content_val.get("subject", f"Strategic Insights & Sample Report for {company_name}")
                body_text = email_content_val.get("body", f"Error generating body for {lead_name}.")
                if "attached sample report" not in body_text.lower() and "attachment" not in body_text.lower():
                    body_text = "I've attached a sample StrategyHub.in report to give you a clearer picture of the strategic insights we offer.\n\n" + body_text
                if "{{MAIN_CTA_TRACKED_LINK_PLACEHOLDER}}" not in body_text:
                    body_text += f"\n\nLearn more after reviewing the report: {{MAIN_CTA_TRACKED_LINK_PLACEHOLDER}}"
                draft_content = {"subject": subject, "body": body_text}
            except Exception as e: st.error(f"Gemini error for {lead['lead_email']}: {e}. Raw: '{email_json_str}'")
        if not draft_content:
            subject = f"Unlock Strategic Insights for {company_name} with StrategyHub.in (Sample Report Attached)"
            body_text = f"Dear {lead_name},\n\nAs a {lead_role} at {company_name}, navigating strategic decisions is paramount. StrategyHub.in offers AI-powered diagnostic reports to provide comprehensive business evaluations, similar to the sample report I've attached to this email for your review.\n\nThis sample will show you how we break down complex business functions into actionable insights.\n\nAfter reviewing the attachment, discover more here: {{MAIN_CTA_TRACKED_LINK_PLACEHOLDER}}\n\nBest regards,\nRishabh\nStrategyHub{email_footer_template.replace('{{UNSUBSCRIBE_LINK_PLACEHOLDER}}', '[UNSUBSCRIBE_LINK_FALLBACK]')}\n\n[Template: AI failed. Demo report attached.]"
            draft_content = {"subject": subject, "body": body_text}

        st.session_state.mcp["email_drafts_this_session"][str(lead['id'])] = draft_content
        update_lead_email_draft(user_id, lead['id'], draft_content["subject"], draft_content["body"])
        progress_bar.progress((i + 1) / total_leads_to_compose, text=f"Drafting for {lead['lead_email']}")

    st.session_state.mcp["current_step"] = "emails_drafted"
    st.session_state.mcp["leads_found_this_session"] = []
    st.success(f"Email drafts composed for {total_leads_to_compose} leads.")
    return True

# --- AGENT 3: Email Sender ---
def agent_email_sender(user_id, lead_id, subject, body, email_log_type="INITIAL"):
    if not all([SMTP_SERVER_CONFIG, SMTP_PORT_CONFIG, SMTP_USERNAME_CONFIG, SMTP_PASSWORD_CONFIG, SENDER_EMAIL]):
        err_msg = "SMTP settings incomplete."
        st.error(err_msg)
        # We need an email_log_id even for failed sends if we want to track the attempt
        email_log_db_id = insert_email_log_for_tracking(user_id, lead_id, email_log_type, subject, body, "FAILED", err_msg)
        update_lead_initial_email_sent_status(user_id, lead_id, "FAILED", err_msg)
        return False

    if not BASE_TRACKING_URL:
        err_msg = "BASE_TRACKING_URL not configured. Cannot send tracked emails."
        st.error(err_msg)
        email_log_db_id = insert_email_log_for_tracking(user_id, lead_id, email_log_type, subject, body, "FAILED", err_msg)
        update_lead_initial_email_sent_status(user_id, lead_id, "FAILED", err_msg)
        return False


    lead = get_lead_by_id(user_id, lead_id)
    if not lead: st.error(f"Lead ID {lead_id} not found."); return False
    recipient_email = lead['lead_email']

    # --- Step 1: Log the email attempt FIRST to get an email_log_id ---
    # This preliminary log uses the original body/subject. It will be updated later.
    email_log_db_id = insert_email_log_for_tracking(user_id, lead_id, email_log_type, subject, body, 'PENDING_SEND')
    if not email_log_db_id:
        st.error("Failed to create initial email log entry for tracking purposes.")
        return False

    # --- Step 2: Prepare email content with tracking links and pixel ---
    main_cta_target_url = STRATEGYHUB_URL
    final_main_cta_link = generate_custom_tracked_link(email_log_db_id, main_cta_target_url)

    # Replace placeholders in the body with actual tracked links
    body_with_actual_links = body.replace("{{MAIN_CTA_TRACKED_LINK_PLACEHOLDER}}", final_main_cta_link)

    actual_unsubscribe_url = generate_unsubscribe_link(recipient_email) # mailto link
    body_with_actual_links = re.sub(
        r"\{\{UNSUBSCRIBE_LINK_PLACEHOLDER\}\}|\[UNSUBSCRIBE_LINK(?:_FALLBACK)?\]",
        actual_unsubscribe_url, body_with_actual_links, flags=re.IGNORECASE
    )

    if "{{DEMO_LINK_PLACEHOLDER}}" in body_with_actual_links:
        demo_target_url = st.session_state.get("demo_link_input", STRATEGYHUB_URL + "/demo")
        final_demo_link = generate_custom_tracked_link(email_log_db_id, demo_target_url)
        body_with_actual_links = body_with_actual_links.replace("{{DEMO_LINK_PLACEHOLDER}}", final_demo_link)

    # Generate HTML body version with tracking pixel
    # This is a simple conversion; a real-world scenario might use a robust HTML templating library
    html_body_with_tracking = f"""
    <html>
        <body>
            <p>{body_with_actual_links.replace('\\n', '<br>')}</p>
            {generate_open_tracking_pixel_html(email_log_db_id)}
        </body>
    </html>
    """
    # Simple replacement to make links clickable in HTML version
    html_body_with_tracking = html_body_with_tracking.replace(final_main_cta_link, f'<a href="{final_main_cta_link}" target="_blank">{final_main_cta_link}</a>')
    if "{{DEMO_LINK_PLACEHOLDER}}" in body and "{{DEMO_LINK_PLACEHOLDER}}" not in body_with_actual_links: # If demo link was processed
         html_body_with_tracking = html_body_with_tracking.replace(final_demo_link, f'<a href="{final_demo_link}" target="_blank">{final_demo_link}</a>')
    html_body_with_tracking = html_body_with_tracking.replace(actual_unsubscribe_url, f'<a href="{actual_unsubscribe_url}">{actual_unsubscribe_url}</a>')


    # --- Step 3: Construct the MIMEMultipart message ---
    msg = MIMEMultipart('alternative') # Use 'alternative' for plain text and HTML
    msg['Subject'] = subject
    msg['From'] = SENDER_EMAIL
    msg['To'] = recipient_email
    msg['Reply-To'] = SENDER_EMAIL

    # Attach parts in order: plain text first, then HTML
    msg.attach(MIMEText(body_with_actual_links, 'plain', 'utf-8'))
    msg.attach(MIMEText(html_body_with_tracking, 'html', 'utf-8'))

    attachment_attached = False
    final_email_body_for_log = body_with_actual_links # Initialize for logging the actual content sent

    if os.path.exists(DEMO_REPORT_PDF_PATH):
        try:
            with open(DEMO_REPORT_PDF_PATH, "rb") as attachment_file:
                part = MIMEApplication(
                    attachment_file.read(),
                    Name=os.path.basename(DEMO_REPORT_PDF_FILENAME)
                )
            part['Content-Disposition'] = f'attachment; filename="{os.path.basename(DEMO_REPORT_PDF_FILENAME)}"'
            msg.attach(part)
            attachment_attached = True
            st.info(f"Demo report PDF ({DEMO_REPORT_PDF_FILENAME}) prepared for attachment to {recipient_email}.")
        except Exception as e_attach:
            st.error(f"Failed to read or attach PDF '{DEMO_REPORT_PDF_FILENAME}' for {recipient_email}: {e_attach}")
            # Email will be sent without attachment
    else:
        st.warning(f"Demo report PDF not found at '{DEMO_REPORT_PDF_PATH}'. Email to {recipient_email} will be sent without it.")

    error_msg_send = ""
    try:
        smtp_port_int = int(SMTP_PORT_CONFIG)
        with smtplib.SMTP(SMTP_SERVER_CONFIG, smtp_port_int, timeout=30) as server:
            server.ehlo()
            if smtp_port_int == 587: server.starttls(); server.ehlo()
            server.login(SMTP_USERNAME_CONFIG, SMTP_PASSWORD_CONFIG)
            server.sendmail(SENDER_EMAIL, recipient_email, msg.as_string())

        if attachment_attached:
            final_email_body_for_log += f"\n\n[Attachment: {DEMO_REPORT_PDF_FILENAME} was sent]"
        elif not os.path.exists(DEMO_REPORT_PDF_PATH):
             final_email_body_for_log += f"\n\n[Attachment: {DEMO_REPORT_PDF_FILENAME} was NOT found and NOT sent]"
        else: # Attachment failed to read/process but file exists
             final_email_body_for_log += f"\n\n[Attachment: {DEMO_REPORT_PDF_FILENAME} FAILED to attach and was NOT sent (file exists but error during processing)]"

        # Update the email_logs entry with final status and body
        update_email_log_status_and_body(email_log_db_id, "SENT", final_email_body_for_log)
        update_user_csv(user_id) # Update CSV after successful send

        if email_log_type == "INITIAL": update_lead_initial_email_sent_status(user_id, lead_id, "SENT")
        else: update_follow_up_db_status(user_id, lead_id, email_log_type, "SENT")
        st.toast(f"Email ({email_log_type}) {'with demo report ' if attachment_attached else ''}sent to {recipient_email}", icon="✅")
        return True
    except smtplib.SMTPAuthenticationError: error_msg_send = "SMTP Auth Error."
    except smtplib.SMTPServerDisconnected: error_msg_send = "SMTP Server Disconnected."
    except smtplib.SMTPException as e_smtp: error_msg_send = f"SMTP error: {e_smtp}"
    except Exception as e_general: error_msg_send = f"General error sending: {e_general}"; st.error(traceback.format_exc())

    # Update log body for failure case
    email_body_for_log_on_fail = body_with_actual_links
    if attachment_attached: # This means it was prepared but sending failed
        email_body_for_log_on_fail += f"\n\n[Attachment: {DEMO_REPORT_PDF_FILENAME} was prepared but email FAILED to send]"
    elif not os.path.exists(DEMO_REPORT_PDF_PATH):
        email_body_for_log_on_fail += f"\n\n[Attachment: {DEMO_REPORT_PDF_FILENAME} was NOT found and NOT sent (email also FAILED)]"
    else: # File exists but attachment process failed
        email_body_for_log_on_fail += f"\n\n[Attachment: {DEMO_REPORT_PDF_FILENAME} FAILED to attach and was NOT sent (email also FAILED)]"

    if error_msg_send: st.error(f"For {recipient_email}: {error_msg_send}")

    # Update the email_logs entry with final status and error
    update_email_log_status_and_body(email_log_db_id, "FAILED", email_body_for_log_on_fail, error_msg_send)
    update_user_csv(user_id) # Update CSV after failed send

    if email_log_type == "INITIAL": update_lead_initial_email_sent_status(user_id, lead_id, "FAILED", error_msg_send)
    return False

# --- AGENT 5: Follow-up Management ---
def agent_manage_follow_ups(user_id):
    if not gemini_model: st.error("Gemini model needed for follow-ups."); return
    all_db_leads = get_all_leads(user_id)
    now = datetime.now()
    leads_for_follow_up_display = []
    follow_up_schedule = {0: "VISIT_PROMO_DAY3", 1: "PAYMENT_PROMO_DAY5", 2: "UPGRADE_PROMO_DAY7"}
    email_json_str_fu = ""
    # Slightly shorter description for follow-ups, assuming initial email had the full detail
    strategyhub_description_for_gemini_fu = """
    StrategyHub.in provides AI-generated strategic evaluation reports helping businesses identify gaps, uncover opportunities, and build solid execution roadmaps.
    Recall the comprehensive sample report structure (Exec Summary, SWOT, Departmental Analysis, etc.) shared previously.
    Our reports aim to improve growth, profitability, and investor confidence.
    """

    for lead in all_db_leads:
        if lead['responded'] or lead['strategyhub_used'] == 3 or lead['initial_email_status'] != 'SENT' or lead['follow_up_count'] >= len(follow_up_schedule):
            continue
        designated_follow_up_type = follow_up_schedule.get(lead['follow_up_count'])
        if not designated_follow_up_type: continue
        is_due = False
        if lead['next_follow_up_due']:
            try:
                due_dt = datetime.fromisoformat(lead['next_follow_up_due'].split('.')[0])
                if now >= due_dt: is_due = True
            except ValueError: st.warning(f"Invalid date for lead {lead['id']}"); continue
        if is_due: leads_for_follow_up_display.append({"lead": lead, "email_log_type": designated_follow_up_type})

    if not leads_for_follow_up_display: st.info("No leads currently due for follow-up."); return
    st.subheader(f"Leads Due for Follow-up ({len(leads_for_follow_up_display)})")
    email_footer_template = f"\n\n---\nTo unsubscribe, click here: {{UNSUBSCRIBE_LINK_PLACEHOLDER}}"

    for item_idx, item_data in enumerate(leads_for_follow_up_display):
        lead = item_data['lead']; current_email_log_type = item_data['email_log_type']
        prompt_context_detail = f"This is a {current_email_log_type.replace('_', ' ')} follow-up. "
        offer_details = ""
        # Note: Follow-up emails will NOT re-attach the PDF by default, to avoid spamming.
        # The prompt can reference the "previously shared sample report".
        if lead['cta_clicked'] == 1:
            prompt_context_detail += f"Lead CLICKED a link from our previous email (which included a sample report). Role: {lead.get('lead_role', 'N/A')}. "
            if lead['strategyhub_used'] == 1:
                prompt_context_detail += "Used free/trial. Goal: UPGRADE. Highlight premium benefits related to insights from the sample report."
                if current_email_log_type in ["PAYMENT_PROMO_DAY5", "UPGRADE_PROMO_DAY7"]:
                    offer_details = f"Upgrade by {(datetime.now() + timedelta(days=5)).strftime('%B %d')} for [Premium Feature/Discount]."
            else:
                prompt_context_detail += "Not 'Used'/'Paid'. Goal: Convert click to usage/subscription. Remind them of the value shown in the sample report."
                if current_email_log_type == "PAYMENT_PROMO_DAY5":
                     offer_details = f"Start your strategic journey by {(datetime.now() + timedelta(days=3)).strftime('%B %d')}."
        elif lead['strategyhub_used'] == 1:
            prompt_context_detail += f"Used free/trial, no recent click. Role: {lead.get('lead_role', 'N/A')}. Goal: Re-engage, upgrade, referencing the depth of our sample report."
            if current_email_log_type in ["PAYMENT_PROMO_DAY5", "UPGRADE_PROMO_DAY7"]:
                 offer_details = f"Unlock advanced insights - offer until {(datetime.now() + timedelta(days=5)).strftime('%B %d')}."
        else: prompt_context_detail += f"No clicks/usage. Role: {lead.get('lead_role', 'N/A')}. Goal: Re-engage, remind them of the value and comprehensive nature of the sample report we shared."
        if offer_details: prompt_context_detail += f"\nOffer/Angle: {offer_details}"

        prompt = f"""
        Compose follow-up for StrategyHub.in. **About StrategyHub.in:** {strategyhub_description_for_gemini_fu}
        To: {lead['lead_name']} ({lead['lead_role']}) at {lead['company_input']}. From: Rishabh, StrategyHub.
        **Lead's Context & Goal:** {prompt_context_detail}
        Craft polite, concise, persuasive follow-up. Remind them of the comprehensive sample report previously shared and its value.
        CTA to StrategyHub.in ({STRATEGYHUB_URL}), use `{{{{MAIN_CTA_TRACKED_LINK_PLACEHOLDER}}}}`.
        Tone: Professional, helpful. Short. Footer: *Exactly*: "{email_footer_template.strip()}" (Replace `{{{{UNSUBSCRIBE_LINK_PLACEHOLDER}}}}` with `[UNSUBSCRIBE_LINK]`).
        Output: JSON {{"subject": "Follow-up Subject", "body": "Follow-up body referencing previously shared insights and {{MAIN_CTA_TRACKED_LINK_PLACEHOLDER}}..."}}
        """
        exp_title = f"Follow-up: {lead['lead_name']} ({current_email_log_type}) - Clicked: {'Y' if lead['cta_clicked'] else 'N'}"
        with st.expander(exp_title):
            st.caption(f"Co: {lead['company_input']}, Role: {lead['lead_role']}, FUs: {lead['follow_up_count']}")
            draft_key_suffix = f"{lead['id']}_{current_email_log_type}_{item_idx}"
            subj_key = f"fu_subj_{draft_key_suffix}"; body_key = f"fu_body_{draft_key_suffix}"
            if subj_key not in st.session_state:
                try:
                    response = gemini_model.generate_content(prompt)
                    email_json_str_fu = response.text.strip()
                    match = re.search(r"```json\s*([\s\S]+?)\s*```", email_json_str_fu, re.DOTALL)
                    clean_json_str = match.group(1).strip() if match else email_json_str_fu
                    json_s = clean_json_str.find('{'); json_e = clean_json_str.rfind('}')
                    if json_s != -1 and json_e != -1 and json_e > json_s: clean_json_str = clean_json_str[json_s : json_e+1]
                    else: raise json.JSONDecodeError("No JSON in follow-up", clean_json_str, 0)
                    content = json.loads(clean_json_str)
                    st.session_state[subj_key] = content.get("subject", f"Following Up: StrategyHub.in & {lead['company_input']}")
                    body_gen = content.get("body", "Error generating follow-up.")
                    if "{{MAIN_CTA_TRACKED_LINK_PLACEHOLDER}}" not in body_gen: body_gen += "\n\nExplore: {{MAIN_CTA_TRACKED_LINK_PLACEHOLDER}}"
                    st.session_state[body_key] = body_gen
                except Exception as e:
                    st.error(f"Follow-up gen error for {lead['lead_email']}: {e}. Raw: '{email_json_str_fu}'")
                    st.session_state[subj_key] = "Review Follow-up - AI Error"
                    st.session_state[body_key] = f"Dear {lead['lead_name']},\n\n[AI Error generating follow-up. Context: {prompt_context_detail} We previously shared a sample report that details our capabilities.]\n\nVisit StrategyHub.in: {{MAIN_CTA_TRACKED_LINK_PLACEHOLDER}}\n\nSincerely,\nRishabh{email_footer_template.replace('{{UNSUBSCRIBE_LINK_PLACEHOLDER}}','[UNSUBSCRIBE_LINK_FALLBACK]')}"
            edited_subject = st.text_input("Subject:", value=st.session_state.get(subj_key, ""), key=f"edit_subj_fu_{draft_key_suffix}")
            edited_body = st.text_area("Body:", value=st.session_state.get(body_key, ""), height=250, key=f"edit_body_fu_{draft_key_suffix}")
            if st.button(f"Send Follow-up ({current_email_log_type}) to {lead['lead_name']}", key=f"send_fu_{draft_key_suffix}"):
                st.session_state[subj_key] = edited_subject; st.session_state[body_key] = edited_body
                if agent_email_sender(st.user['id'], lead['id'], edited_subject, edited_body, email_log_type=current_email_log_type):
                    if subj_key in st.session_state: del st.session_state[subj_key]
                    if body_key in st.session_state: del st.session_state[body_key]
                    st.rerun()

# --- UI LAYOUT AND PAGES ---
def ui_login_register():
    st.title("🚀 AI Lead Outreach Platform")
    st.markdown("Please log in or register to continue.")
    auth_tab1, auth_tab2 = st.tabs(["🔑 Login", "✍️ Register"])
    with auth_tab1:
        st.subheader("Login to Your Account")
        with st.form("login_form"):
            login_email = st.text_input("Email", key="login_email")
            login_password = st.text_input("Password", type="password", key="login_pass")
            if st.form_submit_button("Login"):
                if login_user(login_email, login_password):
                    st.rerun()
    with auth_tab2:
        st.subheader("Create New Account")
        with st.form("register_form"):
            reg_username = st.text_input("Username", key="reg_user")
            reg_email = st.text_input("Email", key="reg_email")
            reg_password = st.text_input("Password", type="password", key="reg_pass")
            reg_password_confirm = st.text_input("Confirm Password", type="password", key="reg_pass_conf")
            if st.form_submit_button("Register"):
                if not all([reg_username, reg_email, reg_password, reg_password_confirm]): st.error("All fields are required.")
                elif reg_password != reg_password_confirm: st.error("Passwords do not match.")
                else: register_user(reg_username, reg_email, reg_password)

def main_app_ui():
    user = st.session_state.user
    st.sidebar.title(f"Welcome, {user['username']}!")
    st.sidebar.markdown("---")
    PAGE_DRAFT_AND_SEND_SESSION = "✍️ Draft & Send Session Emails"
    PAGE_MANAGE_ALL_DRAFTS = "📤 Manage All Drafted Emails"
    page_options = ["🏠 Home", "🔍 Find Leads", PAGE_DRAFT_AND_SEND_SESSION, PAGE_MANAGE_ALL_DRAFTS, "🔄 Follow-ups", "📊 Dashboard", "⚙️ Settings"]
    if 'current_page' not in st.session_state: st.session_state.current_page = "🏠 Home"
    current_page_index = page_options.index(st.session_state.current_page)
    page_selection = st.sidebar.radio("Navigation", page_options, index=current_page_index, key="nav_radio")
    if page_selection != st.session_state.current_page:
        st.session_state.current_page = page_selection
        flow_pages = ["🔍 Find Leads", PAGE_DRAFT_AND_SEND_SESSION, PAGE_MANAGE_ALL_DRAFTS]
        if st.session_state.current_page not in flow_pages and not (st.session_state.current_page == PAGE_MANAGE_ALL_DRAFTS and st.session_state.mcp.get("current_step") == "emails_drafted"):
                 init_mcp()
        st.rerun()
    st.sidebar.markdown("---")
    if st.sidebar.button("Logout", use_container_width=True, type="primary"):
        ui_related_keys = [k for k in st.session_state if k.startswith(('fu_subj_', 'fu_body_', 'edit_s_', 'edit_b_', 'send_s_', 'send_b_', 'compose_s_', 'compose_b_', 'pending_', 'lead_id_for_'))]
        core_session_keys = ['user', 'mcp', 'current_page', 'confirm_delete_account']
        keys_to_del = core_session_keys + ui_related_keys
        for key_del in keys_to_del:
            if key_del in st.session_state: del st.session_state[key_del]
        st.rerun()

    if st.session_state.current_page == "🏠 Home":
        st.title("🚀 AI Lead Outreach Platform - Home")
        st.markdown(f"Hello **{user['username']}**! Streamline your lead outreach. This platform helps you find leads, draft AI-personalized emails (with a sample StrategyHub report attached), send them, and manage follow-ups.")
        st.markdown(f"- **Find Leads:** Discover contacts using Hunter.io.\n"
                    f"- **{PAGE_DRAFT_AND_SEND_SESSION}:** Draft & send emails for new leads (sample report attached).\n"
                    f"- **{PAGE_MANAGE_ALL_DRAFTS}:** Review, edit, send pending drafts (sample report attached).\n"
                    "- **Follow-up:** Manage follow-up sequences (referencing previously sent report).\n"
                    "- **Dashboard:** Monitor performance (opens/clicks tracked by your custom system) and manage individual leads.\n"
                    "- **Settings:** Manage account and configuration.")

        tracking_status_msg = f'Active ({BASE_TRACKING_URL})' if BASE_TRACKING_URL else 'Inactive / Configuration Error'
        if not BASE_TRACKING_URL: tracking_status_msg = "Inactive (BASE_TRACKING_URL not set in .env)"

        pdf_status = "Available" if os.path.exists(DEMO_REPORT_PDF_PATH) else f"MISSING ({DEMO_REPORT_PDF_FILENAME} not found)"
        st.info(f"Emails: {SENDER_EMAIL or 'N/A'}. Custom Tracking System: {tracking_status_msg}. Gemini AI: {'Active' if gemini_model else 'Inactive'}. Sample PDF Report: {pdf_status}")
        if not os.path.exists(DEMO_REPORT_PDF_PATH):
            st.error(f"CRITICAL: The demo report PDF '{DEMO_REPORT_PDF_FILENAME}' is missing from the specified path: '{DEMO_REPORT_PDF_PATH}'. Emails will be sent without it.")
        if not BASE_TRACKING_URL:
            st.error(f"CRITICAL: The BASE_TRACKING_URL environment variable is not set. Email opens and clicks will NOT be tracked.")


    elif st.session_state.current_page == "🔍 Find Leads":
        st.header("🔍 Find Leads")

        # --- TEMPORARY MANUAL LEAD ENTRY FOR TESTING ---
        st.subheader("Manual Test Lead Entry (For Testing Purposes Only)")
        with st.form("manual_test_lead_form", clear_on_submit=False):
            test_company_input = st.text_input("Test Company Name (e.g., 'Test Company')", value="Test Company for Rishabh", key="test_co_input")
            test_lead_name = st.text_input("Test Lead Name (e.g., 'John Doe')", value="Test Recipient", key="test_lead_name")
            test_lead_email = st.text_input("Test Lead Email (YOUR test email address)", value="your_test_email@example.com", key="test_lead_email") # <<< PUT YOUR TEST EMAIL HERE
            test_lead_role = st.text_input("Test Lead Role (e.g., 'QA Tester')", value="Testing Role", key="test_lead_role")

            if st.form_submit_button("➕ Add Manual Test Lead to Session"):
                if test_lead_email and test_company_input:
                    # Clear existing session leads to focus on this test
                    st.session_state.mcp["leads_found_this_session"] = []

                    manual_lead_data = {
                        "company_input": test_company_input,
                        "name": test_lead_name,
                        "email": test_lead_email,
                        "role": test_lead_role,
                        "hunter_raw": {"source": "manual_test_entry"}, # Dummy data
                        "verification_status": "verified", # Assume for test
                        "is_target_role": True, # Assume for test
                    }
                    st.session_state.mcp["leads_found_this_session"].append(manual_lead_data)
                    st.session_state.mcp["current_step"] = "leads_found"
                    st.success(f"Manually added test lead: {test_lead_name} <{test_lead_email}>")
                else:
                    st.error("Please enter at least a test email and company name for the manual lead.")
        st.markdown("---")
        # --- END TEMPORARY MANUAL LEAD ENTRY ---

        user_in_val = st.text_input("Company Name or Website URL:", value=st.session_state.mcp.get("company_input", ""), key="company_input_field", help="e.g., 'Acme Corp' or 'acme.com'")
        if st.button("🔎 Find Leads with Hunter.io", type="primary", use_container_width=True):
            if user_in_val:
                with st.spinner("Searching leads with Hunter.io..."): agent_lead_finder(user['id'], user_in_val)
            else: st.warning("Please enter a company name or website.")
        if st.session_state.mcp.get("current_step") == "leads_found" and st.session_state.mcp.get("leads_found_this_session"):
            st.subheader(f"New Leads This Session ({len(st.session_state.mcp['leads_found_this_session'])}):")
            df_sl = pd.DataFrame(st.session_state.mcp['leads_found_this_session'])
            if not df_sl.empty:
                cols_show = ['name', 'email', 'role', 'verification_status', 'company_input']
                if 'is_target_role' in df_sl.columns:
                    cols_show.append('is_target_role'); df_d = df_sl[cols_show].copy(); df_d['is_target_role'] = df_d['is_target_role'].map({True: 'Yes', False: 'No'})
                    st.dataframe(df_d.head(), use_container_width=True)
                else: st.dataframe(df_sl[cols_show].head(), use_container_width=True)
                if st.button("📝 Process & Compose Emails (with Demo Report)", type="primary", use_container_width=True):
                    if not os.path.exists(DEMO_REPORT_PDF_PATH):
                        st.error(f"Cannot compose emails: Demo report PDF '{DEMO_REPORT_PDF_FILENAME}' is missing from path: '{DEMO_REPORT_PDF_PATH}'.")
                    else:
                        with st.spinner("Saving leads & drafting emails..."):
                            if agent_email_composer(user['id']):
                                st.success("Leads processed, drafts prepared.")
                                st.session_state.current_page = PAGE_DRAFT_AND_SEND_SESSION; st.rerun()
            else: st.info("No new leads this session to display.")
        elif st.session_state.mcp.get("current_step") == "input": st.info("Enter company/domain to start.")

    elif st.session_state.current_page == PAGE_DRAFT_AND_SEND_SESSION:
        st.header(f"{PAGE_DRAFT_AND_SEND_SESSION} (Initial emails will include demo PDF)")
        if st.session_state.mcp.get("current_step") == "emails_drafted" and st.session_state.mcp.get("email_drafts_this_session"):
            mcp_drafts = st.session_state.mcp["email_drafts_this_session"]
            st.info(f"Showing {len(mcp_drafts)} draft(s) from this session. The demo PDF will be attached upon sending. Opens and clicks will be tracked.")
            for lead_id_str in list(mcp_drafts.keys()):
                lead_id = int(lead_id_str); draft_content = mcp_drafts.get(lead_id_str)
                if not draft_content: continue
                lead_info = get_lead_by_id(user['id'], lead_id)
                if not lead_info:
                    st.warning(f"Lead ID {lead_id} not found. Removing from view.")
                    if lead_id_str in mcp_drafts: del mcp_drafts[lead_id_str]
                    continue
                with st.expander(f"Draft: {lead_info['lead_name']} ({lead_info['lead_email']}) - Status: {lead_info['initial_email_status']}", expanded=True):
                    s_key = f"compose_s_{lead_id}"; b_key = f"compose_b_{lead_id}"
                    current_subj = st.session_state.get(s_key, draft_content["subject"])
                    current_body = st.session_state.get(b_key, draft_content["body"])
                    edited_subject = st.text_input("Subject:", current_subj, key=f"ui_s_cs_{lead_id}")
                    edited_body = st.text_area("Body:", current_body, height=300, key=f"ui_b_cs_{lead_id}")
                    col_save, col_send = st.columns(2)
                    if col_save.button(f"💾 Save DB Draft", key=f"save_cs_{lead_id}", use_container_width=True):
                        st.session_state[s_key] = edited_subject; st.session_state[b_key] = edited_body
                        update_lead_email_draft(user['id'], lead_id, edited_subject, edited_body)
                        mcp_drafts[lead_id_str] = {"subject": edited_subject, "body": edited_body}
                        st.success(f"Draft for {lead_info['lead_name']} updated.")
                    if col_send.button(f"📤 Send Email (with PDF)", key=f"send_cs_{lead_id}", type="primary", use_container_width=True):
                        if not os.path.exists(DEMO_REPORT_PDF_PATH):
                            st.error(f"Cannot send email: Demo report PDF '{DEMO_REPORT_PDF_FILENAME}' is missing from path: '{DEMO_REPORT_PDF_PATH}'.")
                        else:
                            update_lead_email_draft(user['id'], lead_id, edited_subject, edited_body)
                            if agent_email_sender(user['id'], lead_id, edited_subject, edited_body, email_log_type="INITIAL"):
                                if lead_id_str in mcp_drafts: del mcp_drafts[lead_id_str]
                                for k_del in [s_key, b_key]:
                                    if k_del in st.session_state: del st.session_state[k_del]
                                st.rerun()
            if not mcp_drafts: st.info("All session drafts processed."); st.session_state.mcp["current_step"] = "input"
        else: st.info("No active session drafts. Find leads or manage all drafts.")

    elif st.session_state.current_page == PAGE_MANAGE_ALL_DRAFTS:
        st.header(f"{PAGE_MANAGE_ALL_DRAFTS} (Initial emails will include demo PDF)")
        drafted_leads_db = [l for l in get_all_leads(user['id']) if l['initial_email_status'] == 'DRAFTED']
        if not drafted_leads_db: st.info("No emails in 'DRAFTED' status.")
        else:
            st.markdown(f"**{len(drafted_leads_db)}** email(s) in 'DRAFTED' status. The demo PDF will be attached upon sending. Opens and clicks will be tracked.")
            for lead_info in drafted_leads_db:
                lead_id = lead_info['id']
                with st.expander(f"To: {lead_info['lead_name']} ({lead_info['lead_email']}) - Co: {lead_info['company_input']}"):
                    s_key = f"send_all_s_{lead_id}"; b_key = f"send_all_b_{lead_id}"
                    current_subj = st.session_state.get(s_key, lead_info["initial_email_subject"])
                    current_body = st.session_state.get(b_key, lead_info["initial_email_body"])
                    edited_subject = st.text_input("Subject:", value=current_subj, key=f"ui_s_sa_{lead_id}")
                    edited_body = st.text_area("Body:", value=current_body, height=300, key=f"ui_b_sa_{lead_id}")
                    col_save, col_send = st.columns(2)
                    if col_save.button(f"💾 Save Draft", key=f"save_sa_{lead_id}", use_container_width=True):
                        st.session_state[s_key] = edited_subject; st.session_state[b_key] = edited_body
                        update_lead_email_draft(user['id'], lead_id, edited_subject, edited_body)
                        st.success(f"Draft for {lead_info['lead_name']} updated.")
                    if col_send.button(f"📤 Send Email (with PDF)", key=f"send_sa_{lead_id}", type="primary", use_container_width=True):
                        if not os.path.exists(DEMO_REPORT_PDF_PATH):
                            st.error(f"Cannot send email: Demo report PDF '{DEMO_REPORT_PDF_FILENAME}' is missing from path: '{DEMO_REPORT_PDF_PATH}'.")
                        else:
                            update_lead_email_draft(user['id'], lead_id, edited_subject, edited_body)
                            if agent_email_sender(user['id'], lead_id, edited_subject, edited_body, email_log_type="INITIAL"):
                                for k_del in [s_key, b_key]:
                                    if k_del in st.session_state: del st.session_state[k_del]
                                st.rerun()
            if drafted_leads_db and st.button("🚀 Send All Pending Emails on This Page (with PDF)", type="primary", use_container_width=True):
                if not os.path.exists(DEMO_REPORT_PDF_PATH):
                    st.error(f"Cannot send batch emails: Demo report PDF '{DEMO_REPORT_PDF_FILENAME}' is missing from path: '{DEMO_REPORT_PDF_PATH}'.")
                else:
                    sent_count, failed_count = 0, 0
                    current_drafts_batch = [l for l in get_all_leads(user['id']) if l['initial_email_status'] == 'DRAFTED']
                    for lead_batch in current_drafts_batch:
                        l_id = lead_batch['id']
                        s_key_b = f"send_all_s_{l_id}"; b_key_b = f"send_all_b_{l_id}"
                        curr_s = st.session_state.get(s_key_b, lead_batch['initial_email_subject'])
                        curr_b = st.session_state.get(b_key_b, lead_batch['initial_email_body'])
                        update_lead_email_draft(user['id'], l_id, curr_s, curr_b)
                        if agent_email_sender(user['id'], l_id, curr_s, curr_b, email_log_type="INITIAL"):
                            sent_count += 1
                            for k_del_b in [s_key_b, b_key_b]:
                                if k_del_b in st.session_state: del st.session_state[k_del_b]
                        else: failed_count += 1
                    st.success(f"Batch Send: {sent_count} sent, {failed_count} failed."); st.rerun()

    elif st.session_state.current_page == "🔄 Follow-ups":
        st.header("🔄 Manage Follow-up Emails")
        st.info("Follow-up emails will reference the previously sent demo report but will not re-attach it. Opens and clicks will be tracked.")
        if st.button("🔄 Scan & Prepare Due Follow-ups", type="primary", use_container_width=True):
            with st.spinner("Scanning for due follow-ups..."):
                for key in list(st.session_state.keys()):
                    if key.startswith("fu_subj_") or key.startswith("fu_body_"): del st.session_state[key]
                agent_manage_follow_ups(user['id'])

    elif st.session_state.current_page == "📊 Dashboard":
        st.header("📊 Campaign Dashboard")
        col_ref1, col_ref2 = st.columns([.7, .3])
        if col_ref1.button("🔄 Refresh Data", key="refresh_dash", use_container_width=True):
            update_user_csv(user['id']); st.rerun()

        all_leads = get_all_leads(user['id'])
        if not all_leads:
            st.info("No leads found.")
            return

        df_leads = pd.DataFrame(all_leads)

        # Fetch tracking data
        conn = get_db_connection()
        tracking_df = pd.read_sql_query(f"""
            SELECT lead_id, event_type, COUNT(id) as count
            FROM tracking_events
            WHERE lead_id IN (SELECT id FROM leads WHERE user_id = {user['id']})
            GROUP BY lead_id, event_type
        """, conn)
        conn.close()

        # Aggregate opens and clicks per lead
        opens_per_lead = tracking_df[tracking_df['event_type'] == 'open'].set_index('lead_id')['count'].to_dict()
        clicks_per_lead = tracking_df[tracking_df['event_type'] == 'click'].set_index('lead_id')['count'].to_dict()

        df_leads['opens'] = df_leads['id'].map(opens_per_lead).fillna(0).astype(int)
        df_leads['clicks'] = df_leads['id'].map(clicks_per_lead).fillna(0).astype(int)

        st.subheader("📈 Key Metrics")
        total_leads = len(df_leads); sent_initial = df_leads[df_leads['initial_email_status'] == 'SENT'].shape[0]
        total_opens = df_leads['opens'].sum()
        total_clicks = df_leads['clicks'].sum()

        open_rate = (total_opens / sent_initial * 100) if sent_initial > 0 else 0
        click_rate_from_sent = (total_clicks / sent_initial * 100) if sent_initial > 0 else 0
        click_rate_from_opens = (total_clicks / total_opens * 100) if total_opens > 0 else 0

        paid_leads = df_leads[df_leads['strategyhub_used'] == 3].shape[0]
        conversion_rate = (paid_leads / total_leads * 100) if total_leads > 0 else 0

        mc = st.columns(5)
        mc[0].metric("Total Leads", total_leads)
        mc[1].metric("Emails Sent (Initial)", sent_initial)
        mc[2].metric("Total Opens", total_opens)
        mc[3].metric("Total Clicks", total_clicks)
        mc[4].metric("Conversion (Paid)", f"{conversion_rate:.2f}%")

        mc2 = st.columns(3)
        mc2[0].metric("Open Rate (from sent)", f"{open_rate:.2f}%")
        mc2[1].metric("Click Rate (from sent)", f"{click_rate_from_sent:.2f}%")
        mc2[2].metric("Click Rate (from opens)", f"{click_rate_from_opens:.2f}%")


        st.subheader("📋 Lead Status Overview")
        df_display = df_leads[['lead_name', 'lead_email', 'company_input', 'lead_role',
                               'initial_email_status', 'opens', 'clicks', 'cta_clicked',
                               'strategyhub_used', 'responded', 'follow_up_count', 'next_follow_up_due']].copy()
        sh_map = {0:'No', 1:'Yes', 2:'Unk', 3:'Paid'}; cta_map = {0:'No', 1:'Yes'}; resp_map = {0:'No', 1:'Yes'}
        df_display['cta_clicked'] = df_display['cta_clicked'].map(cta_map).fillna('No')
        df_display['strategyhub_used'] = df_display['strategyhub_used'].map(sh_map).fillna('Unk')
        df_display['responded'] = df_display['responded'].map(resp_map).fillna('No')
        df_display['next_follow_up_due'] = pd.to_datetime(df_display['next_follow_up_due']).dt.strftime('%Y-%m-%d %H:%M').fillna('N/A')
        st.dataframe(df_display, use_container_width=True)

        st.subheader("📥 Download Your Data")
        user_dir = get_user_data_dir(user['id']); dl_cols = st.columns(3)
        try:
            with open(os.path.join(user_dir, "leads.csv"), "rb") as fp: dl_cols[0].download_button("Leads.csv", fp, "leads.csv", "text/csv", use_container_width=True)
            with open(os.path.join(user_dir, "email_logs.csv"), "rb") as fp: dl_cols[1].download_button("Email_Logs.csv", fp, "email_logs.csv", "text/csv", use_container_width=True)
            with open(os.path.join(user_dir, "tracking_events.csv"), "rb") as fp: dl_cols[2].download_button("Tracking_Events.csv", fp, "tracking_events.csv", "text/csv", use_container_width=True)
        except FileNotFoundError: st.warning("CSVs not generated. Perform actions or refresh.")


        st.subheader("⚙️ Manage Individual Leads")
        for _, lead_row in df_leads.iterrows():
            ld = dict(lead_row); l_id_d = ld['id']; st.markdown("---")
            # Adjusted column widths for new Edit and Delete buttons
            c1,c2,c3,c4,c5,c6,c7 = st.columns([0.25,.15,.15,.1,.1,.1,.15]) # Adjusted widths
            with c1:
                st.markdown(f"**{ld['lead_name']}** ({ld['lead_email']})<br><small>{ld['lead_role']} @ {ld['company_input']}</small>", unsafe_allow_html=True)
            with c2:
                st.caption(f"Initial: {ld['initial_email_status']}")
                if ld['initial_email_error']:
                    with st.popover("Error",use_container_width=True): st.error(ld['initial_email_error'])
            with c3:
                st.caption(f"Opens: {ld['opens']}, Clicks: {ld['clicks']}")
            with c4:
                st.caption(f"FUs: {ld['follow_up_count']}")
                if ld['next_follow_up_due'] and not ld['responded'] and ld['strategyhub_used']!=3:
                    st.caption(f"Next FU: {pd.to_datetime(ld['next_follow_up_due']).strftime('%Y-%m-%d')}")
            with c5:
                curr_resp = bool(ld['responded'])
                new_resp = st.checkbox("Resp?", value=curr_resp, key=f"dash_resp_{l_id_d}")
                if new_resp != curr_resp: set_lead_responded_status(user['id'], l_id_d, 1 if new_resp else 0); st.rerun()
            with c6:
                sh_map_edit={"Unk":2,"No":0,"Yes":1,"Paid":3}; sh_disp_edit=list(sh_map_edit.keys())
                curr_sh_val=ld['strategyhub_used']; curr_sh_text=next((k for k,v in sh_map_edit.items() if v==curr_sh_val),"Unk")
                new_sh_disp=st.selectbox("SH Use:",sh_disp_edit,index=sh_disp_edit.index(curr_sh_text),key=f"dash_sh_{l_id_d}",label_visibility="collapsed")
                if new_sh_disp != curr_sh_text: set_strategyhub_used_status(user['id'],l_id_d,sh_map_edit[new_sh_disp]); st.rerun()
            with c7: # Column for Edit and Delete actions
                # --- EDIT LEAD POPOVER ---
                # Removed use_container_width=True from st.popover
                with st.popover(f"✏️ Edit", key=f"popover_edit_{l_id_d}"): # CORRECTED
                    st.markdown(f"**Edit Lead: {ld['lead_name']}**")
                    with st.form(key=f"edit_lead_form_{l_id_d}", clear_on_submit=False):
                        edited_name = st.text_input("Name", value=ld['lead_name'], key=f"edit_name_{l_id_d}")
                        edited_email = st.text_input("Email", value=ld['lead_email'], key=f"edit_email_{l_id_d}")
                        edited_role = st.text_input("Role", value=ld['lead_role'], key=f"edit_role_{l_id_d}")
                        edited_company = st.text_input("Company Input", value=ld['company_input'], key=f"edit_company_{l_id_d}")

                        edit_cols = st.columns(2)
                        if edit_cols[0].form_submit_button("Save Changes", type="primary", use_container_width=True):
                            if update_lead_details_in_db(user['id'], l_id_d, edited_name, edited_email, edited_role, edited_company):
                                st.rerun() # Rerun to reflect changes
                        edit_cols[1].form_submit_button("Cancel", use_container_width=True) # Form close implicitly

                # --- DELETE LEAD POPOVER ---
                # Removed use_container_width=True from st.popover
                with st.popover(f"🗑️ Delete", key=f"popover_delete_{l_id_d}"): # CORRECTED
                    st.warning(f"Are you sure you want to delete {ld['lead_name']}?")
                    st.markdown("All associated email logs and tracking events will also be deleted.")
                    col_del_conf1, col_del_conf2 = st.columns(2)
                    if col_del_conf1.button("Confirm Delete", key=f"confirm_delete_{l_id_d}", type="primary", use_container_width=True):
                        if delete_lead_from_db(user['id'], l_id_d):
                            # Reset current page or rerun to ensure the lead is removed from the display
                            st.session_state.current_page = "📊 Dashboard"
                            st.rerun()
                    if col_del_conf2.button("Cancel", key=f"cancel_delete_{l_id_d}", use_container_width=True):
                        pass # The popover will close itself on next rerun/interaction

    elif st.session_state.current_page == "⚙️ Settings":
        st.header("⚙️ Application Settings")
        st.subheader("Account Management")
        st.warning("⚠️ Deleting account is irreversible. Data will be removed.")
        if 'confirm_delete_account' not in st.session_state: st.session_state.confirm_delete_account = False
        if st.button("🗑️ Delete My Account Permanently", type="primary", use_container_width=True):
            st.session_state.confirm_delete_account = True; st.rerun()
        if st.session_state.confirm_delete_account:
            st.error("ARE YOU SURE? This cannot be undone.")
            confirm_cols = st.columns(2)
            if confirm_cols[0].button("YES, DELETE MY ACCOUNT", use_container_width=True, type="primary"):
                if delete_user_account(user['id']): st.rerun()
            if confirm_cols[1].button("NO, KEEP MY ACCOUNT", use_container_width=True):
                st.session_state.confirm_delete_account = False; st.rerun()
        st.subheader("Environment Variables Status")
        env_vars = {
            "GOOGLE_API_KEY": bool(GOOGLE_API_KEY), "HUNTER_API_KEY": bool(HUNTER_API_KEY),
            "BASE_TRACKING_URL": bool(BASE_TRACKING_URL),
            "SMTP_SERVER_CONFIG": bool(SMTP_SERVER_CONFIG), "SMTP_PORT_CONFIG": bool(SMTP_PORT_CONFIG),
            "SMTP_USERNAME_CONFIG": bool(SMTP_USERNAME_CONFIG), "SMTP_PASSWORD_CONFIG": bool(SMTP_PASSWORD_CONFIG),
            "SENDER_EMAIL": bool(SENDER_EMAIL), "DATA_DIR": bool(DATA_DIR), "DB_NAME": bool(DB_NAME),
            "DEMO_REPORT_PDF_PATH": os.path.exists(DEMO_REPORT_PDF_PATH) if DEMO_REPORT_PDF_PATH else False
        }
        all_crit_loaded = True
        crit_vars = ["GOOGLE_API_KEY", "HUNTER_API_KEY", "BASE_TRACKING_URL", "SMTP_SERVER_CONFIG",
                     "SMTP_PORT_CONFIG", "SMTP_USERNAME_CONFIG", "SMTP_PASSWORD_CONFIG", "SENDER_EMAIL", "DEMO_REPORT_PDF_PATH"]
        for var_name, is_loaded in env_vars.items():
            is_crit_missing = var_name.split(" (")[0] in crit_vars and not is_loaded
            if is_crit_missing: all_crit_loaded = False
            status_emoji = '✅ Loaded' if is_loaded else ('❌ CRITICAL - Missing' if is_crit_missing else '⚠️ Missing')
            if var_name == "DEMO_REPORT_PDF_PATH":
                st.markdown(f"- `Demo Report PDF ({DEMO_REPORT_PDF_FILENAME})`: {status_emoji} (Path: `{DEMO_REPORT_PDF_PATH}`) ")
            else:
                st.markdown(f"- `{var_name}`: {status_emoji}")
        if not all_crit_loaded: st.error("CRITICAL environment variables or files missing. Check `.env` file and ensure demo PDF exists at the specified path.")
        else: st.success("All critical environment variables appear loaded and demo PDF is present.")

# --- MAIN APP LOGIC ---
if __name__ == "__main__":
    st.set_page_config(layout="wide", page_title="AI Lead Outreach Platform")
    init_db()
    if 'user' not in st.session_state:
        ui_login_register()
    else:
        init_mcp()
        main_app_ui()