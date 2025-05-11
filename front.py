
import streamlit as st
import pyrebase
import re
import uuid
import datetime
from functools import wraps

# Configuration for Firebase
config = {
    "apiKey": "AIzaSyDvnzklw_s8H7DtZu8lYMFrMNqJ9mUFVKM",
    "authDomain": "integration-siem-with-ids.firebaseapp.com",
    "databaseURL": "https://your-project-id-default-rtdb.firebaseio.com/",
    "projectId": "integration-siem-with-id",
    "storageBucket": "integration-siem-with-ids.firebasestorage.app",
    "messagingSenderId": "503831938363",
    "appId": "1:503831938363:web:d04f0d280a1f732e0b231e"
}

# Initialize Firebase
firebase = pyrebase.initialize_app(config)
auth = firebase.auth()
db = firebase.database()

# Page configuration
st.set_page_config(
    page_title="SIEM Dashboard",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Session management
def init_session_state():
    if 'logged_in' not in st.session_state:
        st.session_state.logged_in = False
    if 'user_info' not in st.session_state:
        st.session_state.user_info = None
    if 'user_role' not in st.session_state:
        st.session_state.user_role = None
    if 'user_id' not in st.session_state:
        st.session_state.user_id = None
    if 'login_time' not in st.session_state:
        st.session_state.login_time = None

init_session_state()

# Authentication check decorator
def login_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if not st.session_state.logged_in:
            st.warning("Please log in to access this page")
            login_page()
            return
        else:
            # Check for session timeout (1 hour)
            if st.session_state.login_time:
                current_time = datetime.datetime.now()
                time_difference = current_time - st.session_state.login_time
                if time_difference.total_seconds() > 3600:  # 1 hour in seconds
                    st.warning("Your session has expired. Please log in again.")
                    logout_user()
                    login_page()
                    return
            return func(*args, **kwargs)
    return wrapper

# Utility Functions
def validate_email(email):
    """Validate email format"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def validate_password(password):
    """Validate password strength"""
    # At least 8 characters, 1 uppercase, 1 lowercase, 1 number
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"
    if not re.search(r'[0-9]', password):
        return False, "Password must contain at least one number"
    return True, "Password is strong"

def record_user_activity(user_id, activity_type, details=None):
    """Record user activity in Firebase for auditing"""
    activity_data = {
        "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "activity_type": activity_type,
        "details": details or {}
    }
    db.child("user_activities").child(user_id).push(activity_data)

def logout_user():
    """Logout the user and reset session state"""
    if st.session_state.logged_in and st.session_state.user_id:
        record_user_activity(st.session_state.user_id, "logout")
    
    st.session_state.logged_in = False
    st.session_state.user_info = None
    st.session_state.user_role = None
    st.session_state.user_id = None
    st.session_state.login_time = None

# Authentication Pages
def login_page():
    st.title("SIEM Dashboard Login")
    
    with st.form("login_form"):
        email = st.text_input("Email")
        password = st.text_input("Password", type="password")
        submit_button = st.form_submit_button("Login")
        
        if submit_button:
            if not email or not password:
                st.error("Please enter both email and password")
                return
                
            try:
                # Authenticate user with Firebase
                user = auth.sign_in_with_email_and_password(email, password)
                
                # Get user information from the database
                user_id = user['localId']
                user_info = db.child("users").child(user_id).get().val()
                
                if not user_info:
                    st.error("User profile not found. Please contact administrator.")
                    return
                
                # Set session state
                st.session_state.logged_in = True
                st.session_state.user_info = user_info
                st.session_state.user_role = user_info.get('role', 'viewer')
                st.session_state.user_id = user_id
                st.session_state.login_time = datetime.datetime.now()
                
                # Record login activity
                record_user_activity(user_id, "login", {"email": email})
                
                st.success(f"Welcome {user_info.get('name', email)}!")
                st.rerun()
                
            except Exception as e:
                st.error(f"Login failed: {str(e)}")
    
    st.divider()
    st.write("Don't have an account?")
    if st.button("Sign Up"):
        st.session_state.page = "signup"
        st.rerun()

def signup_page():
    st.title("SIEM Dashboard Sign Up")
    
    with st.form("signup_form"):
        name = st.text_input("Full Name")
        email = st.text_input("Email")
        password = st.text_input("Password", type="password")
        confirm_password = st.text_input("Confirm Password", type="password")
        
        # Role selection with explanation
        role_options = ["Viewer", "Admin"]
        role = st.selectbox(
            "Role", 
            options=role_options,
            help="Viewer: Read-only access to dashboards and alerts. Admin: Full access including settings and actions."
        )
        
        submit_button = st.form_submit_button("Sign Up")
        
        if submit_button:
            # Basic validation
            if not name or not email or not password or not confirm_password:
                st.error("Please fill in all fields")
                return
                
            if not validate_email(email):
                st.error("Please enter a valid email address")
                return
                
            is_valid_password, password_message = validate_password(password)
            if not is_valid_password:
                st.error(password_message)
                return
                
            if password != confirm_password:
                st.error("Passwords do not match")
                return
                
            try:
                # Create user in Firebase Authentication
                user = auth.create_user_with_email_and_password(email, password)
                user_id = user['localId']
                
                # Store additional user information in Firebase Database
                user_data = {
                    "name": name,
                    "email": email,
                    "role": role.lower(),
                    "created_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "last_login": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                }
                db.child("users").child(user_id).set(user_data)
                
                # Record signup activity
                record_user_activity(user_id, "signup", {"email": email, "role": role.lower()})
                
                st.success("Account created successfully! Please log in.")
                st.session_state.page = "login"
                st.rerun()
                
            except Exception as e:
                st.error(f"Registration failed: {str(e)}")
    
    st.divider()
    st.write("Already have an account?")
    if st.button("Log In"):
        st.session_state.page = "login"
        st.rerun()

# Dashboard Pages
@login_required
def admin_dashboard():
    st.title("SIEM Admin Dashboard")
    st.write(f"Welcome, {st.session_state.user_info.get('name')}!")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.metric("Total Alerts", "142", "12%")
    with col2:
        st.metric("Blocked IPs", "27", "3")
    with col3:
        st.metric("Active Users", "5", "1")
    
    # Admin actions
    st.subheader("Admin Actions")
    tab1, tab2, tab3 = st.tabs(["Block/Unblock IPs", "System Settings", "User Management"])
    
    with tab1:
        st.write("Manage blocked IP addresses")
        ip_to_block = st.text_input("IP Address")
        col1, col2 = st.columns(2)
        with col1:
            if st.button("Block IP"):
                if ip_to_block:
                    record_user_activity(st.session_state.user_id, "block_ip", {"ip": ip_to_block})
                    st.success(f"IP {ip_to_block} has been blocked")
        with col2:
            if st.button("Unblock IP"):
                if ip_to_block:
                    record_user_activity(st.session_state.user_id, "unblock_ip", {"ip": ip_to_block})
                    st.success(f"IP {ip_to_block} has been unblocked")
    
    with tab2:
        st.write("System Settings")
        log_retention = st.slider("Log Retention (days)", 7, 365, 30)
        alert_threshold = st.slider("Alert Threshold", 1, 100, 10)
        
        if st.button("Save Settings"):
            record_user_activity(
                st.session_state.user_id, 
                "update_settings", 
                {"log_retention": log_retention, "alert_threshold": alert_threshold}
            )
            st.success("Settings saved successfully")
    
    with tab3:
        st.write("User Management")
        # This would typically fetch users from Firebase
        st.text("Feature coming soon...")

    # Clear logs option
    st.subheader("Log Management")
    if st.button("Clear All Logs"):
        record_user_activity(st.session_state.user_id, "clear_logs")
        st.success("All logs have been cleared")

@login_required
def viewer_dashboard():
    st.title("SIEM Viewer Dashboard")
    st.write(f"Welcome, {st.session_state.user_info.get('name')}!")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.metric("Total Alerts", "142", "12%")
    with col2:
        st.metric("Blocked IPs", "27", "3")
    with col3:
        st.metric("Traffic (24h)", "1.2 TB", "5%")
    
    # Viewer features - read only
    st.subheader("Alerts Overview")
    st.bar_chart({
        "Critical": [12, 5, 8, 4],
        "High": [20, 15, 18, 11],
        "Medium": [30, 25, 28, 24],
        "Low": [45, 35, 40, 30]
    })
    
    st.subheader("Traffic Analysis")
    st.line_chart({
        "HTTP": [100, 120, 80, 110, 95, 70, 85],
        "HTTPS": [200, 220, 180, 210, 195, 170, 185],
        "SSH": [30, 25, 35, 40, 45, 20, 25]
    })
    
    st.subheader("Recent Alerts")
    alerts = [
        {"timestamp": "2023-10-25 14:32:45", "ip": "192.168.1.105", "type": "Brute Force", "severity": "High"},
        {"timestamp": "2023-10-25 14:15:22", "ip": "192.168.1.110", "type": "Port Scan", "severity": "Medium"},
        {"timestamp": "2023-10-25 13:58:17", "ip": "192.168.1.120", "type": "Malware", "severity": "Critical"},
        {"timestamp": "2023-10-25 13:45:30", "ip": "192.168.1.125", "type": "Suspicious Login", "severity": "High"}
    ]
    st.table(alerts)

# Sidebar with navigation and user info
def sidebar_menu():
    with st.sidebar:
        st.title("SIEM Dashboard")
        
        if st.session_state.logged_in:
            st.write(f"Logged in as: {st.session_state.user_info.get('name')}")
            st.write(f"Role: {st.session_state.user_role.capitalize()}")
            
            st.divider()
            
            # Display appropriate menu based on user role
            if st.session_state.user_role == "admin":
                menu_options = ["Admin Dashboard", "View Alerts", "System Logs", "User Management", "Settings"]
            else:  # viewer role
                menu_options = ["Viewer Dashboard", "View Alerts", "Traffic Analysis"]
            
            selected_menu = st.selectbox("Navigation", menu_options)
            
            st.divider()
            
            if st.button("Logout"):
                logout_user()
                st.rerun()

# Main app
def main():
    # Initialize page if not set
    if 'page' not in st.session_state:
        st.session_state.page = "login"
    
    sidebar_menu()
    
    # If logged in, show appropriate dashboard
    if st.session_state.logged_in:
        if st.session_state.user_role == "admin":
            admin_dashboard()
        else:
            viewer_dashboard()
    else:
        # If not logged in, show login or signup page
        if st.session_state.page == "login":
            login_page()
        elif st.session_state.page == "signup":
            signup_page()

if __name__ == "__main__":
    main()