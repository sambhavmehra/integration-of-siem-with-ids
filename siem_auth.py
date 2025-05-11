import streamlit as st
import pyrebase
import re
import datetime
import uuid
import pandas as pd
import time  # Added time import at the top to avoid missing import

# Firebase Configuration - replace with your actual Firebase project credentials
firebase_config = {
    "apiKey": "AIzaSyDvnzklw_s8H7DtZu8lYMFrMNqJ9mUFVKM",
    "authDomain": "integration-siem-with-ids.firebaseapp.com", 
    "databaseURL": "https://integration-siem-with-ids-default-rtdb.firebaseio.com/",
    "projectId": "integration-siem-with-ids",
    "storageBucket": "integration-siem-with-ids.appspot.com",  # Fixed incorrect domain (.firebasestorage.app -> .appspot.com)
    "messagingSenderId": "503831938363",
    "appId": "1:503831938363:web:d04f0d280a1f732e0b231e"
}

# Initialize Firebase
try:
    firebase = pyrebase.initialize_app(firebase_config)
    auth = firebase.auth()
    db = firebase.database()
except Exception as e:
    st.error(f"Firebase initialization error: {e}")
    st.error("Please check that you have installed pyrebase4 and pycryptodome correctly.")
    st.code("pip install pyrebase4 pycryptodome", language="bash")

# Session management
def init_session_state():
    """Initialize session state variables for authentication"""
    if 'user' not in st.session_state:
        st.session_state.user = None
    if 'user_info' not in st.session_state:
        st.session_state.user_info = None
    if 'authenticated' not in st.session_state:
        st.session_state.authenticated = False
    if 'user_role' not in st.session_state:
        st.session_state.user_role = None
    if 'login_time' not in st.session_state:
        st.session_state.login_time = None
    if 'session_id' not in st.session_state:
        st.session_state.session_id = None
    # Initialize page state if not exists
    if 'page' not in st.session_state:
        st.session_state.page = "login"

def validate_email(email):
    """Validate email format using regex"""
    pattern = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
    return re.match(pattern, email)

def validate_password(password):
    """
    Validate password strength:
    - At least 8 characters
    - Contains at least one uppercase letter
    - Contains at least one lowercase letter
    - Contains at least one digit
    - Contains at least one special character
    """
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter"
    
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter"
    
    if not re.search(r"\d", password):
        return False, "Password must contain at least one digit"
    
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False, "Password must contain at least one special character"
    
    return True, "Password is strong"

def create_user(email, password, role, first_name, last_name):
    """Create a new user in Firebase Auth and Realtime Database"""
    try:
        # Create user with email and password
        user = auth.create_user_with_email_and_password(email, password)
        
        # Store additional user data in Realtime Database
        user_data = {
            "email": email,
            "role": role.lower(),  # Ensure role is lowercase for consistency
            "first_name": first_name,
            "last_name": last_name,
            "created_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "last_login": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        
        # Save user data to database using the Firebase UID as the key
        db.child("users").child(user['localId']).set(user_data)
        
        return True, "User created successfully"
    except Exception as e:
        return False, str(e)

def login_user(email, password):
    """Authenticate user with Firebase"""
    try:
        # Sign in with email and password
        user = auth.sign_in_with_email_and_password(email, password)
        
        # Get user details from database
        user_info = db.child("users").child(user['localId']).get().val()
        
        if not user_info:
            return False, "User profile not found", None, None
        
        # Update last login
        db.child("users").child(user['localId']).update({
            "last_login": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        })
        
        # Log login activity
        session_id = str(uuid.uuid4())
        log_user_activity(user['localId'], "login", session_id)
        
        return True, "Login successful", user, user_info
    except Exception as e:
        return False, str(e), None, None

def logout_user():
    """Log out the current user"""
    if st.session_state.user:
        try:
            # Log logout activity
            log_user_activity(st.session_state.user['localId'], "logout", st.session_state.session_id)
        except Exception as e:
            print(f"Error logging logout: {e}")
    
    # Reset session state
    st.session_state.user = None
    st.session_state.user_info = None
    st.session_state.authenticated = False
    st.session_state.user_role = None
    st.session_state.login_time = None
    st.session_state.session_id = None
    st.session_state.page = "login"  # Reset page to login after logout

def check_session_timeout(timeout_minutes=30):
    """Check if the current session has timed out"""
    if st.session_state.authenticated and st.session_state.login_time:
        current_time = datetime.datetime.now()
        login_time = st.session_state.login_time
        elapsed_time = (current_time - login_time).total_seconds() / 60  # in minutes
        
        if elapsed_time > timeout_minutes:
            logout_user()
            st.warning(f"Your session has expired after {timeout_minutes} minutes of inactivity. Please log in again.")
            return True
    return False

def log_user_activity(user_id, activity_type, session_id):
    """Log user activity in Firebase"""
    activity_data = {
        "user_id": user_id,
        "activity_type": activity_type,
        "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "session_id": session_id,
        "ip_address": get_client_ip()
    }
    
    # Add activity to the activity logs collection
    db.child("activity_logs").push(activity_data)

def get_client_ip():
    """Get client IP address (note: this is a simplified version for Streamlit)"""
    # Actual implementation may vary depending on hosting environment
    return "127.0.0.1"  # Placeholder

def render_login_page():
    """Render the login page UI"""
    st.title("🛡️ SIEM Dashboard Login")
    
    with st.form("login_form"):
        email = st.text_input("Email", key="login_email")
        password = st.text_input("Password", type="password", key="login_password")
        submit = st.form_submit_button("Login")
        
        if submit:
            if not email or not password:
                st.error("Please enter both email and password")
            else:
                success, message, user, user_info = login_user(email, password)
                if success:
                    st.session_state.user = user
                    st.session_state.user_info = user_info
                    st.session_state.authenticated = True
                    st.session_state.user_role = user_info.get('role', 'viewer')
                    st.session_state.login_time = datetime.datetime.now()
                    st.session_state.session_id = str(uuid.uuid4())
                    st.success("Login successful! Redirecting to dashboard...")
                    st.session_state.page = "dashboard"
                    st.rerun()
                else:
                    st.error(f"Login failed: {message}")
    
    st.markdown("---")
    if st.button("Don't have an account? Sign up", key="to_signup"):
        st.session_state.page = "signup"
        st.rerun()

def render_signup_page():
    """Render the signup page UI"""
    st.title("🛡️ SIEM Dashboard - Create Account")
    
    with st.form("signup_form"):
        col1, col2 = st.columns(2)
        with col1:
            first_name = st.text_input("First Name")
        with col2:
            last_name = st.text_input("Last Name")
            
        email = st.text_input("Email")
        password = st.text_input("Password", type="password")
        confirm_password = st.text_input("Confirm Password", type="password")
        
        # Modified section - Always show both Admin and Viewer options
        role_options = ["Admin", "Viewer"]
        role = st.selectbox("Account Type", role_options)
        
        submit = st.form_submit_button("Create Account")
        
        if submit:
            # Form validation
            if not all([first_name, last_name, email, password, confirm_password]):
                st.error("Please fill out all fields")
            elif not validate_email(email):
                st.error("Please enter a valid email address")
            elif password != confirm_password:
                st.error("Passwords do not match")
            else:
                # Validate password strength
                is_valid, password_message = validate_password(password)
                if not is_valid:
                    st.error(password_message)
                else:
                    # Create user in Firebase
                    success, message = create_user(email, password, role.lower(), first_name, last_name)
                    if success:
                        st.success("Account created successfully! Please log in.")
                        # Redirect to login page after successful signup
                        st.session_state.page = "login"
                        st.rerun()
                    else:
                        st.error(f"Signup failed: {message}")
    
    st.markdown("---")
    if st.button("Already have an account? Log in",key="to_login"):
        st.session_state.page = "login"
        st.rerun()

def is_admin():
    """Check if the current user has admin privileges"""
    return st.session_state.authenticated and st.session_state.user_role.lower() == "admin"

def require_auth(page_function, require_admin=False):
    """Decorator-like function to require authentication before accessing a page"""
    init_session_state()
    
    # Check for session timeout
    if check_session_timeout():
        render_login_page()
        return
    
    # If not authenticated, show login page
    if not st.session_state.authenticated:
        render_login_page()
        return
    
    # If admin required but user is not admin, show unauthorized message
    if require_admin and not is_admin():
        st.error("You do not have permission to access this page. This action requires administrator privileges.")
        if st.button("Return to Dashboard"):
            st.session_state.page = "dashboard"
            st.rerun()
        return
    
    # If all checks pass, render the requested page
    page_function()

def render_user_profile():
    """Display and allow editing of user profile"""
    st.title("👤 User Profile")
    
    if not st.session_state.user_info:
        st.error("User profile not found")
        return
    
    user_info = st.session_state.user_info
    
    col1, col2 = st.columns(2)
    with col1:
        st.subheader("Account Information")
        st.write(f"**Name:** {user_info.get('first_name', '')} {user_info.get('last_name', '')}")
        st.write(f"**Email:** {user_info.get('email', '')}")
        st.write(f"**Role:** {user_info.get('role', '').capitalize()}")
        st.write(f"**Account Created:** {user_info.get('created_at', '')}")
        st.write(f"**Last Login:** {user_info.get('last_login', '')}")
    
    with col2:
        st.subheader("Update Profile")
        with st.form("update_profile"):
            first_name = st.text_input("First Name", value=user_info.get('first_name', ''))
            last_name = st.text_input("Last Name", value=user_info.get('last_name', ''))
            submit = st.form_submit_button("Update Profile")
            
            if submit:
                try:
                    # Update profile information
                    db.child("users").child(st.session_state.user['localId']).update({
                        "first_name": first_name,
                        "last_name": last_name,
                    })
                    # Update session state
                    st.session_state.user_info.update({
                        "first_name": first_name,
                        "last_name": last_name,
                    })
                    st.success("Profile updated successfully!")
                except Exception as e:
                    st.error(f"Failed to update profile: {e}")
    
    st.subheader("Change Password")
    with st.form("change_password"):
        current_password = st.text_input("Current Password", type="password")
        new_password = st.text_input("New Password", type="password")
        confirm_new_password = st.text_input("Confirm New Password", type="password")
        submit = st.form_submit_button("Change Password")
        
        if submit:
            if not all([current_password, new_password, confirm_new_password]):
                st.error("Please fill out all password fields")
            elif new_password != confirm_new_password:
                st.error("New passwords do not match")
            else:
                # Validate password strength
                is_valid, password_message = validate_password(new_password)
                if not is_valid:
                    st.error(password_message)
                else:
                    try:
                        # Re-authenticate user with current password
                        user = auth.sign_in_with_email_and_password(user_info.get('email', ''), current_password)
                        # Update password
                        auth.change_password(user['idToken'], new_password)
                        st.success("Password changed successfully!")
                    except Exception as e:
                        st.error(f"Failed to change password: {e}")

# Admin functions
def render_user_management():
    """Admin page for managing users"""
    if not is_admin():
        st.error("You do not have permission to access this page")
        return
    
    st.title("👥 User Management")
    
    # Get all users from database
    try:
        users = db.child("users").get().val()
        if not users:
            st.info("No users found")
            return
        
        # Convert to list
        users_list = [{"id": uid, **user_data} for uid, user_data in users.items()]
        
        # Display users in a dataframe
        users_df = pd.DataFrame([
            {
                "Name": f"{user.get('first_name', '')} {user.get('last_name', '')}",
                "Email": user.get('email', ''),
                "Role": user.get('role', '').capitalize(),
                "Created": user.get('created_at', ''),
                "Last Login": user.get('last_login', ''),
                "ID": user.get('id', '')
            }
            for user in users_list
        ])
        
        st.dataframe(users_df[["Name", "Email", "Role", "Created", "Last Login"]])
        
        # User management actions
        st.subheader("User Actions")
        
        # Select user
        selected_user_email = st.selectbox("Select User", [u.get('email', '') for u in users_list])
        selected_user = next((u for u in users_list if u.get('email', '') == selected_user_email), None)
        
        if selected_user:
            col1, col2 = st.columns(2)
            
            with col1:
                # Change role
                new_role = st.selectbox("Change Role", 
                                       ["admin", "viewer"], 
                                       index=0 if selected_user.get('role', '').lower() == 'admin' else 1)
                
                if st.button("Update Role"):
                    try:
                        db.child("users").child(selected_user['id']).update({"role": new_role})
                        st.success(f"Updated role for {selected_user_email} to {new_role}")
                    except Exception as e:
                        st.error(f"Failed to update role: {e}")
            
            with col2:
                # Delete user (dangerous operation)
                if st.button("Delete User", help="This will permanently delete the user account"):
                    confirmation = st.text_input(
                        "Type the user's email to confirm deletion", 
                        key="delete_confirmation"
                    )
                    
                    confirm_delete = st.button("Confirm Delete")
                    if confirmation == selected_user_email and confirm_delete:
                        try:
                            # In a production system, you would use Firebase Admin SDK to delete the user
                            # Here we just delete from the database
                            db.child("users").child(selected_user['id']).remove()
                            st.success(f"Deleted user {selected_user_email}")
                        except Exception as e:
                            st.error(f"Failed to delete user: {e}")
        
        # Create new admin user
        st.subheader("Create New Admin")
        
        with st.form("create_admin"):
            col1, col2 = st.columns(2)
            with col1:
                first_name = st.text_input("First Name", key="admin_first_name")
            with col2:
                last_name = st.text_input("Last Name", key="admin_last_name")
                
            email = st.text_input("Email", key="admin_email")
            password = st.text_input("Password", type="password", key="admin_password")
            confirm_password = st.text_input("Confirm Password", type="password", key="admin_confirm")
            
            submit = st.form_submit_button("Create Admin User")
            
            if submit:
                # Form validation
                if not all([first_name, last_name, email, password, confirm_password]):
                    st.error("Please fill out all fields")
                elif not validate_email(email):
                    st.error("Please enter a valid email address")
                elif password != confirm_password:
                    st.error("Passwords do not match")
                else:
                    # Validate password strength
                    is_valid, password_message = validate_password(password)
                    if not is_valid:
                        st.error(password_message)
                    else:
                        # Create admin user in Firebase
                        success, message = create_user(email, password, "admin", first_name, last_name)
                        if success:
                            st.success("Admin account created successfully!")
                        else:
                            st.error(f"Admin creation failed: {message}")
    
    except Exception as e:
        st.error(f"Error loading users: {e}")

# Activity logging functions
def render_audit_logs():
    """Admin page for viewing audit logs"""
    if not is_admin():
        st.error("You do not have permission to access this page")
        return
    
    st.title("📊 Audit Logs")
    
    # Get activity logs from database
    try:
        logs = db.child("activity_logs").order_by_child("timestamp").limit_to_last(100).get().val()
        if not logs:
            st.info("No activity logs found")
            return
        
        # Convert to list
        logs_list = [{"id": log_id, **log_data} for log_id, log_data in logs.items()]
        
        # Sort by timestamp (descending)
        logs_list.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
        
        # Display logs
        st.subheader("Recent Activity")
        
        # Filter options
        col1, col2 = st.columns(2)
        with col1:
            activity_types = ["All"] + list(set(log.get('activity_type', '') for log in logs_list))
            selected_activity = st.selectbox("Filter by Activity Type", activity_types)
        
        with col2:
            # Get user emails for filtering
            user_ids = list(set(log.get('user_id', '') for log in logs_list))
            users = {}
            for user_id in user_ids:
                user_data = db.child("users").child(user_id).get().val()
                if user_data:
                    users[user_id] = user_data.get('email', user_id)
                else:
                    users[user_id] = user_id
            
            user_options = ["All"] + list(users.values())
            selected_user = st.selectbox("Filter by User", user_options)
        
        # Apply filters
        filtered_logs = logs_list
        if selected_activity != "All":
            filtered_logs = [log for log in filtered_logs if log.get('activity_type', '') == selected_activity]
        
        if selected_user != "All":
            selected_user_id = next((uid for uid, email in users.items() if email == selected_user), None)
            if selected_user_id:
                filtered_logs = [log for log in filtered_logs if log.get('user_id', '') == selected_user_id]
        
        # Create dataframe for display
        logs_df = pd.DataFrame([
            {
                "Time": log.get('timestamp', ''),
                "User": users.get(log.get('user_id', ''), log.get('user_id', '')),
                "Activity": log.get('activity_type', '').capitalize(),
                "Session ID": log.get('session_id', '')[:8] + "...",  # Truncate for display
                "IP Address": log.get('ip_address', '')
            }
            for log in filtered_logs
        ])
        
        st.dataframe(logs_df)
        
        # Export options
        if st.button("Export Logs (CSV)"):
            csv = logs_df.to_csv(index=False)
            st.download_button(
                label="Download CSV",
                data=csv,
                file_name=f"siem_audit_logs_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv"
            )
    
    except Exception as e:
        st.error(f"Error loading audit logs: {e}")

def render_navbar():
    """Render the navigation bar with conditional elements based on authentication status"""
    if st.session_state.authenticated:
        col1, col2, col3, col4 = st.columns([1, 6, 2, 1])
        
        with col1:
            st.image("https://via.placeholder.com/50", width=50)  # Replace with your logo
        
        with col2:
            st.title("🛡️ SIEM Dashboard")
        
        with col3:
            st.write(f"👤 {st.session_state.user_info.get('first_name', 'User')}")
            
        with col4:
            if st.button("Logout"):
                logout_user()
                st.rerun()
    
    # Add a separator
    st.markdown("---")

# Main application entry point
def main():
    st.set_page_config(
        page_title="SIEM Dashboard",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded"
    )
    
    # Initialize session state
    init_session_state()
    
    # Create sidebar navigation
    with st.sidebar:
        st.title("🛡️ SIEM Dashboard")
        st.markdown("---")
        
        if st.session_state.authenticated:
            # Main navigation
            st.subheader("Navigation")
            pages = {
                "Dashboard": "dashboard",
                "Alerts": "alerts",
                "Reports": "reports",
                "User Profile": "profile"
            }
            
            # Add admin pages if user is admin
            if is_admin():
                pages.update({
                    "User Management": "user_management",
                    "Audit Logs": "audit_logs",
                    "System Settings": "settings"
                })
            
            selected_page = st.radio("Go to", list(pages.keys()))
            st.session_state.page = pages[selected_page]
            
            st.markdown("---")
            if st.button("Logout", key="sidebar_logout"):
                logout_user()
                st.rerun()
        else:
            # Authentication options
            auth_options = ["Login", "Sign Up"]
            selected_auth = st.radio("Authentication", auth_options)
            
            if selected_auth == "Login":
                st.session_state.page = "login"
            else:
                st.session_state.page = "signup"
    
    # Render appropriate page based on selection
    if st.session_state.page == "login":
        render_login_page()
    elif st.session_state.page == "signup":
        render_signup_page()
    elif st.session_state.page == "profile":
        require_auth(render_user_profile)
    elif st.session_state.page == "user_management":
        require_auth(render_user_management, require_admin=True)
    elif st.session_state.page == "audit_logs":
        require_auth(render_audit_logs, require_admin=True)
    elif st.session_state.page == "dashboard":
        require_auth(render_dashboard)
    elif st.session_state.page == "alerts":
        require_auth(render_alerts)
    elif st.session_state.page == "reports":
        require_auth(render_reports)
    elif st.session_state.page == "settings":
        require_auth(render_settings, require_admin=True)

def render_dashboard():
    """Render the main dashboard page"""
    st.title("📊 SIEM Dashboard")
    st.write(f"Welcome back, {st.session_state.user_info.get('first_name', 'User')}!")
    
    # Dashboard metrics
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric(label="Active Alerts", value="24", delta="4")
    with col2:
        st.metric(label="Security Score", value="87%", delta="3%")
    with col3:
        st.metric(label="Systems Monitored", value="42", delta="-1")
    with col4:
        st.metric(label="Incidents (24h)", value="3", delta="-2")
    
    # Dashboard charts and visualizations would go here
    st.subheader("Recent Security Events")
    
    # Placeholder for chart
    st.line_chart({"Low": [3, 4, 2, 5, 3, 6, 4], 
                   "Medium": [2, 1, 3, 2, 4, 1, 2], 
                   "High": [0, 1, 0, 2, 1, 0, 1],
                   "Critical": [0, 0, 1, 0, 0, 0, 1]})
    
    st.subheader("Top Alert Sources")
    source_data = pd.DataFrame({
        "Source": ["Firewall", "IDS", "Server Logs", "Authentication", "Network"],
        "Count": [45, 32, 28, 15, 9]
    })
    st.bar_chart(source_data.set_index("Source"))
    
    # Recent alerts table
    st.subheader("Recent Critical Alerts")
    alerts_data = {
        "Time": ["2025-05-11 09:34:12", "2025-05-11 08:22:45", "2025-05-10 23:45:30", "2025-05-10 21:12:08"],
        "Source": ["Firewall", "IDS", "Authentication", "Server"],
        "Description": [
            "Multiple failed SSH attempts",
            "Possible SQL injection attempt",
            "Privilege escalation detected",
            "Unusual file access pattern"
        ],
        "Status": ["New", "Investigating", "New", "Resolved"]
    }
    st.dataframe(pd.DataFrame(alerts_data))

# Completing the alerts_data dictionary and render_alerts function
def render_alerts():
    """Render the alerts page"""
    st.title("⚠️ Security Alerts")
    
    # Filters
    col1, col2, col3 = st.columns(3)
    with col1:
        severity = st.multiselect("Severity", ["Critical", "High", "Medium", "Low"], default=["Critical", "High"])
    with col2:
        status = st.multiselect("Status", ["New", "Investigating", "Resolved", "False Positive"], default=["New", "Investigating"])
    with col3:
        date_range = st.date_input("Date Range", [datetime.datetime.now() - datetime.timedelta(days=7), datetime.datetime.now()])
    
    # Alert listing
    alerts_data = {
        "Time": [
            "2025-05-11 09:34:12", "2025-05-11 08:22:45", "2025-05-10 23:45:30", 
            "2025-05-10 21:12:08", "2025-05-10 16:45:32", "2025-05-10 14:22:10",
            "2025-05-09 22:15:40", "2025-05-09 18:34:22", "2025-05-09 12:45:11"
        ],
        "Severity": [
            "High", "Critical", "High", "Medium", "Critical", "Low",
            "Medium", "High", "Low"
        ],
        "Source": [
            "Firewall", "IDS", "Authentication", "Server", "Network", "Endpoint",
            "IDS", "Firewall", "Server"
        ],
        "Description": [
            "Multiple failed SSH attempts", 
            "Possible SQL injection attempt", 
            "Privilege escalation detected", 
            "Unusual file access pattern",
            "DDoS attack signature detected",
            "Unusual user login time",
            "Suspicious outbound traffic",
            "Brute force attempt blocked",
            "Non-compliant system detected"
        ],
        "Status": [
            "New", "Investigating", "New", "Resolved", "Investigating", "Resolved",
            "False Positive", "New", "Resolved"
        ]
    }
    
    # Create DataFrame
    alerts_df = pd.DataFrame(alerts_data)
    
    # Apply filters
    filtered_df = alerts_df[
        alerts_df["Severity"].isin(severity) &
        alerts_df["Status"].isin(status)
    ]
    
    # Show filtered alerts
    if len(filtered_df) > 0:
        st.dataframe(filtered_df)
    else:
        st.info("No alerts match your filters")
    
    # Alert details
    st.subheader("Alert Details")
    selected_alert = st.selectbox("Select Alert to View Details", 
                                 filtered_df["Description"].tolist() if not filtered_df.empty else ["No alerts available"])
    
    if selected_alert != "No alerts available":
        alert_details = filtered_df[filtered_df["Description"] == selected_alert].iloc[0]
        
        col1, col2 = st.columns(2)
        with col1:
            st.write(f"**Time:** {alert_details['Time']}")
            st.write(f"**Source:** {alert_details['Source']}")
            st.write(f"**Severity:** {alert_details['Severity']}")
        
        with col2:
            st.write(f"**Status:** {alert_details['Status']}")
            st.write(f"**Description:** {alert_details['Description']}")
        
        # Alert actions
        st.subheader("Actions")
        action_col1, action_col2, action_col3 = st.columns(3)
        
        with action_col1:
            if st.button("Mark as Investigating"):
                st.success(f"Alert '{selected_alert}' marked as Investigating")
        
        with action_col2:
            if st.button("Mark as Resolved"):
                st.success(f"Alert '{selected_alert}' marked as Resolved")
        
        with action_col3:
            if st.button("Mark as False Positive"):
                st.success(f"Alert '{selected_alert}' marked as False Positive")

def render_reports():
    """Render the reports page"""
    st.title("📈 Security Reports")
    
    # Report type selection
    report_type = st.selectbox(
        "Select Report Type",
        ["Security Overview", "Alert Summary", "User Activity", "Compliance Status", "Custom Report"]
    )
    
    # Date range for report
    col1, col2 = st.columns(2)
    with col1:
        start_date = st.date_input("Start Date", datetime.datetime.now() - datetime.timedelta(days=30))
    with col2:
        end_date = st.date_input("End Date", datetime.datetime.now())
    
    # Generate report button
    if st.button("Generate Report"):
        with st.spinner("Generating report..."):
            # Simulate report generation delay
            time.sleep(2)
            
            st.success("Report generated successfully!")
            
            # Display appropriate report based on selection
            if report_type == "Security Overview":
                render_security_overview_report(start_date, end_date)
            elif report_type == "Alert Summary":
                render_alert_summary_report(start_date, end_date)
            elif report_type == "User Activity":
                render_user_activity_report(start_date, end_date)
            elif report_type == "Compliance Status":
                render_compliance_report(start_date, end_date)
            elif report_type == "Custom Report":
                render_custom_report(start_date, end_date)

def render_security_overview_report(start_date, end_date):
    """Render security overview report"""
    st.subheader("Security Overview Report")
    st.write(f"Period: {start_date} to {end_date}")
    
    # Summary metrics
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric(label="Total Alerts", value="137")
    with col2:
        st.metric(label="Critical Alerts", value="12")
    with col3:
        st.metric(label="Avg. Response Time", value="27 min")
    with col4:
        st.metric(label="Security Score", value="87%")
    
    # Alert trend chart
    st.subheader("Alert Trends")
    dates = pd.date_range(start=start_date, end=end_date, freq='D')
    trend_data = pd.DataFrame({
        "Date": dates,
        "Critical": np.random.randint(0, 3, size=len(dates)),
        "High": np.random.randint(1, 8, size=len(dates)),
        "Medium": np.random.randint(2, 12, size=len(dates)),
        "Low": np.random.randint(3, 15, size=len(dates))
    })
    st.line_chart(trend_data.set_index("Date"))
    
    # Top sources pie chart
    st.subheader("Alert Sources")
    source_data = {
        "Source": ["Firewall", "IDS", "Authentication", "Server Logs", "Network", "Endpoint"],
        "Count": [45, 32, 28, 15, 9, 8]
    }
    source_df = pd.DataFrame(source_data)
    st.bar_chart(source_df.set_index("Source"))
    
    # Export options
    if st.button("Export Report (PDF)"):
        st.info("PDF export functionality would be implemented here")
    
    if st.button("Export Data (CSV)"):
        # Create CSV for download
        csv = trend_data.to_csv(index=False)
        st.download_button(
            label="Download CSV",
            data=csv,
            file_name=f"security_overview_{start_date}_to_{end_date}.csv",
            mime="text/csv"
        )

def render_alert_summary_report(start_date, end_date):
    """Render alert summary report"""
    st.subheader("Alert Summary Report")
    st.write(f"Period: {start_date} to {end_date}")
    
    # Alert summary by severity
    st.subheader("Alerts by Severity")
    severity_data = {
        "Severity": ["Critical", "High", "Medium", "Low"],
        "Count": [12, 35, 48, 42]
    }
    severity_df = pd.DataFrame(severity_data)
    st.bar_chart(severity_df.set_index("Severity"))
    
    # Alert summary by status
    st.subheader("Alerts by Status")
    status_data = {
        "Status": ["New", "Investigating", "Resolved", "False Positive"],
        "Count": [24, 18, 82, 13]
    }
    status_df = pd.DataFrame(status_data)
    st.bar_chart(status_df.set_index("Status"))
    
    # Alert listing
    st.subheader("Top Critical Alerts")
    critical_alerts = {
        "Time": [
            "2025-05-11 08:22:45", 
            "2025-05-10 16:45:32",
            "2025-05-08 14:12:23",
            "2025-05-06 09:34:57",
            "2025-05-04 22:15:30"
        ],
        "Source": ["IDS", "Network", "Firewall", "Authentication", "Server"],
        "Description": [
            "Possible SQL injection attempt",
            "DDoS attack signature detected",
            "Multiple IPs blocked due to brute force",
            "Privilege escalation attempt detected",
            "Critical service failure"
        ],
        "Status": ["Investigating", "Investigating", "Resolved", "Resolved", "Resolved"]
    }
    st.dataframe(pd.DataFrame(critical_alerts))

def render_user_activity_report(start_date, end_date):
    """Render user activity report"""
    st.subheader("User Activity Report")
    st.write(f"Period: {start_date} to {end_date}")
    
    # User activity summary
    st.subheader("Login Activity")
    
    # Sample user data
    user_data = {
        "User": ["admin@example.com", "jsmith@example.com", "analyst@example.com", "operator@example.com"],
        "Login Count": [45, 32, 28, 19],
        "Last Login": ["2025-05-11 08:12:45", "2025-05-11 09:34:22", "2025-05-10 16:45:12", "2025-05-09 14:22:30"],
        "Failed Attempts": [0, 1, 0, 3]
    }
    st.dataframe(pd.DataFrame(user_data))
    
    # Activity timeline
    st.subheader("User Activity Timeline")
    dates = pd.date_range(start=start_date, end=end_date, freq='D')
    activity_data = pd.DataFrame({
        "Date": dates,
        "Logins": np.random.randint(3, 15, size=len(dates)),
        "User Management": np.random.randint(0, 5, size=len(dates)),
        "Configuration Changes": np.random.randint(0, 3, size=len(dates))
    })
    st.line_chart(activity_data.set_index("Date"))
    
    # Recent admin actions
    st.subheader("Recent Administrative Actions")
    admin_actions = {
        "Time": [
            "2025-05-11 10:15:22",
            "2025-05-10 16:32:45",
            "2025-05-09 14:22:30",
            "2025-05-08 09:45:12",
            "2025-05-07 11:34:56"
        ],
        "User": ["admin@example.com", "admin@example.com", "jsmith@example.com", "admin@example.com", "jsmith@example.com"],
        "Action": [
            "Created new user account",
            "Updated firewall rules",
            "Modified user permissions",
            "System configuration change",
            "Generated security report"
        ]
    }
    st.dataframe(pd.DataFrame(admin_actions))

def render_compliance_report(start_date, end_date):
    """Render compliance status report"""
    st.subheader("Compliance Status Report")
    st.write(f"Period: {start_date} to {end_date}")
    
    # Compliance score
    st.metric(label="Overall Compliance Score", value="92%", delta="3%")
    
    # Compliance by framework
    st.subheader("Compliance by Framework")
    framework_data = {
        "Framework": ["PCI DSS", "HIPAA", "GDPR", "SOC 2", "ISO 27001"],
        "Score": [95, 88, 94, 91, 90]
    }
    framework_df = pd.DataFrame(framework_data)
    st.bar_chart(framework_df.set_index("Framework"))
    
    # Non-compliant items
    st.subheader("Non-Compliant Items")
    non_compliant = {
        "Item": [
            "Password Policy",
            "Data Encryption",
            "Access Control",
            "Audit Logging",
            "Incident Response"
        ],
        "Framework": ["PCI DSS", "HIPAA", "GDPR", "SOC 2", "ISO 27001"],
        "Status": ["In Progress", "Not Implemented", "Partially Compliant", "In Progress", "Partially Compliant"],
        "Due Date": ["2025-06-01", "2025-05-30", "2025-06-15", "2025-07-01", "2025-06-10"]
    }
    st.dataframe(pd.DataFrame(non_compliant))
    
    # Remediation tasks
    st.subheader("Remediation Tasks")
    tasks = {
        "Task": [
            "Update password requirements",
            "Implement encryption for data at rest",
            "Review user access permissions",
            "Enhance audit logging capabilities",
            "Update incident response procedures"
        ],
        "Assigned To": ["jsmith@example.com", "admin@example.com", "analyst@example.com", "admin@example.com", "jsmith@example.com"],
        "Status": ["In Progress", "Not Started", "In Progress", "In Progress", "Not Started"],
        "Due Date": ["2025-05-20", "2025-05-25", "2025-06-01", "2025-06-15", "2025-05-30"]
    }
    st.dataframe(pd.DataFrame(tasks))

def render_custom_report(start_date, end_date):
    """Render custom report builder"""
    st.subheader("Custom Report Builder")
    st.write(f"Period: {start_date} to {end_date}")
    
    # Report components selection
    st.write("Select components to include in your report:")
    include_alerts = st.checkbox("Alert Summary", value=True)
    include_trends = st.checkbox("Trend Analysis", value=True)
    include_sources = st.checkbox("Alert Sources", value=True)
    include_users = st.checkbox("User Activity", value=False)
    include_compliance = st.checkbox("Compliance Status", value=False)
    
    # Display selected components
    if include_alerts:
        st.subheader("Alert Summary")
        severity_data = {
            "Severity": ["Critical", "High", "Medium", "Low"],
            "Count": [12, 35, 48, 42]
        }
        severity_df = pd.DataFrame(severity_data)
        st.bar_chart(severity_df.set_index("Severity"))
    
    if include_trends:
        st.subheader("Alert Trends")
        dates = pd.date_range(start=start_date, end=end_date, freq='D')
        trend_data = pd.DataFrame({
            "Date": dates,
            "Critical": np.random.randint(0, 3, size=len(dates)),
            "High": np.random.randint(1, 8, size=len(dates)),
            "Medium": np.random.randint(2, 12, size=len(dates)),
            "Low": np.random.randint(3, 15, size=len(dates))
        })
        st.line_chart(trend_data.set_index("Date"))
    
    if include_sources:
        st.subheader("Alert Sources")
        source_data = {
            "Source": ["Firewall", "IDS", "Authentication", "Server Logs", "Network", "Endpoint"],
            "Count": [45, 32, 28, 15, 9, 8]
        }
        source_df = pd.DataFrame(source_data)
        st.bar_chart(source_df.set_index("Source"))
    
    if include_users:
        st.subheader("User Activity")
        user_data = {
            "User": ["admin@example.com", "jsmith@example.com", "analyst@example.com", "operator@example.com"],
            "Login Count": [45, 32, 28, 19],
            "Last Login": ["2025-05-11 08:12:45", "2025-05-11 09:34:22", "2025-05-10 16:45:12", "2025-05-09 14:22:30"],
            "Failed Attempts": [0, 1, 0, 3]
        }
        st.dataframe(pd.DataFrame(user_data))
    
    if include_compliance:
        st.subheader("Compliance Status")
        framework_data = {
            "Framework": ["PCI DSS", "HIPAA", "GDPR", "SOC 2", "ISO 27001"],
            "Score": [95, 88, 94, 91, 90]
        }
        framework_df = pd.DataFrame(framework_data)
        st.bar_chart(framework_df.set_index("Framework"))
    
    # Export options
    if st.button("Export Custom Report"):
        st.success("Custom report generated!")
        st.info("Export functionality would be implemented here")

def render_settings():
    """Render system settings page (admin only)"""
    if not is_admin():
        st.error("You do not have permission to access this page")
        return
    
    st.title("⚙️ System Settings")
    
    # System settings tabs
    tab1, tab2, tab3, tab4 = st.tabs(["General", "Notifications", "Data Sources", "Backup & Restore"])
    
    with tab1:
        st.subheader("General Settings")
        
        with st.form("general_settings"):
            col1, col2 = st.columns(2)
            
            with col1:
                system_name = st.text_input("System Name", value="SIEM Dashboard")
                session_timeout = st.number_input("Session Timeout (minutes)", min_value=5, max_value=120, value=30)
            
            with col2:
                timezone = st.selectbox("System Timezone", ["UTC", "US/Eastern", "US/Central", "US/Pacific", "Europe/London"])
                date_format = st.selectbox("Date Format", ["YYYY-MM-DD", "MM/DD/YYYY", "DD/MM/YYYY"])
            
            submit = st.form_submit_button("Save General Settings")
            
            if submit:
                st.success("General settings updated successfully!")
    
    with tab2:
        st.subheader("Notification Settings")
        
        with st.form("notification_settings"):
            enable_email = st.checkbox("Enable Email Notifications", value=True)
            
            if enable_email:
                email_recipients = st.text_area("Email Recipients (one per line)", value="admin@example.com\nanalyst@example.com")
                
                st.subheader("Notification Triggers")
                notify_critical = st.checkbox("Critical Alerts", value=True)
                notify_high = st.checkbox("High Severity Alerts", value=True)
                notify_medium = st.checkbox("Medium Severity Alerts", value=False)
                notify_low = st.checkbox("Low Severity Alerts", value=False)
                notify_login = st.checkbox("Failed Login Attempts", value=True)
                
            enable_slack = st.checkbox("Enable Slack Notifications", value=False)
            
            if enable_slack:
                slack_webhook = st.text_input("Slack Webhook URL")
                slack_channel = st.text_input("Slack Channel", value="#security-alerts")
            
            submit = st.form_submit_button("Save Notification Settings")
            
            if submit:
                st.success("Notification settings updated successfully!")
    
    with tab3:
        st.subheader("Data Sources")
        
        # List existing data sources
        data_sources = [
            {"name": "Firewall", "type": "Syslog", "status": "Active", "last_update": "2025-05-11 08:12:45"},
            {"name": "IDS", "type": "API", "status": "Active", "last_update": "2025-05-11 09:34:22"},
            {"name": "Server Logs", "type": "File Import", "status": "Active", "last_update": "2025-05-11 07:45:30"},
            {"name": "Authentication", "type": "Database", "status": "Active", "last_update": "2025-05-11 06:22:15"},
            {"name": "Network Monitoring", "type": "SNMP", "status": "Inactive", "last_update": "2025-05-10 14:12:30"}
        ]
        
        st.dataframe(pd.DataFrame(data_sources))
        
        # Add new data source
        st.subheader("Add Data Source")
        with st.form("add_data_source"):
            col1, col2 = st.columns(2)
            
            with col1:
                source_name = st.text_input("Source Name")
                source_type = st.selectbox("Source Type", ["Syslog", "API", "File Import", "Database", "SNMP"])
            
            with col2:
                connection_string = st.text_input("Connection String")
                credentials = st.text_input("Credentials", type="password")
            
            submit = st.form_submit_button("Add Data Source")
            
            if submit:
                if not source_name or not connection_string:
                    st.error("Please fill out all required fields")
                else:
                    st.success(f"Data source '{source_name}' added successfully!")
    
    with tab4:
        st.subheader("Backup & Restore")
        
        # Backup section
        st.write("##### Create Backup")
        backup_col1, backup_col2 = st.columns(2)
        
        with backup_col1:
            backup_type = st.selectbox("Backup Type", ["Full", "Configuration Only", "Alerts Only", "User Data Only"])
        
        with backup_col2:
            encrypt_backup = st.checkbox("Encrypt Backup", value=True)
        
        if st.button("Create Backup"):
            with st.spinner("Creating backup..."):
                # Simulate backup process
                time.sleep(2)
                st.success("Backup created successfully!")
                st.download_button(
                    label="Download Backup File",
                    data=b"This would be a real backup file",
                    file_name=f"siem_backup_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.zip",
                    mime="application/zip"
                )
        
        # Restore section
        st.write("##### Restore from Backup")
        uploaded_file = st.file_uploader("Upload Backup File", type=["zip"])
        
        if uploaded_file is not None:
            if st.button("Restore from Backup"):
                st.warning("Warning: Restoring from backup will overwrite current data. This action cannot be undone.")
                confirm = st.checkbox("I understand and want to proceed with the restore")
                
                if confirm and st.button("Confirm Restore"):
                    with st.spinner("Restoring from backup..."):
                        # Simulate restore process
                        time.sleep(3)
                        st.success("System restored successfully from backup!")

# Missing imports
import numpy as np

# Run the application
if __name__ == "__main__":
    main()