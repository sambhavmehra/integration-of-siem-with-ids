import time
import streamlit as st
import pyrebase
import datetime
import pandas as pd
import json
import os

# Firebase configuration - replace with your Firebase project details
firebaseConfig = {
    "apiKey": "your-api-key",
    "authDomain": "your-project-id.firebaseapp.com",
    "databaseURL": "https://your-project-id-default-rtdb.firebaseio.com",
    "projectId": "your-project-id",
    "storageBucket": "your-project-id.appspot.com",
    "messagingSenderId": "your-messaging-sender-id",
    "appId": "your-app-id"
}

# Initialize Firebase
firebase = pyrebase.initialize_app(firebaseConfig)
auth = firebase.auth()
db = firebase.database()

# File to store user session info
USER_SESSION_FILE = "user_session.json"
BLOCKED_IPS_FILE = "blocked_ips.json"
USER_ROLES_FILE = "user_roles.json"

# Custom CSS for auth pages
auth_styles = """
<style>
    .auth-form {
        max-width: 500px;
        margin: 0 auto;
        padding: 20px;
        border-radius: 10px;
        background-color: #f5f5f5;
        box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
    }
    .auth-header {
        text-align: center;
        margin-bottom: 20px;
    }
    .auth-input {
        width: 100%;
        margin-bottom: 15px;
    }
    .auth-button {
        width: 100%;
        background-color: #4CAF50;
        color: white;
        padding: 10px;
        border: none;
        border-radius: 5px;
        cursor: pointer;
    }
    .auth-button:hover {
        background-color: #45a049;
    }
    .auth-switch {
        text-align: center;
        margin-top: 15px;
    }
    .user-info {
        background-color: #f0f8ff;
        padding: 10px;
        border-radius: 5px;
        margin-bottom: 15px;
    }
    .admin-section {
        border-left: 5px solid #4CAF50;
        padding-left: 15px;
        margin: 20px 0;
    }
    .user-card {
        background-color: #f5f5f5;
        padding: 10px;
        border-radius: 5px;
        margin-bottom: 10px;
        display: flex;
        justify-content: space-between;
        align-items: center;
    }
    .block-history-card {
        background-color: #f5f5f5;
        padding: 10px;
        border-radius: 5px;
        margin-bottom: 10px;
    }
</style>
"""

# Initialize user roles dictionary and save to file
def init_user_roles():
    if os.path.exists(USER_ROLES_FILE):
        with open(USER_ROLES_FILE, 'r') as f:
            return json.load(f)
    else:
        # Default admin email - change this to your email
        default_roles = {
            "admin@siem.com": "admin"
        }
        with open(USER_ROLES_FILE, 'w') as f:
            json.dump(default_roles, f)
        return default_roles

# Save user roles to file
def save_user_roles(roles):
    with open(USER_ROLES_FILE, 'w') as f:
        json.dump(roles, f)

# Save session to file
def save_session(user_info):
    with open(USER_SESSION_FILE, 'w') as f:
        json.dump(user_info, f)

# Load session from file
def load_session():
    if os.path.exists(USER_SESSION_FILE):
        with open(USER_SESSION_FILE, 'r') as f:
            try:
                return json.load(f)
            except json.JSONDecodeError:
                return None
    return None

# Clear session file
def clear_session():
    if os.path.exists(USER_SESSION_FILE):
        os.remove(USER_SESSION_FILE)

# Function to record IP block history
def record_ip_block(ip_address, reason, user_email):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Create a unique ID for the block record
    block_id = f"{ip_address}_{timestamp.replace(' ', '_').replace(':', '-')}"
    
    # Save to Firebase database
    db.child("ip_blocks").child(block_id).set({
        "ip": ip_address,
        "reason": reason,
        "blocked_by": user_email,
        "timestamp": timestamp
    })
    
    return timestamp

# Function to get all IP block history
def get_block_history():
    try:
        blocks = db.child("ip_blocks").get()
        if blocks.val():
            return blocks.val()
        return {}
    except Exception as e:
        st.error(f"Error fetching block history: {e}")
        return {}

# Get all users
def get_all_users():
    try:
        users = db.child("users").get()
        if users.val():
            return users.val()
        return {}
    except Exception as e:
        st.error(f"Error fetching users: {e}")
        return {}

# Delete a user (admin only)
def delete_user(user_id):
    try:
        # First remove from roles file
        roles = init_user_roles()
        user_email = db.child("users").child(user_id).child("email").get().val()
        if user_email in roles:
            del roles[user_email]
            save_user_roles(roles)
        
        # Then remove from Firebase DB
        db.child("users").child(user_id).remove()
        return True
    except Exception as e:
        st.error(f"Error deleting user: {e}")
        return False

# Authentication pages
def show_login_page():
    st.markdown(auth_styles, unsafe_allow_html=True)
    st.markdown("<h1 class='auth-header'>🛡️ SIEM Dashboard Login</h1>", unsafe_allow_html=True)
    
    with st.container():
        st.markdown("<div class='auth-form'>", unsafe_allow_html=True)
        email = st.text_input("Email", key="login_email")
        password = st.text_input("Password", type="password", key="login_password")
        
        col1, col2 = st.columns(2)
        with col1:
            login_button = st.button("Login")
        with col2:
            reset_password = st.button("Reset Password")
            
        st.markdown("<div class='auth-switch'>Don't have an account? <a href='#' id='show-signup'>Sign Up</a></div>", unsafe_allow_html=True)
        st.markdown("</div>", unsafe_allow_html=True)
        
        if login_button:
            if not email or not password:
                st.error("Please fill in all fields")
                return False
                
            try:
                user = auth.sign_in_with_email_and_password(email, password)
                user_info = auth.get_account_info(user['idToken'])
                
                # Load user roles
                roles = init_user_roles()
                role = roles.get(email, "user")  # Default to 'user' if not found
                
                # Create session
                session_data = {
                    "email": email,
                    "uid": user_info['users'][0]['localId'],
                    "role": role,
                    "last_login": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                }
                
                # Save user to Firebase if not exists
                db.child("users").child(user_info['users'][0]['localId']).update({
                    "email": email,
                    "last_login": session_data["last_login"]
                })
                
                # Save session locally
                save_session(session_data)
                
                st.success("Login successful!")
                st.experimental_rerun()
                return True
                
            except Exception as e:
                error_message = str(e)
                if "INVALID_PASSWORD" in error_message:
                    st.error("Invalid password. Please try again.")
                elif "EMAIL_NOT_FOUND" in error_message:
                    st.error("Email not found. Please sign up.")
                else:
                    st.error(f"Login failed: {error_message}")
                return False
                
        if reset_password:
            if not email:
                st.error("Please enter your email address")
                return False
                
            try:
                auth.send_password_reset_email(email)
                st.success("Password reset email sent. Please check your inbox.")
            except Exception as e:
                st.error(f"Failed to send reset email: {str(e)}")
    
    # Add JavaScript to handle tab switching
    st.markdown("""
    <script>
        document.getElementById('show-signup').addEventListener('click', function(e) {
            e.preventDefault();
            // This would normally change tabs, but we'll use Streamlit session state instead
            sessionStorage.setItem('auth_mode', 'signup');
            window.location.reload();
        });
    </script>
    """, unsafe_allow_html=True)
    
    return False

def show_signup_page():
    st.markdown(auth_styles, unsafe_allow_html=True)
    st.markdown("<h1 class='auth-header'>🛡️ SIEM Dashboard Sign Up</h1>", unsafe_allow_html=True)
    
    with st.container():
        st.markdown("<div class='auth-form'>", unsafe_allow_html=True)
        email = st.text_input("Email", key="signup_email")
        password = st.text_input("Password", type="password", key="signup_password")
        confirm_password = st.text_input("Confirm Password", type="password", key="confirm_password")
        
        signup_button = st.button("Sign Up")
        
        st.markdown("<div class='auth-switch'>Already have an account? <a href='#' id='show-login'>Login</a></div>", unsafe_allow_html=True)
        st.markdown("</div>", unsafe_allow_html=True)
        
        if signup_button:
            if not email or not password or not confirm_password:
                st.error("Please fill in all fields")
                return False
                
            if password != confirm_password:
                st.error("Passwords do not match")
                return False
                
            try:
                user = auth.create_user_with_email_and_password(email, password)
                user_info = auth.get_account_info(user['idToken'])
                
                # Default role for new users is 'user'
                roles = init_user_roles()
                roles[email] = "user"  # Assign user role
                save_user_roles(roles)
                
                # Save user to Firebase
                db.child("users").child(user_info['users'][0]['localId']).set({
                    "email": email,
                    "created_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "role": "user"
                })
                
                st.success("Account created successfully! Please login.")
                
                # Switch to login page after successful signup
                time.sleep(2)
                st.session_state.auth_mode = "login"
                st.experimental_rerun()
                return True
                
            except Exception as e:
                error_message = str(e)
                if "EMAIL_EXISTS" in error_message:
                    st.error("Email already exists. Please login.")
                elif "WEAK_PASSWORD" in error_message:
                    st.error("Password should be at least 6 characters")
                else:
                    st.error(f"Sign up failed: {error_message}")
                return False
    
    # Add JavaScript to handle tab switching
    st.markdown("""
    <script>
        document.getElementById('show-login').addEventListener('click', function(e) {
            e.preventDefault();
            // This would normally change tabs, but we'll use Streamlit session state instead
            sessionStorage.setItem('auth_mode', 'login');
            window.location.reload();
        });
    </script>
    """, unsafe_allow_html=True)
    
    return False

# Show user management page (admin only)
def show_user_management():
    st.markdown("<h2>👥 User Management</h2>", unsafe_allow_html=True)
    
    users = get_all_users()
    roles = init_user_roles()
    
    if users:
        st.write(f"Total users: {len(users)}")
        
        # Filter options
        role_filter = st.selectbox("Filter by role", ["All", "admin", "user"])
        
        filtered_users = {}
        for uid, user_data in users.items():
            user_email = user_data.get("email", "")
            user_role = roles.get(user_email, "user")
            
            if role_filter == "All" or user_role == role_filter:
                filtered_users[uid] = {**user_data, "role": user_role}
        
        # Display users
        for uid, user_data in filtered_users.items():
            with st.container():
                col1, col2 = st.columns([3, 1])
                
                with col1:
                    st.markdown(f"""
                    <div class='user-card'>
                        <div>
                            <strong>Email:</strong> {user_data.get('email', 'N/A')}<br>
                            <strong>Role:</strong> {user_data.get('role', 'user')}<br>
                            <strong>Last Login:</strong> {user_data.get('last_login', 'Never')}
                        </div>
                    </div>
                    """, unsafe_allow_html=True)
                
                with col2:
                    # Don't allow admins to delete themselves or other admins
                    current_user = load_session()
                    if current_user and current_user["email"] != user_data.get("email", "") and user_data.get("role", "user") != "admin":
                        if st.button("Delete", key=f"delete_{uid}"):
                            if delete_user(uid):
                                st.success(f"User {user_data.get('email', '')} deleted!")
                                st.experimental_rerun()
                    
                    # Option to change role
                    new_role = "admin" if user_data.get("role", "user") == "user" else "user"
                    if st.button(f"Make {new_role}", key=f"role_{uid}"):
                        roles[user_data.get("email", "")] = new_role
                        save_user_roles(roles)
                        st.success(f"User role updated to {new_role}!")
                        st.experimental_rerun()
    else:
        st.info("No users found.")

# Show IP blocking history (admin only)
def show_block_history():
    st.markdown("<h2>🚫 IP Blocking History</h2>", unsafe_allow_html=True)
    
    block_history = get_block_history()
    
    if block_history:
        # Convert to DataFrame for easy filtering
        history_list = []
        for block_id, block_data in block_history.items():
            history_list.append(block_data)
        
        history_df = pd.DataFrame(history_list)
        
        # Filter options
        col1, col2 = st.columns(2)
        with col1:
            # Filter by user
            users = ["All"] + list(history_df["blocked_by"].unique())
            selected_user = st.selectbox("Filter by user", users)
        
        with col2:
            # Date range filter
            date_range = st.date_input(
                "Filter by date range",
                [
                    datetime.datetime.now() - datetime.timedelta(days=7),
                    datetime.datetime.now()
                ]
            )
        
        # Apply filters
        if selected_user != "All":
            history_df = history_df[history_df["blocked_by"] == selected_user]
        
        if len(date_range) == 2:
            start_date, end_date = date_range
            history_df["date"] = pd.to_datetime(history_df["timestamp"]).dt.date
            history_df = history_df[
                (history_df["date"] >= start_date) & 
                (history_df["date"] <= end_date)
            ]
        
        # Display history
        if not history_df.empty:
            for _, block in history_df.iterrows():
                st.markdown(f"""
                <div class='block-history-card'>
                    <strong>IP Address:</strong> {block["ip"]}<br>
                    <strong>Blocked by:</strong> {block["blocked_by"]}<br>
                    <strong>Date:</strong> {block["timestamp"]}<br>
                    <strong>Reason:</strong> {block["reason"]}
                </div>
                """, unsafe_allow_html=True)
        else:
            st.info("No blocking history found with the selected filters.")
    else:
        st.info("No IP blocking history found.")

# Main auth flow
def auth_flow():
    # Initialize session state
    if "auth_mode" not in st.session_state:
        st.session_state.auth_mode = "login"
    
    # Check if user is already logged in
    user_session = load_session()
    
    if user_session:
        return user_session
    else:
        # Show login or signup page
        if st.session_state.auth_mode == "login":
            show_login_page()
        else:
            show_signup_page()
        
        # Add option to switch between login and signup
        col1, col2 = st.columns(2)
        with col1:
            if st.button("Go to Login" if st.session_state.auth_mode == "signup" else "Go to Signup"):
                st.session_state.auth_mode = "login" if st.session_state.auth_mode == "signup" else "signup"
                st.experimental_rerun()
        
        return None

# Function to block IP with user tracking
def block_ip_with_user(ip_address, reason, user_email):
    # First, record the block in Firebase
    timestamp = record_ip_block(ip_address, reason, user_email)
    
    # Then block the IP using the original blocking function
    # This function needs to be imported from your original code
    # block_ip(ip_address, reason)
    
    return timestamp

# Logout function
def logout():
    clear_session()
    st.success("Logged out successfully!")
    st.experimental_rerun()