import streamlit as st
import firebase_admin
from firebase_admin import credentials, auth, firestore
import json
import os
from datetime import datetime
import uuid
import re

# Initialize Firebase if not already initialized
if not firebase_admin._apps:
    # Load Firebase credentials from a JSON file
    # Make sure to create a firebase_credentials.json file with your Firebase project credentials
    if os.path.exists("config.js"):
        cred = credentials.Certificate("firebase_credentials.json")
        firebase_admin.initialize_app(cred)
    else:
        st.error("Firebase credentials file not found. Please create firebase_credentials.json")
        st.stop()

# Initialize Firestore database
db = firestore.client()

# Session state initialization
if 'logged_in' not in st.session_state:
    st.session_state.logged_in = False

if 'user_info' not in st.session_state:
    st.session_state.user_info = {
        "uid": None,
        "email": None,
        "name": None,
        "role": None
    }

def is_valid_email(email):
    """Check if the email is valid using regex"""
    email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(email_regex, email) is not None

def is_strong_password(password):
    """Check if the password is strong enough"""
    # At least 8 characters, 1 uppercase, 1 lowercase, 1 number
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    if not any(c.isupper() for c in password):
        return False, "Password must contain at least one uppercase letter"
    if not any(c.islower() for c in password):
        return False, "Password must contain at least one lowercase letter"
    if not any(c.isdigit() for c in password):
        return False, "Password must contain at least one number"
    return True, "Password is strong"

def signup_user(email, password, full_name):
    """Create a new user account with Firebase Auth and Firestore"""
    try:
        # Create user in Firebase Authentication
        user = auth.create_user(
            email=email,
            password=password,
            display_name=full_name
        )
        
        # Add user to Firestore with default role as 'user'
        db.collection('users').document(user.uid).set({
            'uid': user.uid,
            'email': email,
            'name': full_name,
            'role': 'user',  # Default role
            'created_at': datetime.now(),
            'last_login': datetime.now()
        })
        
        return True, user.uid
    except Exception as e:
        return False, str(e)

def login_user(email, password):
    """Authenticate a user with Firebase Auth and update Firestore"""
    try:
        # Import PyJWT for Firebase ID token verification
        import jwt
        
        # Get user by email
        users = auth.get_users_by_email(email)
        if not users.users:
            return False, "User not found"
        
        user = users.users[0]
        
        # In a real application, you would verify the password with Firebase Auth REST API
        # Here's a simplified example (not secure for production)
        # In production, use Firebase Authentication REST API for sign-in
        
        # For demo purposes, search the user in Firestore
        user_doc = db.collection('users').document(user.uid).get()
        
        if user_doc.exists:
            user_data = user_doc.to_dict()
            
            # Update last login time
            db.collection('users').document(user.uid).update({
                'last_login': datetime.now()
            })
            
            return True, {
                'uid': user.uid,
                'email': user_data.get('email'),
                'name': user_data.get('name'),
                'role': user_data.get('role', 'user')
            }
        else:
            return False, "User data not found"
    except Exception as e:
        return False, str(e)

def get_all_users():
    """Get all users from Firestore (admin only)"""
    try:
        users = []
        user_docs = db.collection('users').stream()
        
        for doc in user_docs:
            users.append(doc.to_dict())
        
        return users
    except Exception as e:
        st.error(f"Error fetching users: {e}")
        return []

def delete_user(uid):
    """Delete a user (admin only)"""
    try:
        # Delete from Firebase Auth
        auth.delete_user(uid)
        
        # Delete from Firestore
        db.collection('users').document(uid).delete()
        
        return True, "User deleted successfully"
    except Exception as e:
        return False, str(e)

def update_user_role(uid, new_role):
    """Update user role (admin only)"""
    try:
        db.collection('users').document(uid).update({
            'role': new_role
        })
        return True, "User role updated successfully"
    except Exception as e:
        return False, str(e)

def logout_user():
    """Log out the current user"""
    st.session_state.logged_in = False
    st.session_state.user_info = {
        "uid": None,
        "email": None,
        "name": None,
        "role": None
    }
    return True

def login_signup_page():
    # Custom CSS for the login page
    st.markdown("""
    <style>
        .auth-container {
            max-width: 400px;
            margin: 0 auto;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0px 0px 10px rgba(0, 0, 0, 0.1);
        }
        .auth-header {
            text-align: center;
            padding-bottom: 15px;
            border-bottom: 1px solid #eee;
            margin-bottom: 20px;
        }
        .stButton button {
            width: 100%;
            font-weight: bold;
        }
    </style>
    """, unsafe_allow_html=True)
    
    # App title
    st.markdown("<h1 style='text-align: center;'>🛡️ Network SIEM Dashboard</h1>", unsafe_allow_html=True)
    
    # Create tabs for Login and Signup
    tab1, tab2 = st.tabs(["Login", "Sign Up"])
    
    # Login Tab
    with tab1:
        with st.container():
            st.markdown("<div class='auth-header'><h3>Login to Dashboard</h3></div>", unsafe_allow_html=True)
            
            email = st.text_input("Email", key="login_email")
            password = st.text_input("Password", type="password", key="login_password")
            
            if st.button("Login"):
                if not email or not password:
                    st.error("Please fill in all fields")
                else:
                    with st.spinner("Logging in..."):
                        success, result = login_user(email, password)
                        
                        if success:
                            st.session_state.logged_in = True
                            st.session_state.user_info = result
                            st.success(f"Welcome back, {result['name']}!")
                            st.experimental_rerun()
                        else:
                            st.error(f"Login failed: {result}")
    
    # Signup Tab
    with tab2:
        with st.container():
            st.markdown("<div class='auth-header'><h3>Create New Account</h3></div>", unsafe_allow_html=True)
            
            full_name = st.text_input("Full Name", key="signup_name")
            email = st.text_input("Email", key="signup_email")
            password = st.text_input("Password", type="password", key="signup_password")
            confirm_password = st.text_input("Confirm Password", type="password", key="signup_confirm")
            
            if st.button("Sign Up"):
                # Validate inputs
                if not full_name or not email or not password or not confirm_password:
                    st.error("Please fill in all fields")
                elif not is_valid_email(email):
                    st.error("Please enter a valid email address")
                elif password != confirm_password:
                    st.error("Passwords do not match")
                else:
                    # Check password strength
                    is_strong, msg = is_strong_password(password)
                    if not is_strong:
                        st.error(msg)
                    else:
                        with st.spinner("Creating your account..."):
                            success, result = signup_user(email, password, full_name)
                            
                            if success:
                                st.success("Account created successfully! You can now log in.")
                                # Switch to login tab
                                tab1.selectbox = True
                            else:
                                st.error(f"Sign up failed: {result}")

# Admin page for user management
def admin_page():
    st.title("User Management")
    
    if st.session_state.user_info["role"] != "admin":
        st.error("You don't have permission to access this page")
        return
    
    st.subheader("All Users")
    
    users = get_all_users()
    if users:
        user_df = []
        for user in users:
            user_df.append({
                "UID": user.get("uid", "N/A"),
                "Name": user.get("name", "N/A"),
                "Email": user.get("email", "N/A"),
                "Role": user.get("role", "user"),
                "Created": user.get("created_at", "N/A"),
                "Last Login": user.get("last_login", "N/A")
            })
        
        # Display user list
        for i, user in enumerate(user_df):
            with st.expander(f"{user['Name']} ({user['Email']}) - {user['Role']}"):
                col1, col2, col3 = st.columns([3, 1, 1])
                
                with col1:
                    st.write(f"**UID:** {user['UID']}")
                    st.write(f"**Created:** {user['Created']}")
                    st.write(f"**Last Login:** {user['Last Login']}")
                
                with col2:
                    new_role = st.selectbox(
                        "Role", 
                        ["user", "admin"], 
                        index=0 if user['Role'] == "user" else 1,
                        key=f"role_{i}"
                    )
                    
                    if new_role != user['Role']:
                        if st.button("Update Role", key=f"update_{i}"):
                            success, msg = update_user_role(user['UID'], new_role)
                            if success:
                                st.success(msg)
                                st.experimental_rerun()
                            else:
                                st.error(msg)
                
                with col3:
                    # Don't allow admin to delete themselves
                    if user['UID'] != st.session_state.user_info['uid']:
                        if st.button("Delete User", key=f"delete_{i}"):
                            success, msg = delete_user(user['UID'])
                            if success:
                                st.success(msg)
                                st.experimental_rerun()
                            else:
                                st.error(msg)
    else:
        st.info("No users found")

def main():
    # Check if user is logged in
    if not st.session_state.logged_in:
        login_signup_page()
    else:
        # Show logout button in sidebar
        with st.sidebar:
            st.write(f"Logged in as: **{st.session_state.user_info['name']}**")
            st.write(f"Role: **{st.session_state.user_info['role']}**")
            
            if st.button("Logout"):
                logout_user()
                st.experimental_rerun()
            
            # Admin section in sidebar
            if st.session_state.user_info["role"] == "admin":
                st.divider()
                st.subheader("Admin Controls")
                if st.button("User Management"):
                    st.session_state.page = "admin"
        
        # Determine which page to show
        if "page" not in st.session_state:
            st.session_state.page = "main"
            
        if st.session_state.page == "admin" and st.session_state.user_info["role"] == "admin":
            admin_page()
        else:
            st.session_state.page = "main"
            # Import and call main dashboard function here
            # from frontend import main_dashboard
            # main_dashboard(st.session_state.user_info)
            
            # For now, show placeholder
            st.title("🛡️ Network SIEM Dashboard")
            st.success(f"Welcome to the SIEM Dashboard, {st.session_state.user_info['name']}!")
            st.info("Main dashboard will be integrated here")

if __name__ == "__main__":
    main()