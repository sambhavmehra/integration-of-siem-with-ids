import firebase_admin
from firebase_admin import credentials, auth, db
import streamlit as st
import os
import json
import pyrebase
import datetime
import re

# Firebase configuration
# Note: In production, these values should be stored securely (e.g., environment variables)
firebaseConfig = {
    "apiKey": "AIzaSyA1234567890abcdefghijklmnopqrst",
    "authDomain": "siem-dashboard.firebaseapp.com",
    "databaseURL": "https://siem-dashboard-default-rtdb.firebaseio.com",
    "projectId": "siem-dashboard",
    "storageBucket": "siem-dashboard.appspot.com",
    "messagingSenderId": "123456789012",
    "appId": "1:123456789012:web:abcdef1234567890"
}

# Initialize Firebase
def initialize_firebase():
    # Check if Firebase is already initialized
    if not firebase_admin._apps:
        # Use service account credentials from JSON
        cred_dict = {
            "type": "service_account",
            "project_id": "siem-dashboard",
            # Add other service account credentials here
        }
        cred = credentials.Certificate(cred_dict)
        firebase_admin.initialize_app(cred, {
            'databaseURL': firebaseConfig["databaseURL"]
        })
    
    # Initialize Pyrebase for authentication
    firebase = pyrebase.initialize_app(firebaseConfig)
    return firebase

# Validate email format
def is_valid_email(email):
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(email_pattern, email))

# Check password strength
def check_password_strength(password):
    # Password should have:
    # - At least 8 characters
    # - At least one uppercase letter
    # - At least one lowercase letter
    # - At least one digit
    # - At least one special character
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    
    if not any(c.isupper() for c in password):
        return False, "Password must contain at least one uppercase letter"
    
    if not any(c.islower() for c in password):
        return False, "Password must contain at least one lowercase letter"
    
    if not any(c.isdigit() for c in password):
        return False, "Password must contain at least one digit"
    
    if not any(c in "!@#$%^&*()-_=+[]{}|;:'\",.<>/?`~" for c in password):
        return False, "Password must contain at least one special character"
    
    return True, "Password is strong"

# User registration
def register_user(email, password, user_data):
    firebase = initialize_firebase()
    auth_instance = firebase.auth()
    
    try:
        # Create user in Firebase Authentication
        user = auth_instance.create_user_with_email_and_password(email, password)
        
        # Store additional user data in Realtime Database
        db_ref = db.reference(f"/users/{user['localId']}")
        user_data["created_at"] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        db_ref.set(user_data)
        
        return True, "User registered successfully"
    except Exception as e:
        error_message = str(e)
        if "EMAIL_EXISTS" in error_message:
            return False, "Email already exists"
        elif "WEAK_PASSWORD" in error_message:
            return False, "Password is too weak"
        else:
            return False, f"Registration failed: {error_message}"

# User login
def login_user(email, password):
    firebase = initialize_firebase()
    auth_instance = firebase.auth()
    
    try:
        # Sign in user with email and password
        user = auth_instance.sign_in_with_email_and_password(email, password)
        
        # Get user data from Realtime Database
        user_id = user['localId']
        user_token = user['idToken']
        
        # Get user role and other data
        db_ref = db.reference(f"/users/{user_id}")
        user_data = db_ref.get()
        
        # Log user activity
        log_user_activity(user_id, "login")
        
        return True, {
            "user_id": user_id,
            "email": email,
            "token": user_token,
            "role": user_data.get("role", "viewer"),  # Default to viewer if role is not set
            "first_name": user_data.get("first_name", ""),
            "last_name": user_data.get("last_name", "")
        }
    except Exception as e:
        error_message = str(e)
        if "INVALID_PASSWORD" in error_message:
            return False, "Invalid password"
        elif "EMAIL_NOT_FOUND" in error_message:
            return False, "Email not found"
        else:
            return False, f"Login failed: {error_message}"

# Reset password
def reset_password(email):
    firebase = initialize_firebase()
    auth_instance = firebase.auth()
    
    try:
        auth_instance.send_password_reset_email(email)
        return True, "Password reset email sent"
    except Exception as e:
        return False, f"Failed to send reset email: {str(e)}"

# Check if user is authenticated
def is_authenticated():
    return 'user' in st.session_state and st.session_state.user is not None

# Check if user has admin role
def is_admin():
    if not is_authenticated():
        return False
    return st.session_state.user.get('role') == 'admin'

# Log user activity
def log_user_activity(user_id, activity_type, details=None):
    try:
        activity_data = {
            "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "activity_type": activity_type,
            "ip_address": get_client_ip()
        }
        
        if details:
            activity_data["details"] = details
        
        # Store activity in Firebase
        activity_ref = db.reference(f"/user_activities/{user_id}")
        activity_ref.push().set(activity_data)
        
        return True
    except Exception as e:
        print(f"Error logging activity: {str(e)}")
        return False

# Get client IP address
def get_client_ip():
    # In Streamlit, this is not straightforward
    # For demonstration purposes, return a placeholder
    return "127.0.0.1"  # In a real app, you would get the actual client IP

# Logout user
def logout_user():
    if 'user' in st.session_state:
        user_id = st.session_state.user.get('user_id')
        if user_id:
            log_user_activity(user_id, "logout")
        
        # Clear session state
        st.session_state.user = None
        st.session_state.authentication_status = False
        return True
    return False