from ctypes import util
import streamlit as st
import pandas as pd
import json
import numpy as np
import matplotlib.pyplot as plt
import plotly.express as px
import plotly.graph_objects as go
import datetime
import subprocess
import time
import os
import requests
from collections import Counter, defaultdict
import socket
import ipaddress
from streamlit_autorefresh import st_autorefresh
import pygame  # Added for sound capabilities

# Telegram configuration - reusing from app.py
BOT_TOKEN = "7587958880:AAGvskvuVenEtf7trB_m9gnDaagne0XMJas"
CHAT_ID = "1301172409"
TELEGRAM_URL = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"

# Constants
LOG_FILE = "ids_logs.json"
BLOCKED_IPS_FILE = "blocked_ips.json"
SIREN_SOUND_FILE = "siren.mp3"  # Added siren sound file
SIREN_DURATION = 5  # Duration in seconds to play the siren

# Initialize the sound system
pygame.mixer.init()

# Function to get all network interfaces and their IPs
def get_network_ips():
    network_ips = []
    try:
        # For Unix/Linux/MacOS
        hostname = socket.gethostname()
        # Get all addresses for the hostname
        addresses = socket.getaddrinfo(hostname, None)
        
        for addr in addresses:
            ip = addr[4][0]
            # Filter out IPv6 and loopback addresses
            if '.' in ip and ip != '127.0.0.1':
                network_ips.append(ip)
                
        # If no IPs found, try alternative method for Linux
        if not network_ips:
            try:
                import netifaces
                for interface in netifaces.interfaces():
                    # Skip loopback interface
                    if interface == 'lo':
                        continue
                    # Get addresses for this interface
                    addrs = netifaces.ifaddresses(interface)
                    # Get IPv4 addresses
                    if netifaces.AF_INET in addrs:
                        for addr in addrs[netifaces.AF_INET]:
                            ip = addr['addr']
                            if ip != '127.0.0.1': 
                                network_ips.append(ip)
            except ImportError:
                # If netifaces not available, try command line tool
                try:
                    import subprocess
                    result = subprocess.check_output(['hostname', '-I']).decode('utf-8').strip()
                    if result:
                        network_ips = result.split()
                except:
                    pass
    except Exception as e:
        st.error(f"Error getting network IPs: {e}")
        
    return network_ips

# Auto-whitelist internal IPs of the current system
# Constants
MANUAL_WHITELIST_FILE = "manual_whitelisted_ips.json"

# Auto-whitelist internal IPs of the current system
AUTO_WHITELISTED_IPS = get_network_ips()

# Load manually added IPs from file
def load_manual_whitelist():
    if os.path.exists(MANUAL_WHITELIST_FILE):
        try:
            with open(MANUAL_WHITELIST_FILE, 'r') as f:
                return json.load(f)
        except:
            return []
    return []

# Save manually added IPs to file
def save_manual_whitelist(whitelist):
    with open(MANUAL_WHITELIST_FILE, 'w') as f:
        json.dump(whitelist, f)

# Load and combine whitelists
MANUAL_WHITELISTED_IPS = load_manual_whitelist()
WHITELISTED_IPS = list(set(AUTO_WHITELISTED_IPS + MANUAL_WHITELISTED_IPS))  # ✅ Now this is only a list


# Page configuration
st.set_page_config(
    page_title=" SIEM & IDS Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Auto-refresh every 5 seconds
st_autorefresh(interval=5000, key="datarefresh")

# Custom CSS
st.markdown("""
<style>
    .alert-box {
        padding: 10px;
        border-radius: 5px;
        margin-bottom: 10px;
    }
    .critical {
        background-color: rgba(255, 0, 0, 0.2);
        border-left: 5px solid red;
    }
    .warning {
        background-color: rgba(255, 165, 0, 0.2);
        border-left: 5px solid orange;
    }
    .info {
        background-color: rgba(0, 0, 255, 0.2);
        border-left: 5px solid blue;
    }
    .blocked {
        background-color: rgba(0, 0, 0, 0.2);
        border-left: 5px solid black;
        color: white;
    }
    .stDataFrame {
        font-size: 14px !important;
    }
    .css-1v3fvcr {
        padding-top: 0px;
    }
    .title-container {
        display: flex;
        align-items: center;
        justify-content: space-between;
    }
    .alert-counter {
        font-size: 24px;
        font-weight: bold;
        color: #ff4b4b;
    }
    .stop-siren-btn {
        background-color: #ff4b4b;
        color: white;
        font-weight: bold;
        border-radius: 5px;
        padding: 10px 15px;
        cursor: pointer;
    }
</style>
""", unsafe_allow_html=True)

# Initialize session state for blocked IPs
if 'blocked_ips' not in st.session_state:
    if os.path.exists(BLOCKED_IPS_FILE):
        with open(BLOCKED_IPS_FILE, 'r') as f:
            try:
                st.session_state.blocked_ips = json.load(f)
            except json.JSONDecodeError:
                st.session_state.blocked_ips = {}
    else:
        st.session_state.blocked_ips = {}

if 'notification_history' not in st.session_state:
    st.session_state.notification_history = []

# Initialize session state for processed alerts to avoid repeated sirens
if 'processed_alerts' not in st.session_state:
    st.session_state.processed_alerts = set()

# Initialize session state for siren settings
if 'siren_enabled' not in st.session_state:
    st.session_state.siren_enabled = True

# Initialize session state for siren playing status
if 'siren_playing' not in st.session_state:
    st.session_state.siren_playing = False

# Function to play siren sound
def play_siren():
    if st.session_state.siren_enabled and os.path.exists(SIREN_SOUND_FILE):
        try:
            pygame.mixer.music.load(SIREN_SOUND_FILE)
            pygame.mixer.music.play(-1)  # Play indefinitely until stopped
            st.session_state.siren_playing = True
        except Exception as e:
            st.error(f"Failed to play siren sound: {e}")
    elif not os.path.exists(SIREN_SOUND_FILE):
        st.error(f"Siren sound file '{SIREN_SOUND_FILE}' not found.")

# Function to stop siren sound
def stop_siren():
    try:
        pygame.mixer.music.stop()
        st.session_state.siren_playing = False
    except Exception as e:
        st.error(f"Failed to stop siren sound: {e}")

# Function to load and parse log data
def load_logs():
    logs = []
    try:
        with open(LOG_FILE, 'r') as f:
            for line in f:
                try:
                    log = json.loads(line.strip())
                    logs.append(log)
                except json.JSONDecodeError:
                    continue
    except FileNotFoundError:
        st.warning("Log file not found. Make sure the IDS is running.")
    
    return logs

def block_ip(ip_address, reason):
    # Whitelist check (auto + manual)
    if ip_address in WHITELISTED_IPS:
        st.warning(f"⚠️ Skipping block. IP {ip_address} is in the whitelist.")
        return

    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    st.session_state.blocked_ips[ip_address] = {
        "timestamp": timestamp,
        "reason": reason
    }

    # Save to file
    with open(BLOCKED_IPS_FILE, 'w') as f:
        json.dump(st.session_state.blocked_ips, f)

    # Apply firewall rules based on OS
    if os.name == 'nt':  # Windows
        try:
            if "Unsecured HTTP" in reason:
                subprocess.run([
                    'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                    f'name=SIEM_Block_HTTP_{ip_address}', 'dir=in',
                    'action=block', f'remoteip={ip_address}',
                    'protocol=TCP', 'localport=80'
                ], shell=True, check=True)
                st.success(f"✅ IP {ip_address} blocked for HTTP (port 80) in Windows firewall.")
            else:
                subprocess.run([
                    'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                    f'name=SIEM_Block_{ip_address}', 'dir=in',
                    'action=block', f'remoteip={ip_address}'
                ], shell=True, check=True)
                st.success(f"✅ IP {ip_address} fully blocked in Windows firewall.")

            send_telegram_alert(ip_address, "BLOCKED", timestamp, reason)
            play_siren()

        except Exception as e:
            st.error(f"❌ Failed to add firewall rule: {e}")

    else:  # Linux
        try:
            if "Unsecured HTTP" in reason:
                subprocess.run([
                    'sudo', 'iptables', '-A', 'INPUT', '-s', ip_address,
                    '-p', 'tcp', '--dport', '80', '-j', 'DROP'
                ])
                st.success(f"✅ IP {ip_address} blocked for HTTP on Linux.")
            else:
                subprocess.run([
                    'sudo', 'iptables', '-A', 'INPUT', '-s', ip_address,
                    '-j', 'DROP'
                ])
                st.success(f"✅ IP {ip_address} fully blocked on Linux.")

            send_telegram_alert(ip_address, "BLOCKED", timestamp, reason)
            play_siren()

        except Exception as e:
            st.error(f"❌ Failed to add firewall rule: {e}")



def unblock_ip(ip_address):
    if ip_address in st.session_state.blocked_ips:
        # Remove from our blocked list
        reason = st.session_state.blocked_ips[ip_address]["reason"]
        del st.session_state.blocked_ips[ip_address]
        
        # Save to file
        with open(BLOCKED_IPS_FILE, 'w') as f:
            json.dump(st.session_state.blocked_ips, f)
        
        # Check if we're running on Windows or Linux
        if os.name == 'nt':  # Windows
            try:
                # For Windows, use netsh to unblock the IP
                if "Unsecured HTTP" in reason:
                    # Remove HTTP specific rule
                    subprocess.run(['netsh', 'advfirewall', 'firewall', 'delete', 'rule', 
                                   f'name=SIEM_Block_HTTP_{ip_address}'], 
                                   shell=True, check=True)
                else:
                    # Remove complete block rule
                    subprocess.run(['netsh', 'advfirewall', 'firewall', 'delete', 'rule', 
                                   f'name=SIEM_Block_{ip_address}'], 
                                   shell=True, check=True)
                st.success(f"IP {ip_address} has been unblocked from Windows firewall")
            except Exception as e:
                st.error(f"Failed to remove firewall rule: {e}")
        else:  # Linux
            try:
                # Original Linux logic
                if "Unsecured HTTP" in reason:
                    # Remove HTTP specific rule
                    subprocess.run(['sudo', 'iptables', '-D', 'INPUT', '-s', ip_address, '-p', 'tcp', '--dport', '80', '-j', 'DROP'])
                else:
                    # Remove complete block rule
                    subprocess.run(['sudo', 'iptables', '-D', 'INPUT', '-s', ip_address, '-j', 'DROP'])
                st.success(f"IP {ip_address} has been unblocked")
            except Exception as e:
                st.error(f"Failed to remove firewall rule: {e}")

def send_telegram_alert(src_ip, detection_type, timestamp, additional_info=""):
    message = f"🚨 {detection_type}\n\n🕒 Time: {timestamp}\n🔴 Source IP: {src_ip}\n⚠ Info: {additional_info}"
    payload = {
        "chat_id": CHAT_ID,
        "text": message,
        "parse_mode": "Markdown"
    }
    try:
        response = requests.post(TELEGRAM_URL, data=payload)
        if response.status_code == 200:
            st.session_state.notification_history.append({
                "timestamp": timestamp,
                "message": f"Alert sent for {src_ip} - {detection_type}",
                "success": True
            })
        else:
            st.session_state.notification_history.append({
                "timestamp": timestamp,
                "message": f"Failed to send alert: {response.status_code}",
                "success": False
            })
    except Exception as e:
        st.session_state.notification_history.append({
            "timestamp": timestamp,
            "message": f"Error sending alert: {str(e)}",
            "success": False
        })

def geolocate_ip(ip):
    try:
        response = requests.get(f"https://ipapi.co/{ip}/json/")
        if response.status_code == 200:
            data = response.json()
            return {
                "country": data.get("country_name", "Unknown"),
                "city": data.get("city", "Unknown"),
                "lat": data.get("latitude", 0),
                "lon": data.get("longitude", 0),
                "org": data.get("org", "Unknown")
            }
    except:
        pass
    return {
        "country": "Unknown",
        "city": "Unknown",
        "lat": 0,
        "lon": 0,
        "org": "Unknown"
    }


# Function to check for new malicious activities and trigger siren
def check_for_new_malicious_activities(df):
    if df is None or df.empty:
        return
    
    # Get all malicious activities AND unsecured HTTP traffic
    security_df = df[df['detection'].astype(str).str.contains('Malicious|Unsecured HTTP')]
    
    if not security_df.empty:
        # Create a unique identifier for each alert
        security_df['alert_id'] = security_df.apply(
            lambda x: f"{x['source_ip']}_{x['destination_ip']}_{x['protocol']}_{x['timestamp']}", axis=1
        )
        
        # Check for new security alerts
        new_alerts = [
            alert_id for alert_id in security_df['alert_id'].values 
            if alert_id not in st.session_state.processed_alerts
        ]
        
        # If new security alerts detected, trigger siren and send Telegram notifications
        if new_alerts:
            # Add new alerts to processed set
            st.session_state.processed_alerts.update(new_alerts)
            
            # Play siren for new security alerts
            play_siren()
            
            # Send Telegram notifications for new alerts
            for alert_id in new_alerts:
                alert = security_df[security_df['alert_id'] == alert_id].iloc[0]
                timestamp = alert['timestamp'].strftime("%Y-%m-%d %H:%M:%S")
                send_telegram_alert(
                    alert['source_ip'], 
                    alert['detection'], 
                    timestamp, 
                    f"Protocol: {alert['protocol']} | Destination: {alert['destination_ip']}"
                )
            
            # Limit the size of processed_alerts set to prevent memory issues
            if len(st.session_state.processed_alerts) > 1000:
                # Keep only the most recent 500 alerts
                st.session_state.processed_alerts = set(list(st.session_state.processed_alerts)[-500:])

# Sidebar
st.sidebar.title("🛡️ SIEM Controls")
refresh_btn = st.sidebar.button("🔄 Refresh Data")

# Show stop siren button in sidebar if siren is playing
if st.session_state.siren_playing:
    if st.sidebar.button("🔇 Stop Siren", key="stop_siren_sidebar"):
        stop_siren()

# Navigation
page = st.sidebar.radio("Navigation", ["Dashboard", "Alerts", "Traffic Analysis", "Blocked IPs", "Settings"])

# Load data
logs = load_logs()

# Convert logs to DataFrame for easier analysis
if logs:
    df = pd.DataFrame(logs)
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    
    # Ensure 'detection' column values are strings
    df['detection'] = df['detection'].astype(str)
    
    # Check for new malicious activities and trigger siren if needed
    check_for_new_malicious_activities(df)
    
    # Count detection types
    detection_counts = df['detection'].value_counts()
    
    # Calculate statistics
    total_logs = len(df)
    # Fixed line: Convert all values to strings before checking for substring
    alerts_count = sum(1 for x in df['detection'].astype(str) if "Malicious" in x or "Unsecured" in x)
    unique_ips_count = df['source_ip'].nunique()
    
    # Create time-series data
    df_time = df.set_index('timestamp')
    df_time_resampled = df_time.resample('1Min').size().reset_index(name='count')
    
    # Get top source IPs
    top_src_ips = df['source_ip'].value_counts().head(10).reset_index()
    top_src_ips.columns = ['source_ip', 'count']
    
    # Get protocols distribution
    protocol_dist = df['protocol'].value_counts().reset_index()
    protocol_dist.columns = ['protocol', 'count']
    
    # Get the last 24 hours of data
    now = datetime.datetime.now()
    last_24h = now - datetime.timedelta(hours=24)
    df_24h = df[df['timestamp'] > pd.Timestamp(last_24h)]
    
    # Calculate hourly traffic
    hourly_traffic = df_24h.set_index('timestamp').resample('1H').size().reset_index(name='count')
    
    # Get malicious IPs - ensure string conversion
    malicious_ips = df[df['detection'].astype(str).str.contains('Malicious')]['source_ip'].unique()
else:
    df = pd.DataFrame()
    detection_counts = pd.Series()  # Changed from empty dict to empty Series
    total_logs = 0
    alerts_count = 0
    unique_ips_count = 0
    df_time_resampled = pd.DataFrame()
    top_src_ips = pd.DataFrame()
    protocol_dist = pd.DataFrame()
    hourly_traffic = pd.DataFrame()
    malicious_ips = []

# Dashboard Page
if page == "Dashboard":
    col_title, col_siren = st.columns([4, 1])
    
    with col_title:
        st.title("🛡️ SIEM & IDS Dashboard")
    
    # Show stop siren button if siren is playing
    with col_siren:
        if st.session_state.siren_playing:
            if st.button("🔇 Stop Siren", key="stop_siren_dashboard"):
                stop_siren()
    
    # Stats Row
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("Total Packets", total_logs)
    with col2:
        st.metric("Alerts", alerts_count, f"{alerts_count/max(total_logs, 1)*100:.1f}%" if total_logs else "0%")
    with col3:
        st.metric("Unique IPs", unique_ips_count)
    with col4:
        st.metric("Blocked IPs", len(st.session_state.blocked_ips))
    
    # Main dashboard
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.subheader("Network Traffic Over Time")
        if not df_time_resampled.empty:
            fig = px.line(df_time_resampled, x='timestamp', y='count', 
                          title="Packets per Minute")
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No traffic data available yet.")
        
        st.subheader("Detection Summary")
        if not detection_counts.empty:
            fig = px.pie(values=detection_counts.values, names=detection_counts.index,
                         title="Detection Types")
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No detection data available yet.")
    
    with col2:
        # Add stop siren button at the top of the alerts section if siren is playing
        if st.session_state.siren_playing:
            st.button("🔇 Stop Siren", key="stop_siren_alerts", on_click=stop_siren)
            
        st.subheader("Recent Alerts")
        if not df.empty:
            # Convert to string before using str.contains
            recent_alerts = df[df['detection'].astype(str).str.contains('Malicious|Unsecured')].tail(10).sort_values('timestamp', ascending=False)
            
            if not recent_alerts.empty:
                for _, alert in recent_alerts.iterrows():
                    with st.container():
                        if "Malicious" in str(alert['detection']):
                            st.markdown(f"""
                            <div class="alert-box critical">
                                <strong>⚠ {alert['detection']}</strong><br>
                                📅 {alert['timestamp']}<br>
                                🔍 Source: {alert['source_ip']} → Dest: {alert['destination_ip']}<br>
                                🔄 Protocol: {alert['protocol']}
                            </div>
                            """, unsafe_allow_html=True)
                        else:
                            st.markdown(f"""
                            <div class="alert-box warning">
                                <strong>⚠ {alert['detection']}</strong><br>
                                📅 {alert['timestamp']}<br>
                                🔍 Source: {alert['source_ip']} → Dest: {alert['destination_ip']}<br>
                                🔄 Protocol: {alert['protocol']}
                            </div>
                            """, unsafe_allow_html=True)
            else:
                st.info("No alerts detected yet.")
        else:
            st.info("No alert data available yet.")
    
    # Bottom row
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("Top Source IPs")
        if not top_src_ips.empty:
            fig = px.bar(top_src_ips, x='source_ip', y='count', 
                         title="Top Source IPs")
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No IP data available yet.")
            
    with col2:
        st.subheader("Protocol Distribution")
        if not protocol_dist.empty:
            fig = px.bar(protocol_dist, x='protocol', y='count',
                         title="Protocol Distribution", color='protocol')
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No protocol data available yet.")

# Alerts Page
elif page == "Alerts":
    # Title row with stop siren button
    col_title, col_siren = st.columns([4, 1])
    
    with col_title:
        st.title("🚨 Security Alerts")
    
    # Show stop siren button if siren is playing
    with col_siren:
        if st.session_state.siren_playing:
            if st.button("🔇 Stop Siren", key="stop_siren_alerts_page"):
                stop_siren()
    
    # Filter options
    col1, col2 = st.columns(2)
    with col1:
        if not df.empty:
            detection_types = ['All'] + list(df['detection'].unique())
            selected_detection = st.selectbox("Filter by Detection Type", detection_types)
        else:
            selected_detection = "All"
    
    with col2:
        if not df.empty:
            protocols = ['All'] + list(df['protocol'].unique())
            selected_protocol = st.selectbox("Filter by Protocol", protocols)
        else:
            selected_protocol = "All"
    
    # Apply filters
    if not df.empty:
        filtered_df = df.copy()
        
        if selected_detection != 'All':
            filtered_df = filtered_df[filtered_df['detection'] == selected_detection]
        
        if selected_protocol != 'All':
            filtered_df = filtered_df[filtered_df['protocol'] == selected_protocol]
        
        # Sort by timestamp descending
        filtered_df = filtered_df.sort_values('timestamp', ascending=False)
        
        # Alert table
        st.subheader(f"Detected Events ({len(filtered_df)} records)")
        
        for idx, alert in filtered_df.iterrows():
            col1, col2 = st.columns([5, 1])
            
            with col1:
                if "Malicious" in str(alert['detection']):
                    box_class = "critical"
                elif "Unsecured" in str(alert['detection']):
                    box_class = "warning"
                else:
                    box_class = "info"
                
                ip_blocked = alert['source_ip'] in st.session_state.blocked_ips
                if ip_blocked:
                    box_class = "blocked"
                
                st.markdown(f"""
                <div class="alert-box {box_class}">
                    <strong>{'[BLOCKED] ' if ip_blocked else ''}{alert['detection']}</strong><br>
                    📅 {alert['timestamp']}<br>
                    🔍 Source: {alert['source_ip']} → Dest: {alert['destination_ip']}<br>
                    🔄 Protocol: {alert['protocol']}
                </div>
                """, unsafe_allow_html=True)
            
            with col2:
                if not ip_blocked and ("Malicious" in str(alert['detection']) or "Unsecured" in str(alert['detection'])):
                    if st.button("Block IP", key=f"block_{alert['source_ip']}_{alert['timestamp']}_{idx}"):
                        block_ip(alert['source_ip'], alert['detection'])

                elif ip_blocked:
                    if st.button("Unblock", key=f"unblock_{alert['source_ip']}_{alert['timestamp']}_{idx}"):
                       unblock_ip(alert['source_ip'])

    else:
        st.info("No alert data available yet.")

# Traffic Analysis Page
elif page == "Traffic Analysis":
    # Title row with stop siren button
    col_title, col_siren = st.columns([4, 1])
    
    with col_title:
        st.title("🔍 Traffic Analysis")
    
    # Show stop siren button if siren is playing
    with col_siren:
        if st.session_state.siren_playing:
            if st.button("🔇 Stop Siren", key="stop_siren_traffic"):
                stop_siren()
    
    if not df.empty:
        # Time range selector
        col1, col2 = st.columns(2)
        with col1:
            time_range = st.selectbox("Time Range", 
                                     ["Last Hour", "Last 6 Hours", "Last 24 Hours", "Last 7 Days", "All Time"])
        
        # Filter by time range
        now = datetime.datetime.now()
        if time_range == "Last Hour":
            start_time = now - datetime.timedelta(hours=1)
        elif time_range == "Last 6 Hours":
            start_time = now - datetime.timedelta(hours=6)
        elif time_range == "Last 24 Hours":
            start_time = now - datetime.timedelta(hours=24)
        elif time_range == "Last 7 Days":
            start_time = now - datetime.timedelta(days=7)
        else:
            start_time = df['timestamp'].min()
        
        filtered_df = df[df['timestamp'] >= pd.Timestamp(start_time)]
        
        # Traffic patterns by hour of day
        st.subheader("Traffic Patterns by Hour of Day")
        if not filtered_df.empty:
            hourly_pattern = filtered_df.groupby(filtered_df['timestamp'].dt.hour).size().reset_index()
            hourly_pattern.columns = ['hour', 'count']
            
            fig = px.bar(hourly_pattern, x='hour', y='count',
                        labels={'hour': 'Hour of Day', 'count': 'Number of Packets'},
                        title="Traffic Distribution by Hour of Day")
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No data available for the selected time range.")
        
        # IP Geolocations
        st.subheader("IP Geolocation Map")
        
        # Get unique IPs
        unique_ips = filtered_df['source_ip'].unique()
        
        # For demo, let's get a sample of IPs to geolocate
        # (to avoid hitting API limits)
        sample_ips = unique_ips[:10]
        
        # Collect geolocation data
        geo_data = []
        for ip in sample_ips:
            if not (ip.startswith('192.168.') or ip.startswith('10.') or ip.startswith('172.')):  # Skip private IPs
                location = geolocate_ip(ip)
                if location['lat'] != 0 and location['lon'] != 0:
                    malicious = ip in malicious_ips
                    blocked = ip in st.session_state.blocked_ips
                    
                    geo_data.append({
                        'ip': ip,
                        'lat': location['lat'],
                        'lon': location['lon'],
                        'country': location['country'],
                        'city': location['city'],
                        'org': location['org'],
                        'count': filtered_df[filtered_df['source_ip'] == ip].shape[0],
                        'malicious': malicious,
                        'blocked': blocked
                    })
        
        if geo_data:
            geo_df = pd.DataFrame(geo_data)
            fig = px.scatter_geo(geo_df, 
                                lat='lat', 
                                lon='lon',
                                color='malicious',
                                size='count',
                                hover_name='ip',
                                hover_data=['country', 'city', 'org', 'count', 'malicious', 'blocked'],
                                projection='natural earth',
                                title='IP Geolocations')
            
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No geolocation data available for the selected time range.")
        
        # Protocol and detection correlation
        st.subheader("Protocol and Detection Correlation")
        
        if not filtered_df.empty:
            # Handle potential errors in crosstab by ensuring detection is always a string
            try:
                protocol_detection = pd.crosstab(filtered_df['protocol'], 
                                                filtered_df['detection'].astype(str).apply(lambda x: "Malicious" if "Malicious" in x else "HTTP" if "HTTP" in x else "Secure"))
                
                fig = px.bar(protocol_detection.reset_index().melt(id_vars=['protocol']),
                            x='protocol', y='value', color='detection', 
                            title="Protocol vs Detection Type", barmode='group')
                st.plotly_chart(fig, use_container_width=True)
            except Exception as e:
                st.error(f"Error creating protocol-detection correlation: {str(e)}")
        else:
            st.info("No data available for the selected time range.")
        
        # Show raw data
        st.subheader("Raw Traffic Data")
        st.dataframe(filtered_df)
    else:
        st.info("No traffic data available yet.")

# Blocked IPs Page
elif page == "Blocked IPs":
    # Title row with stop siren button
    col_title, col_siren = st.columns([4, 1])
    
    with col_title:
        st.title("🚫 Blocked IPs Management")
    
    # Show stop siren button if siren is playing
    with col_siren:
        if st.session_state.siren_playing:
            if st.button("🔇 Stop Siren", key="stop_siren_blocked"):
                stop_siren()
    
    # Add new IP block form
    st.subheader("Block New IP")
    col1, col2 = st.columns(2)
    
    with col1:
        new_ip = st.text_input("IP Address")
    
    with col2:
        block_reason = st.text_input("Reason for Blocking")
    
    if st.button("Block IP"):
        if new_ip:
            try:
                ipaddress.ip_address(new_ip)  # Validate IP format
                block_ip(new_ip, block_reason if block_reason else "Manually blocked")
            except ValueError:
                st.error("Invalid IP address format")
    
    # List of blocked IPs
    st.subheader("Currently Blocked IPs")
    
    if st.session_state.blocked_ips:
        blocked_df = pd.DataFrame([
            {
                "IP Address": ip,
                "Blocked On": data["timestamp"],
                "Reason": data["reason"]}
            for ip, data in st.session_state.blocked_ips.items()
        ])
        
        for _, row in blocked_df.iterrows():
            col1, col2 = st.columns([5, 1])
            
            with col1:
                st.markdown(f"""
                <div class="alert-box blocked">
                    <strong>BLOCKED: {row['IP Address']}</strong><br>
                    📅 {row['Blocked On']}<br>
                    🚫 Reason: {row['Reason']}
                </div>
                """, unsafe_allow_html=True)
            
            with col2:
                if st.button(f"Unblock", key=f"unblock_list_{row['IP Address']}"):
                    unblock_ip(row['IP Address'])
    else:
        st.info("No IPs are currently blocked.")

# Settings Page
elif page == "Settings":
    # Title row with stop siren button
    col_title, col_siren = st.columns([4, 1])
    
    with col_title:
        st.title("⚙️ System Settings")
    
    # Show stop siren button if siren is playing
    with col_siren:
        if st.session_state.siren_playing:
            if st.button("🔇 Stop Siren", key="stop_siren_settings"):
                stop_siren()
    
    # Network Settings
    st.subheader("Network Settings")
    
    # Show network interfaces
    network_ips = get_network_ips()
    st.write("**Network Interfaces:**")
    for ip in network_ips:
        st.code(ip)
    
    # Telegram Notification Settings
    st.subheader("Notification Settings")
    
    # Telegram settings
    telegram_enabled = st.checkbox("Enable Telegram Notifications", 
                                  value=True if BOT_TOKEN and CHAT_ID else False)
    
    col1, col2 = st.columns(2)
    
    with col1:
        bot_token = st.text_input("Bot Token", value=BOT_TOKEN, type="password")
    
    with col2:
        chat_id = st.text_input("Chat ID", value=CHAT_ID)
    
    if st.button("Save Telegram Settings"):
        # This would normally save to a config file
        st.success("Telegram settings saved.")
        # Send a test notification
        if telegram_enabled and bot_token and chat_id:
            test_url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
            test_payload = {
                "chat_id": chat_id,
                "text": "🧪 Test notification from SIEM Dashboard",
                "parse_mode": "Markdown"
            }
            try:
                response = requests.post(test_url, data=test_payload)
                if response.status_code == 200:
                    st.success("Test notification sent successfully!")
                else:
                    st.error(f"Failed to send test notification. Status code: {response.status_code}")
            except Exception as e:
                st.error(f"Error sending test notification: {str(e)}")
    
    # Siren Settings
    st.subheader("Alert Siren Settings")
    
    siren_enabled = st.checkbox("Enable Alert Siren for Security Events", 
                               value=st.session_state.siren_enabled)
    
    if siren_enabled != st.session_state.siren_enabled:
        st.session_state.siren_enabled = siren_enabled
        if siren_enabled:
            st.success("Alert siren enabled. Siren will play when security events are detected.")
        else:
            st.warning("Alert siren disabled. No sound will play for security events.")
            # Stop any playing siren
            if st.session_state.siren_playing:
                stop_siren()
    
    # Test siren button
    if st.button("Test Siren") and st.session_state.siren_enabled:
        play_siren()
    
    st.subheader("🔐 Whitelisted IPs Management")
    st.write("### Whitelisted IPs")
    for ip in WHITELISTED_IPS:
      st.code(ip)
    with st.expander("✏️ Manage Manual Whitelist"):
      col1, col2 = st.columns(2) 
      with col1: 
          new_whitelist_ip = st.text_input("Add IP to Manual Whitelist")
          if st.button("➕ Add to Whitelist"):
              try:
                  ipaddress.ip_address(new_whitelist_ip)
                  if new_whitelist_ip not in MANUAL_WHITELISTED_IPS:
                      MANUAL_WHITELISTED_IPS.append(new_whitelist_ip)
                      save_manual_whitelist(MANUAL_WHITELISTED_IPS)
                      st.success(f"Added {new_whitelist_ip} to manual whitelist.")
                  else:
                      st.info("IP already in manual whitelist.")
              except ValueError:
                  st.error("Invalid IP address.")
      with col2:
          if MANUAL_WHITELISTED_IPS:
               remove_ip = st.selectbox("Select IP to Remove", MANUAL_WHITELISTED_IPS)
               if st.button("🗑️ Remove from Whitelist"):
                   MANUAL_WHITELISTED_IPS.remove(remove_ip)
                   save_manual_whitelist(MANUAL_WHITELISTED_IPS)
                   st.success(f"Removed {remove_ip} from manual whitelist.")
               else:
                   st.info("No manually whitelisted IPs.")                            
    
    # Log Settings
    st.subheader("Log Settings")
    
    # Show log file path
    st.write(f"**Log File Path:** `{os.path.abspath(LOG_FILE)}`")
    
    # Option to clear logs
    if st.button("Clear All Logs", help="This will delete all log entries."):
        try:
            # Backup logs first
            backup_folder = "backup"
            os.makedirs(backup_folder, exist_ok=True)  # Ensure backup folder exists
            backup_file = os.path.join(backup_folder, f"ids_logs_backup_{datetime.datetime.now().strftime('%Y-%m-%d_%I-%M-%S_%p')}.json")
        
            if os.path.exists(LOG_FILE):
                import shutil
                shutil.copy(LOG_FILE, backup_file)
                
                # Now clear the log file
                with open(LOG_FILE, 'w') as f:
                    f.write('')
                
                st.success(f"Logs cleared. Backup saved to {backup_file}")
            else:
                st.warning("No log file found to clear.")
        except Exception as e:
            st.error(f"Error clearing logs: {str(e)}")
    
    # Notification History
    st.subheader("Notification History")
    
    if st.session_state.notification_history:
        for notification in reversed(st.session_state.notification_history[-10:]):
            if notification["success"]:
                st.success(f"{notification['timestamp']} - {notification['message']}")
            else:
                st.error(f"{notification['timestamp']} - {notification['message']}")
    else:
        st.info("No notification history available.")
    
    # Clear notification history
    if st.button("Clear Notification History"):
        st.session_state.notification_history = []
        st.success("Notification history cleared.")

# Footer
st.markdown("---")
st.markdown("Integration IDS with SIEM  Dashboard - Monitoring network traffic in real-time")


