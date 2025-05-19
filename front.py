import streamlit as st
import subprocess
import os

# Page config
st.set_page_config(
    page_title="Integration of SIEM & IDS System",
    layout="wide",
)

# Initialize session state for toggle
if "explore_open" not in st.session_state:
    st.session_state.explore_open = False

# Custom CSS - Orange theme version
st.markdown(
    """
    <style>
    .stApp {
        background: linear-gradient(135deg, #0f0c29, #302b63, #24243e, #1f1c2c);
        color: white;
        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        padding-top: 80px;
    }

    .center {
        text-align: center;
        padding: 50px;
    }

    .big-title {
        font-size: 4em;
        font-weight: 900;
        line-height: 1.2;
        margin-bottom: 20px;
        animation: fadeInDown 1s ease-out;
    }

    .red-text {
        color: #FFA500; /* Orange */
    }

    .subtitle {
        font-size: 1.3em;
        color: #ccc;
        max-width: 800px;
        margin: 20px auto 50px auto;
        line-height: 1.8;
        animation: fadeInUp 1s ease-out;
    }

    .stButton button {
        padding: 18px 40px;
        margin: 15px;
        border-radius: 12px;
        font-weight: bold;
        font-size: 1.2em;
        transition: 0.4s ease;
        box-shadow: 0 10px 20px rgba(0,0,0,0.3);
        cursor: pointer;
    }

    .stButton button:hover {
        transform: scale(1.05);
    }

    .explore-btn {
        background-color: #FFA500 !important; /* Orange */
        color: white !important;
        border: none;
    }

    .explore-btn:hover {
        background-color: #e69500 !important; /* Darker orange */
    }

    .get-started-btn {
        background-color: transparent;
        color: #FFA500 !important;
        border: 2px solid #FFA500 !important;
    }

    .get-started-btn:hover {
        background-color: #FFA500 !important;
        color: white !important;
    }

    @keyframes fadeInDown {
        from {opacity: 0; transform: translateY(-30px);}
        to {opacity: 1; transform: translateY(0);}
    }

    @keyframes fadeInUp {
        from {opacity: 0; transform: translateY(30px);}
        to {opacity: 1; transform: translateY(0);}
    }
    </style>
    """,
    unsafe_allow_html=True
)

# Main Content
st.markdown('<div class="center">', unsafe_allow_html=True)

st.markdown(
    '<div class="big-title">🛡️Integration <span class="red-text">SIEM with IDS</span><br>Advanced Threat Detection System</div>',
    unsafe_allow_html=True
)

st.markdown(
    '<div class="subtitle">An ultimate cybersecurity solution combining real-time monitoring, intelligent threat detection, automated response, and complete traffic visibility in a single unified platform.</div>',
    unsafe_allow_html=True
)

# Buttons
# Buttons Side-by-Side with Same Styling
st.markdown('<div style="display: flex; justify-content: center; gap: 0px;">', unsafe_allow_html=True)

col1, col2 = st.columns([1, 1])

with col1:
    explore_btn = st.button("🔎 Explore Features", key="explore_btn", help="See features")
    st.markdown(
        """<style>
        .stButton > button {
            background-color: transparent;
            color: #FFA500 !important;
            border: 2px solid #FFA500 !important;
            border-radius: 12px;
            padding: 18px 40px;
            font-weight: bold;
            font-size: 1.2em;
            transition: 0.4s ease;
            box-shadow: 0 10px 20px rgba(0,0,0,0.3);
        }
        .stButton > button:hover {
            background-color: #FFA500 !important;
            color: white !important;
        }
        </style>""",
        unsafe_allow_html=True
    )
    if explore_btn:
        st.session_state.explore_open = not st.session_state.explore_open

with col2:
    start_clicked = st.button("🚀 Get Started", key="start_btn")
    # Same style is already applied above, no need to repeat


st.markdown('</div>', unsafe_allow_html=True)

# Explore Features - Toggle Dropdown
if st.session_state.explore_open:
    with st.expander("🚀 Explore Platform Features", expanded=True):
        st.markdown("""
        - 🛡️ **Real-time Threat Detection** with ML-powered IDS.
        - 📊 **Advanced SIEM Dashboard** with traffic & attack analytics.
        - 🚨 **Instant Telegram Alerts** on security incidents.
        - 🌍 **GeoIP Location Mapping** for source tracking.
        - 📈 **Protocol, Traffic & Trend Analysis** reports.
        - 🔊 **Critical Attack Siren** for immediate response.
    
        """)

# Launch Frontend.py if "Get Started" clicked
if start_clicked:
    file_path = os.path.join(os.getcwd(), "frontend.py")
    subprocess.Popen(["streamlit", "run", file_path])
    st.success("✅ SIEM Dashboard is starting in a new tab!")
