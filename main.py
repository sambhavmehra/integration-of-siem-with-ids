import subprocess
import time
import os

# Run front.py (Streamlit frontend)
front_process = subprocess.Popen(["streamlit", "run", "front.py"])
print("✅ front.py (SIEM Dashboard) started!")

# Wait for 30 seconds before starting IDS
print("⏳ Waiting 30 seconds before starting IDS...")
time.sleep(30)

# Run ids.py (IDS detection)
ids_process = subprocess.Popen(["python", "ids.py"])
print("🚀 ids.py (IDS) started!")

# Optional: Wait for both to finish (not really needed unless you want to block script)
front_process.wait()
ids_process.wait()
