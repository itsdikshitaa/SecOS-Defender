from flask import Flask, render_template, jsonify
import os
import json
import datetime

app = Flask(__name__)

# Path to the alert log file
ALERT_LOG_FILE = os.path.join(os.path.dirname(__file__), '../alert/alerts.json')

# Ensure the alerts directory exists
os.makedirs(os.path.dirname(ALERT_LOG_FILE), exist_ok=True)

# Initialize alert log if it doesn't exist
if not os.path.exists(ALERT_LOG_FILE):
    with open(ALERT_LOG_FILE, 'w') as f:
        json.dump([], f)

@app.route('/')
def dashboard():
    return render_template('dashboard.html')

@app.route('/alerts')
def get_alerts():
    try:
        with open(ALERT_LOG_FILE, 'r') as f:
            alerts = json.load(f)
        # Sort alerts by timestamp in reverse order (newest first)
        alerts.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
        return jsonify(alerts)
    except Exception as e:
        print(f"Error accessing alerts: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/health')
def health_check():
    return jsonify({"status": "healthy", "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")})

if __name__ == '__main__':
    print("Starting SecOS Defender Web Dashboard...")
    print("Access the dashboard at http://localhost:5000")
    app.run(debug=False, host='0.0.0.0') 