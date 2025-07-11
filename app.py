from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO, emit
import threading, requests
import subprocess
import time
import csv

app = Flask(__name__)
socketio = SocketIO(app)

# Global variables
script_running = False
script_thread = None

# Load rules from CSV file
def load_rules(filename):
    rules = []
    try:
        with open(filename, 'r') as file:
            reader = csv.DictReader(file)
            for row in reader:
                rules.append(row)
    except Exception as e:
        print(f"Error loading rules: {e}")
    return rules

# Load blocked IPs from the file
def load_blocked_ips():
    blocked_ips = []
    try:
        with open('blocked_ip.txt', 'r') as file:
            blocked_ips = [line.strip() for line in file]
    except FileNotFoundError:
        pass
    return blocked_ips

# Load logs from the file
# def load_logs():
#     logs = []
#     try:
#         with open('logs.txt', 'r') as file:
#             logs = [line.strip() for line in file]
#     except FileNotFoundError:
#         pass
#     return logs

def load_logs():
    logs = []
    try:
        with open('logs.txt', 'r') as file:
            for line in file:
                # Split each line based on spaces
                parts = line.strip().split()
                # Create a dictionary to store attributes
                log_entry = {}
                # Create attributes for each part
                for index, part in enumerate(parts):
                    log_entry[f'attr{index + 1}'] = part
                logs.append(log_entry)
    except FileNotFoundError:
        pass
    return logs



def run_script():
    """Function to run the main.py script."""
    global script_running
    script_running = True
    try:
        process = subprocess.Popen(['sudo', 'python3', 'main.py'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        for line in iter(process.stdout.readline, b''):
            socketio.emit('log_message', {'message': line.decode('utf-8').strip()})
            socketio.sleep(0.1)
        process.stdout.close()
        process.wait()
    except Exception as e:
        socketio.emit('log_message', {'message': str(e)})
    finally:
        script_running = False

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/alerts')
def alerts():
    logs = load_logs()
    return render_template('alerts.html', logs=logs)

@app.route('/blocked_ips')
def blocked_ips():
    blocked_ips = load_blocked_ips()
    return render_template('blocked_ips.html', blocked_ips=blocked_ips)

@app.route('/rules')
def rules():
    rules = load_rules('rule.csv')
    return render_template('rules.html', rules=rules)

@app.route('/logs')
def logs():
    logs = load_logs()
    return render_template('logs.html', logs=logs)

@app.route('/start')
def start():
    return render_template('start.html')

@app.route('/start_script', methods=['POST'])
def start_script():
    global script_thread
    script_running = request.form.get("start")
    if script_running is None:
        script_thread = threading.Thread(target=run_script)
        script_thread.start()
        return jsonify({"status": "started"})
    else:
        return jsonify({"status": "already running"})

@socketio.on('connect')
def handle_connect():
    if script_running:
        socketio.start_background_task(run_script)

if __name__ == '__main__':
    socketio.run(app, debug=True)

