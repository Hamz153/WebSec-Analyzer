import os
import threading
import queue
import sys
import uuid
from flask import Flask, render_template, request, jsonify, send_from_directory, Response
from WebSecAnalyzer import run_scan, wordlist_sub_default, wordlist_dic_default, wordlist_file_default

app = Flask(__name__)

# Configuration
OUTPUT_DIR = "output"
os.makedirs(OUTPUT_DIR, exist_ok=True)

# Map scan IDs to queues
scan_logs = {}

class MultiUserLogger:
    def __init__(self, original_stdout):
        self.original_stdout = original_stdout

    def write(self, data):
        if data.strip():
            # Broadcast to all active scan queues
            # In a real multi-user app, we'd want more granular control,
            # but for this internal tool, broadcasting is better than splitting.
            for q in scan_logs.values():
                q.put(data)
        self.original_stdout.write(data)

    def flush(self):
        self.original_stdout.flush()

sys.stdout = MultiUserLogger(sys.stdout)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def start_scan():
    data = request.json
    target = data.get('target')
    if not target:
        return jsonify({"error": "Target is required"}), 400

    scan_id = str(uuid.uuid4())
    log_queue = queue.Queue()
    scan_logs[scan_id] = log_queue

    # Extract options
    options = {
        "subdomain_wordlist": data.get('subdomain_wordlist', wordlist_sub_default),
        "directory_wordlist": data.get('directory_wordlist', wordlist_dic_default),
        "file_wordlist": data.get('file_wordlist', wordlist_file_default),
        "depth": int(data.get('depth', 2)),
        "threads": int(data.get('threads', 20)),
        "output_file": f"WebSecAnalyzer_{scan_id}.pdf",
        "username": data.get('username'),
        "password": data.get('password'),
        "login_url": data.get('login_url'),
        "auto_csrf": data.get('auto_csrf', False),
        "auto_fields": data.get('auto_fields', False)
    }

    def run_async_scan(s_id, target_in, opts):
        try:
            run_scan(target_in, **opts)
            scan_logs[s_id].put("SCAN_COMPLETE")
        except Exception as e:
            scan_logs[s_id].put(f"ERROR: {str(e)}")
            scan_logs[s_id].put("SCAN_COMPLETE")

    thread = threading.Thread(target=run_async_scan, args=(scan_id, target, options))
    thread.start()

    return jsonify({"scan_id": scan_id}), 202

@app.route('/logs/<scan_id>')
def stream_logs(scan_id):
    if scan_id not in scan_logs:
        return jsonify({"error": "Invalid scan ID"}), 404

    def generate():
        q = scan_logs[scan_id]
        while True:
            log = q.get()
            yield f"data: {log}\n\n"
            if log == "SCAN_COMPLETE":
                # Clean up queue after completion
                # Delay cleanup slightly to ensure last message is sent
                break
        del scan_logs[scan_id]

    return Response(generate(), mimetype='text/event-stream')

@app.route('/reports')
def list_reports():
    files = sorted([f for f in os.listdir(OUTPUT_DIR) if f.endswith('.pdf') or f.endswith('.txt')], reverse=True)
    return jsonify(files)

@app.route('/reports/<path:filename>')
def download_report(filename):
    return send_from_directory(OUTPUT_DIR, filename)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
