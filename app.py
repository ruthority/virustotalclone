# app.py (using Flask)

import os
import json
import requests
import time
import base64
import hashlib
from urllib.parse import unquote
from flask import Flask, request, jsonify, render_template

# The recommended way to handle your API key in production
API_KEY = "ed3b051406ab2001bdf787e4f4aed79ca290616120d9325cd248e955d0311e43"

app = Flask(__name__)

def get_report_from_analysis_id(analysis_id, max_attempts=10, delay=15):
    """Polls the VirusTotal API for a completed analysis report and gets the final file report."""
    headers = {"x-apikey": API_KEY}
    for attempt in range(max_attempts):
        response = requests.get(f"https://www.virustotal.com/api/v3/analyses/{analysis_id}", headers=headers)
        report = response.json()
        status = report.get('data', {}).get('attributes', {}).get('status')
        if status == 'completed':
            file_id = report.get('meta', {}).get('file_info', {}).get('sha256')
            if file_id:
                file_report_resp = requests.get(f"https://www.virustotal.com/api/v3/files/{file_id}", headers=headers)
                file_report_resp.raise_for_status()
                final_report = file_report_resp.json()
                final_report['meta'] = {'analysis_id': analysis_id}
                return final_report
            return report
        time.sleep(delay)
    return {"data": {"attributes": {"status": "timed_out"}}, "meta": {"analysis_id": analysis_id}}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan_url', methods=['GET', 'POST'])
def scan_url():
    if request.method == 'GET':
        return jsonify({"error": "This endpoint only accepts POST requests from the web form."}), 405

    try:
        url = request.form.get('url')
        if not url:
            return jsonify({"error": "URL not provided."}), 400
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        headers = {"x-apikey": API_KEY}
        data = {"url": url}
        requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data=data).raise_for_status()
        report_response = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers={"x-apikey": API_KEY})
        report_response.raise_for_status()
        report_data = report_response.json()
        return jsonify(report_data)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/scan_file', methods=['GET', 'POST'])
def scan_file():
    if request.method == 'GET':
        return jsonify({"error": "This endpoint only accepts POST requests from the web form."}), 405

    try:
        if 'file' not in request.files:
            return jsonify({"error": "No file part in the request."}), 400
        file = request.files['file']
        if file.filename == '':
            return jsonify({"error": "No selected file."}), 400

        # Read the file data and compute its hashes
        file_bytes = file.read()
        sha256_hash = hashlib.sha256(file_bytes).hexdigest()
        md5_hash = hashlib.md5(file_bytes).hexdigest()
        sha1_hash = hashlib.sha1(file_bytes).hexdigest()

        headers_api = {"x-apikey": API_KEY}

        # 1. Check if the file's hash already exists in VirusTotal
        # VirusTotal primarily uses SHA-256 for file identification.
        hash_check_response = requests.get(f"https://www.virustotal.com/api/v3/files/{sha256_hash}", headers=headers_api)

        if hash_check_response.status_code == 200:
            # File already exists, return its report
            report_data = hash_check_response.json()
            # Add the other hashes to the report for completeness
            report_data['hashes'] = {
                'md5': md5_hash,
                'sha1': sha1_hash,
                'sha256': sha256_hash
            }
            return jsonify(report_data)
        elif hash_check_response.status_code == 404:
            # File does not exist, proceed with upload
            files = {'file': (file.filename, file_bytes)}
            submission_response = requests.post("https://www.virustotal.com/api/v3/files", headers=headers_api, files=files)
            submission_response.raise_for_status()
            analysis_id = submission_response.json().get('data', {}).get('id')

            if not analysis_id:
                return jsonify({"error": "Failed to get analysis ID from submission."}), 400

            report = get_report_from_analysis_id(analysis_id)
            # Add the other hashes to the report for completeness
            report['hashes'] = {
                'md5': md5_hash,
                'sha1': sha1_hash,
                'sha256': sha256_hash
            }
            return jsonify(report)
        else:
            # Handle other HTTP errors gracefully
            hash_check_response.raise_for_status()

    except requests.exceptions.HTTPError as err:
        return jsonify({"error": f"HTTP Error: {err}"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run()