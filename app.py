from flask import Flask, render_template, request, jsonify
from packages import crawler, sqli, XSS
import os, json, subprocess, io
import google.generativeai as genai
from flask import send_file
import requests

app = Flask(__name__)
REPORT_DIR = 'reports'

if not os.path.exists(REPORT_DIR):
    os.makedirs(REPORT_DIR)

genai.configure(api_key=os.environ.get("GOOGLE_API_KEY"))

session = requests.Session()

def get_reports():
    if not os.path.exists(REPORT_DIR):
        os.makedirs(REPORT_DIR)
    files = sorted(os.listdir(REPORT_DIR), reverse=True)
    return [f for f in files if f.endswith('.json')]

@app.route('/')
def index():
    return render_template("index.html", results = None)

@app.route('/deep_scan', methods=['POST'])
def scan():

    if session is None:
        return "Error: Could not authenticate with target. Check if DVWA is running.", 500

    target_url = request.form.get('target_url')

    results = crawler.crawl(target_url, session)
    all_forms = results.get('forms', [])
    sqli_findings = sqli.injector(all_forms, session)
    xss_findings = XSS.injector(all_forms, session)
    total_findings = sqli_findings + xss_findings

    report_filename = f"scan_report_latest.json"

    filepath = os.path.join(REPORT_DIR, report_filename)

    with open(filepath, 'w') as f:
        json.dump(total_findings, f, indent=4)

    return render_template('index.html',
                           results=total_findings,
                           target=target_url,
                           reports=get_reports())


@app.route('/get_ai_analysis')
def get_ai_analysis():
    try:
        report_path = os.path.join(REPORT_DIR, "scan_report_latest.json")
        if not os.path.exists(report_path):
            return jsonify({"analysis": "Error: Run a scan first to generate a report."})

        with open(report_path, 'r') as f:
            report_data = json.load(f)

            api_key = os.environ.get("GOOGLE_API_KEY")
            if not api_key:
                return jsonify(
                    {"analysis": "CRITICAL: API Key is MISSING from environment. Run: $env:GOOGLE_API_KEY='your_key'"})

        model = genai.GenerativeModel('gemini-2.5-flash')
        prompt = (
            f"You are a Senior Security Auditor. Analyze these specific findings: {json.dumps(report_data[:5])}. "
            "For each, explain: 1. Why this payload works on this URL. 2. The specific line of code fix (e.g., Prepared Statements). ",
            "Keep it technical and concise for a terminal output. 3. Generate a PHP/JS/Python code block needed to fix the vulnerability.",
            "4. Rate the severity (Low/Medium/High/Critical)."
        )
        response = model.generate_content(prompt)
        return jsonify({"analysis": response.text})
    except Exception as e:
        print(f"DEBUG ERROR: {e}")
        return jsonify({"analysis": f"API ERROR: {str(e)}"})

@app.route('/view_report/<filename>')
def view_report(filename):
    filepath = os.path.join(REPORT_DIR, filename)
    with open(filepath, 'r') as f:
        data = json.load(f)
    return render_template('index.html', results=data, target=filename)

@app.route('/download/<filename>')
def download_report(filename):
    file_path = os.path.join(REPORT_DIR, filename)
    if not os.path.exists(file_path):
        return "Report not found", 404
    with open(file_path, 'rb') as f:
        file_data = f.read()
    try:
        os.remove(file_path)
        print(f"\n[!] SYSTEM WIPED: {filename} deleted securely.\n")
    except Exception as e:
        print(f"Cleanup Error: {e}")

    return send_file(
        io.BytesIO(file_data),
        mimetype='application/json',
        as_attachment=True,
        download_name=filename
    )

if __name__ == '__main__':
    app.run(debug=True)





