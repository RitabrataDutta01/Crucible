from ctypes.util import test
from datetime import datetime
from flask import Flask, render_template, request, jsonify
from packages import crawler, sqli, XSS, lfi
import os, json, subprocess, io
import google.generativeai as genai
from flask import send_file
import requests, sys
from bs4 import BeautifulSoup


def resource_path(relative_path):
    
    try:
        
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)

TEMPLATE_DIR = resource_path('templates')
STATIC_DIR = resource_path('static')
DATA_DIR = resource_path('data')

app = Flask(__name__, template_folder=TEMPLATE_DIR, static_folder=STATIC_DIR)
REPORT_DIR = 'reports'

if not os.path.exists(REPORT_DIR):
    os.makedirs(REPORT_DIR)

genai.configure(api_key=os.environ.get("GOOGLE_API_KEY"))

session = requests.Session()

def DVWA_login(base_url, username = "admin", password = "password"):
    
    if not base_url.startswith(('http://', 'https://')):
        base_url = 'http://' + base_url
    
    login_url = base_url.rstrip('/') + '/login.php'
    
    r = session.get(login_url)
    soup = BeautifulSoup(r.text, 'html.parser')
    
    token_input = soup.find('input', {'name': 'user_token'})
    if not token_input:
        print("[-] DVWA Login Failed: CSRF token not found.")
        return None
    
    user_token = token_input.get('value', '')
    payload = {
        'username': username,
        'password': password,
        'Login': 'Login',
        'user_token': user_token
    }
    
    r = session.post(login_url, data=payload)
    
    if 'login.php' in r.url or 'Login failed' in r.text:
        print("[-] DVWA Login Failed: Check credentials and DVWA status.")
        return None
    
    print(f"[+] DVWA Login Successful. {username}")
    
    security_url = base_url.rstrip('/') + '/security.php'
    session.post(security_url, data={'security': 'medium', 'seclev_submit': 'Submit'})
    
    return session

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
    
    if not target_url.startswith(('http://', 'https://')):
        target_url = 'http://' + target_url
    
    dvwa_user = request.form.get('dvwa_user', 'admin')
    dvwa_pass = request.form.get('dvwa_pass', 'password')
    authenticated_session = DVWA_login(target_url, dvwa_user, dvwa_pass)
    if authenticated_session is None:
        return "Error: Could not authenticate with DVWA. Check credentials and URL.", 500

    results = crawler.crawl(target_url, authenticated_session)
    all_forms = results.get('forms', [])
    #sqli_findings = sqli.injector(all_forms, authenticated_session)
    #xss_findings = XSS.injector(all_forms, authenticated_session)
    lfi_findings = sqli.injector(all_forms, authenticated_session) + XSS.injector(all_forms, authenticated_session) + lfi.injector(results, authenticated_session)
    total_findings = lfi_findings

    report_filename = f"scan_report_latest.json"

    filepath = os.path.join(REPORT_DIR, report_filename)
    
    bxss_file = os.path.join(REPORT_DIR, "blind_xss_hits.json")
    bxss_findings = []

    if os.path.exists(bxss_file):
        with open(bxss_file, 'r') as f:
            bxss_findings = json.load(f)
            
    active_findings = total_findings + bxss_findings

    with open(filepath, 'w') as f:
        json.dump(active_findings, f, indent=4)
    
    if os.path.exists(bxss_file):
        try:
            os.remove(bxss_file) 
            print("[!] Blind XSS logs cleared and merged into main report.")
        except Exception as e:
            print(f"Cleanup Error: {e}")

    return render_template('index.html',
                           results=active_findings,
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
    file_path = os.path.abspath(os.path.join(REPORT_DIR, filename))
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

@app.route('/bxss/<scan_id>')
def bxss_callback(scan_id):
    
    victim_data = {
        "timestamp": str(datetime.now()),
        "scan_id": scan_id,
        "victim_ip": request.remote_addr,
        "user_agent": request.headers.get('User-Agent'),
        "referrer": request.headers.get('Referer'),
        "vulnerability": "Blind XSS verified"
    }
    
    try:
        report_path = os.path.join(REPORT_DIR, "blind_xss_hits.json")
        hits = []
        
        if os.path.exists(report_path):
            with open(report_path, 'r') as f:
                try:
                    hits = json.load(f)
                except json.JSONDecodeError:
                    hits = []
        
        hits.append(victim_data)
        with open(report_path, 'w') as f:
            json.dump(hits, f, indent=4)

    except Exception as e:
        print(f"[!] Error logging Blind XSS: {e}")

    print(f"\n[🔥] BLIND XSS HIT! ID: {scan_id} from {request.remote_addr}")
    return "OK", 200

if __name__ == '__main__':
    app.run(debug=True)

