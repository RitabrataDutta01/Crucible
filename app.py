from flask import Flask, render_template, request, jsonify
from packages import crawler, sqli, XSS
import os, json

app = Flask(__name__)
REPORT_DIR = 'reports'

if not os.path.exists(REPORT_DIR):
    os.makedirs(REPORT_DIR)

@app.route('/')
def index():
    return render_template("index.html", results = None)

@app.route('/deep_scan', methods=['POST'])
def scan():
    target_url = request.form.get('target_url')

    results = crawler.crawl(target_url)
    all_forms = results.get('forms', [])

    sqli_findings = sqli.injector(all_forms)

    xss_findings = XSS.injector(all_forms)

    total_findings = sqli_findings + xss_findings

    return render_template('index.html', results=total_findings, target=target_url)

@app.route('/history')
def history():
    files = sorted(os.listdir(REPORT_DIR), reverse=True)
    reports = [f for f in files if f.endswith('.json')]
    return render_template('history.html', reports=reports)

@app.route('/view_report/<filename>')
def view_report(filename):
    filepath = os.path.join(REPORT_DIR, filename)
    with open(filepath, 'r') as f:
        data = json.load(f)
    return render_template('index.html', results=data, target=filename)

if __name__ == '__main__':
    app.run(debug=True)