from flask import Flask, render_template, request, jsonify
from packages import crawler, sqli
import os, json

app = Flask(__name__)
REPORT_DIR = 'reports'
if not os.path.exists(REPORT_DIR):
    os.makedirs(REPORT_DIR)
@app.route('/')
def index():
    return render_template("index.html", results = None)
@app.route('/scan', methods=['POST'])
def scan():
    target_url = request.form.get('target_url')

    results = crawler.crawl(target_url)
    sqli_vulnerable = sqli.injector(results['forms'])

    return render_template('index.html', results=sqli_vulnerable, target=target_url)

@app.route('/history')
def history():
    files = os.listdir(REPORT_DIR)
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