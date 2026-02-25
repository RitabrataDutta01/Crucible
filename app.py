from flask import Flask, render_template, request, jsonify
from packages import crawler, sqli
import os

app = Flask(__name__)

@app.route('/')
def index():
    return render_template("index.html", results = None)

#target = 'https://demo.testfire.net/'

#res = crawler.crawl(target, max_depth=1)

#sqli_vulnerable = sqli.injector(res['forms'])
#print(sqli_vulnerable)

@app.route('/scan', methods=['POST'])
def scan():
    target_url = request.form.get('target_url')

    results = crawler.crawl(target_url)
    sqli_vulnerable = sqli.injector(results['forms'])

    return render_template('index.html', results = sqli_vulnerable)

if __name__ == '__main__':
    app.run(debug=True)