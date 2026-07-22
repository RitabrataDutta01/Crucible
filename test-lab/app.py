from flask import Flask, request, render_template, make_response
import sqlite3, os, time

app = Flask(__name__)
DB_PATH = os.path.join(os.path.dirname(__file__), 'crucible_lab.db')

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')

    username = request.form.get('username', '')
    password = request.form.get('password', '')

    conn = get_db()
    cur = conn.cursor()
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    try:
        cur.execute(query)
        user = cur.fetchone()
    except Exception as e:
        return render_template('login.html', error=str(e))
    finally:
        conn.close()

    if user:
        return render_template('login.html', message=f"Welcome, {user['username']}! (role: {user['role']})")
    return render_template('login.html', error='Invalid credentials')

@app.route('/search')
def search():
    q = request.args.get('q', '')
    results = []

    if q:
        conn = get_db()
        cur = conn.cursor()
        try:
            query = f"SELECT * FROM products WHERE name LIKE '%{q}%'"
            cur.execute(query)
            results = [dict(r) for r in cur.fetchall()]
        except Exception as e:
            return render_template('search.html', q=q, error=str(e))
        finally:
            conn.close()

    return render_template('search.html', q=q, results=results)

@app.route('/products')
def products():
    category = request.args.get('category', '')
    results = []

    if category:
        conn = get_db()
        cur = conn.cursor()
        try:
            query = f"SELECT * FROM products WHERE category='{category}'"
            cur.execute(query)
            results = [dict(r) for r in cur.fetchall()]
        except Exception as e:
            conn.close()
            return render_template('products.html', category=category, error=str(e))
        conn.close()

    return render_template('products.html', category=category, results=results)

@app.route('/product')
def product():
    pid = request.args.get('id', '')
    product = None

    if pid:
        conn = get_db()
        cur = conn.cursor()
        try:
            # Simulate time-based injection support via LIKE
            if 'sleep' in pid.lower() or 'delay' in pid.lower():
                time.sleep(8)
            query = f"SELECT * FROM products WHERE id={pid}"
            cur.execute(query)
            row = cur.fetchone()
            product = dict(row) if row else None
        except Exception as e:
            conn.close()
            return render_template('products.html', category='', error=str(e))
        conn.close()

    return render_template('products.html', category='', selected=product)

@app.route('/logout')
def logout():
    resp = make_response(render_template('login.html', message='Logged out successfully'))
    return resp

if __name__ == '__main__':
    print('[+] Crucible Test Lab running on http://localhost:5050')
    app.run(host='0.0.0.0', port=5050, debug=True)
