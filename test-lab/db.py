import sqlite3, os

DB_PATH = os.path.join(os.path.dirname(__file__), 'crucible_lab.db')

def get_conn():
    return sqlite3.connect(DB_PATH)

def init_db():
    conn = get_conn()
    cur = conn.cursor()

    cur.executescript('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user'
        );

        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            category TEXT NOT NULL,
            price REAL NOT NULL,
            description TEXT
        );

        DELETE FROM users;
        DELETE FROM products;

        INSERT INTO users (username, password, role) VALUES
            ('admin', 'supersecret123', 'admin'),
            ('user1', 'password1', 'user'),
            ('jdoe', 'letmein', 'user');

        INSERT INTO products (name, category, price, description) VALUES
            ('Widget Pro', 'electronics', 29.99, 'A high-quality widget for professionals.'),
            ('Gadget X', 'electronics', 49.99, 'Next-gen gadget with bluetooth.'),
            ('USB-C Hub', 'electronics', 19.99, '7-in-1 USB-C hub with HDMI.'),
            ('Ergonomic Mouse', 'electronics', 34.99, 'Wireless vertical mouse.'),
            ('Running Shoes', 'sports', 89.99, 'Lightweight running shoes with gel sole.'),
            ('Yoga Mat', 'sports', 24.99, 'Non-slip extra thick yoga mat.'),
            ('Dumbbell Set', 'sports', 149.99, 'Adjustable dumbbells 5-25 lbs.'),
            ('Water Bottle', 'sports', 14.99, 'Insulated stainless steel 32oz.'),
            ('Mystery Novel', 'books', 12.99, 'A gripping whodunit thriller.'),
            ('Python Guide', 'books', 39.99, 'Comprehensive Python programming guide.'),
            ('Cookbook', 'books', 29.99, '100 easy vegan recipes.'),
            ('History of Rome', 'books', 24.99, 'An epic journey through ancient Rome.');
    ''')

    conn.commit()
    conn.close()
    print(f"[+] Database initialized: {DB_PATH}")

if __name__ == '__main__':
    init_db()
