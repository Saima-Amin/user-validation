from flask import Flask, request, session, render_template, redirect, url_for, flash
from flask_bcrypt import Bcrypt
import pymysql
import os
from dotenv import load_dotenv
import re

# Load environment variables from .env file (for local development)
load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'your-secret-key')
bcrypt = Bcrypt(app)

# Establish a MySQL connection (Google Cloud SQL or local/Aiven)
def get_db_connection():
    try:
        # For Google App Engine, use Unix socket; for local/Aiven, use host/port
        if os.environ.get('GAE_ENV', '').startswith('standard'):
            # Google Cloud SQL connection using Unix socket
            conn = pymysql.connect(
                unix_socket=f"/cloudsql/{os.environ.get('CLOUD_SQL_CONNECTION_NAME')}",
                user=os.environ.get('DB_USER', 'your_username'),
                password=os.environ.get('DB_PASS', 'your_password'),
                db=os.environ.get('DB_NAME', 'your_database'),
                charset='utf8mb4',
                cursorclass=pymysql.cursors.DictCursor
            )
        else:
            # Local or Aiven connection (for development)
            conn = pymysql.connect(
                host=os.environ.get('DB_HOST', 'localhost'),
                user=os.environ.get('DB_USER', 'your_username'),
                password=os.environ.get('DB_PASS', 'your_password'),
                db=os.environ.get('DB_NAME', 'your_database'),
                port=int(os.environ.get('DB_PORT', 3306)),
                charset='utf8mb4',
                cursorclass=pymysql.cursors.DictCursor,
                ssl={'ca': 'ca.pem'} if os.environ.get('DB_HOST') != 'localhost' else None
            )
        return conn
    except pymysql.MySQLError as e:
        raise Exception(f"Database connection failed: {str(e)}")

# Create users table if not exists
def init_db():
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS users (
                        id INT AUTO_INCREMENT PRIMARY KEY,
                        username VARCHAR(30) UNIQUE,
                        password VARCHAR(100),
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)
            conn.commit()
    except Exception as e:
        print(f"Error initializing database: {str(e)}")
        raise

# Render registration page
@app.route('/register', methods=['GET'])
def register_page():
    return render_template('register.html')

# Handle registration form submission
@app.route('/register', methods=['POST'])
def register():
    username = request.form.get('username')
    password = request.form.get('password')

    # Validate username: alphanumeric, 3-30 characters
    if not username or not re.match(r'^[a-zA-Z0-9]{3,30}$', username):
        flash('Username must be 3-30 characters and alphanumeric', 'error')
        return redirect(url_for('register_page'))

    # Validate password: at least 8 characters
    if not password or len(password) < 8:
        flash('Password must be at least 8 characters', 'error')
        return redirect(url_for('register_page'))

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

    try:
        with get_db_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
                if cursor.fetchone():
                    flash('Username already exists', 'error')
                    return redirect(url_for('register_page'))

                cursor.execute(
                    "INSERT INTO users (username, password) VALUES (%s, %s)",
                    (username, hashed_password)
                )
                conn.commit()
                flash('Registration successful! You can now log in.', 'success')
                return redirect(url_for('login_page'))
    except Exception as e:
        flash(f'Error: {str(e)}', 'error')
        return redirect(url_for('register_page'))

# Render login page
@app.route('/login', methods=['GET'])
def login_page():
    return render_template('login.html')

# Handle login form submission
@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')

    if not username or not password:
        flash('Username and password required', 'error')
        return redirect(url_for('login_page'))

    try:
        with get_db_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute("SELECT password FROM users WHERE username = %s", (username,))
                user = cursor.fetchone()
                if user and bcrypt.check_password_hash(user['password'], password):
                    session['username'] = username
                    flash('Login successful!', 'success')
                    return redirect(url_for('home'))
                else:
                    flash('Invalid credentials', 'error')
                    return redirect(url_for('login_page'))
    except Exception as e:
        flash(f'Error: {str(e)}', 'error')
        return redirect(url_for('login_page'))

# Home page after login
@app.route('/')
def home():
    if 'username' in session:
        return render_template('home.html', username=session['username'])
    return redirect(url_for('login_page'))

# Initialize database on startup
if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 8080)))