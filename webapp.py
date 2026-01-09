from flask import Flask, render_template, request, redirect, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import os

app = Flask(__name__)
app.secret_key = 'change-this-secret-key'
DB_FILE = 'users.db'

def init_db():
    if not os.path.exists(DB_FILE):
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute('''CREATE TABLE users (
                        id INTEGER PRIMARY KEY,
                        username TEXT UNIQUE NOT NULL,
                        email TEXT UNIQUE NOT NULL,
                        password TEXT NOT NULL,
                        is_admin INTEGER DEFAULT 0
                    )''')
        conn.commit()
        conn.close()

def get_db():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not username or not password:
            flash('Username and password required', 'error')
            return render_template('login.html')
        
        conn = get_db()
        # SECURE: Use parameterized query
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()
        
        # Check hashed password
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['is_admin'] = user['is_admin']
            
            if user['is_admin']:
                return '<script>window.top.location.href = "/admin";</script>'
            else:
                return '<script>window.top.location.href = "/dashboard";</script>'
        else:
            flash('Invalid username or password', 'error')
            return render_template('login.html')
    
    return render_template('login.html')

@app.route('/registre', methods=['GET', 'POST'])
def registre():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if not all([username, email, password, confirm_password]):
            flash('All fields required', 'error')
            return render_template('registre.html')
        
        if len(username) < 3:
            flash('Username must be at least 3 characters', 'error')
            return render_template('registre.html')
        
        if len(password) < 6:
            flash('Password must be at least 6 characters', 'error')
            return render_template('registre.html')
        
        if password != confirm_password:
            flash('Passwords do not match', 'error')
            return render_template('registre.html')
        
        conn = get_db()
        
        # Check if username already exists
        existing_user = conn.execute('SELECT username FROM users WHERE username = ?', (username,)).fetchone()
        if existing_user:
            conn.close()
            flash('Username already exists. Please choose another one.', 'error')
            return render_template('registre.html')
        
        # Check if email already exists
        existing_email = conn.execute('SELECT email FROM users WHERE email = ?', (email,)).fetchone()
        if existing_email:
            conn.close()
            flash('Email already registered. Please use another email or login.', 'error')
            return render_template('registre.html')
        
        try:
            hashed_password = generate_password_hash(password)
            conn.execute('INSERT INTO users (username, email, password, is_admin) VALUES (?, ?, ?, ?)',
                        (username, email, hashed_password, 0))
            conn.commit()
            flash('Registration successful! Please login.', 'success')
            return '<script>window.top.location.href = "/login";</script>'
        except Exception as e:
            flash('An error occurred during registration. Please try again.', 'error')
        finally:
            conn.close()
    
    return render_template('registre.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect('/login')
    if session.get('is_admin'):
        return redirect('/admin')
    return render_template('dashboard.html', username=session['username'])

@app.route('/admin')
def admin():
    if 'user_id' not in session or not session.get('is_admin'):
        flash('Access denied. Admin only.', 'error')
        return redirect('/login')
    
    conn = get_db()
    users = conn.execute('SELECT id, username, email, is_admin FROM users').fetchall()
    conn.close()
    
    return render_template('admin.html', users=users, username=session['username'])

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out', 'success')
    return redirect('/login')


if __name__ == '__main__':
    init_db()
    app.run(debug=True)