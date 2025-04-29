
from flask import Flask, render_template_string, request, redirect, url_for, session, flash, send_file
import os
import json
import base64
import random
import string
from hashlib import sha256
from datetime import datetime, timedelta
from cryptography.fernet import Fernet
from io import BytesIO

app = Flask(__name__)
app.secret_key = os.urandom(24)

USER_DATA_FILE = "users.json"
DATA_FILE = "passwords.enc"

def generate_key(password):
    return base64.urlsafe_b64encode(sha256(password.encode()).digest())

def encrypt_data(data, password):
    return Fernet(generate_key(password)).encrypt(json.dumps(data).encode())

def decrypt_data(token, password):
    return json.loads(Fernet(generate_key(password)).decrypt(token).decode())

def save_data(data, password):
    with open(DATA_FILE, "wb") as f:
        f.write(encrypt_data(data, password))

def load_data(password):
    if not os.path.exists(DATA_FILE):
        return []
    with open(DATA_FILE, "rb") as f:
        try:
            return decrypt_data(f.read(), password)
        except:
            return []

def generate_password(length=16):
    chars = string.ascii_letters + string.digits + string.punctuation
    while True:
        pwd = ''.join(random.choices(chars, k=length))
        if all(any(c in group for c in pwd) for group in [string.ascii_lowercase, string.ascii_uppercase, string.digits, string.punctuation]):
            return pwd

def check_strength(pwd):
    score = sum([
        any(c.islower() for c in pwd),
        any(c.isupper() for c in pwd),
        any(c.isdigit() for c in pwd),
        any(c in string.punctuation for c in pwd)
    ])
    if len(pwd) >= 12 and score == 4:
        return "Strong"
    elif len(pwd) >= 8 and score >= 3:
        return "Okay"
    return "Weak"

def load_users():
    return json.load(open(USER_DATA_FILE)) if os.path.exists(USER_DATA_FILE) else {}

def save_users(users):
    with open(USER_DATA_FILE, "w") as f:
        json.dump(users, f)

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        users = load_users()
        username = request.form['username']
        password = request.form['password']
        hashed_pw = sha256(password.encode()).hexdigest()
        if username in users and users[username] == hashed_pw:
            session['username'] = username
            session['password'] = password
            return redirect(url_for('home'))
        flash("Invalid login.")
    return render_template_string(login_html)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        users = load_users()
        username = request.form['username']
        password = request.form['password']
        if username in users:
            flash("Username exists.")
        else:
            users[username] = sha256(password.encode()).hexdigest()
            save_users(users)
            return redirect(url_for('login'))
    return render_template_string(register_html)

@app.route('/home', methods=['GET', 'POST'])
def home():
    if 'username' not in session:
        return redirect(url_for('login'))

    entries = load_data(session['password'])
    if request.method == 'POST':
        title = request.form['title']
        uname = request.form['username']
        pwd = request.form['password']
        entries.append({
            'title': title,
            'username': uname,
            'password': pwd,
            'created': datetime.now().isoformat()
        })
        save_data(entries, session['password'])
        return redirect(url_for('home'))

    for entry in entries:
        created = datetime.fromisoformat(entry['created'])
        entry['expired'] = (datetime.now() - created) > timedelta(days=30)
        entry['strength'] = check_strength(entry['password'])

    return render_template_string(home_html, entries=entries)

@app.route('/delete/<int:index>')
def delete(index):
    if 'username' not in session:
        return redirect(url_for('login'))
    data = load_data(session['password'])
    if 0 <= index < len(data):
        data.pop(index)
        save_data(data, session['password'])
    return redirect(url_for('home'))

@app.route('/backup')
def backup():
    if 'username' not in session:
        return redirect(url_for('login'))
    data = load_data(session['password'])
    encrypted_json = encrypt_data(data, session['password'])
    return send_file(BytesIO(encrypted_json), mimetype='application/octet-stream',
                     as_attachment=True, download_name='passwords_backup.enc')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

login_html = """<!doctype html><html><head><title>Login</title></head><body class="container">
<h2>Login</h2>
<form method="post">
  Username: <input name="username"><br>
  Password: <input type="password" name="password"><br>
  <button type="submit">Login</button>
</form>
<p>Or <a href="/register">Register</a></p></body></html>"""

register_html = """<!doctype html><html><head><title>Register</title></head><body class="container">
<h2>Register</h2>
<form method="post">
  Username: <input name="username"><br>
  Password: <input type="password" name="password"><br>
  <button type="submit">Register</button>
</form></body></html>"""

home_html = """<!doctype html><html><head>
<title>Dashboard</title>
<link rel="stylesheet" href="/static/static.css">
<script>
function setTheme(bg, input) {
  document.body.style.backgroundColor = bg;
  document.querySelectorAll('input, textarea').forEach(el => el.style.backgroundColor = input);
}
</script>
</head><body class="container">
<h2>Welcome {{ session['username'] }} <small style="font-weight:normal;">(Phase 2)</small></h2>
<a href="/logout">Logout</a>
<a href="/backup" style="float:right;">Download Backup</a>
<hr>
<h3>Add New Login</h3>
<form method="post">
  Title: <input name="title"><br>
  Username: <input name="username"><br>
  Password: <input name="password" id="pwd"><br>
  <button type="button" onclick="document.getElementById('pwd').value=Math.random().toString(36).slice(-12)">Generate</button>
  <button type="submit">Save</button>
</form>
<hr>
<h3>Stored Logins</h3>
{% for e in entries %}
<div class="card">
  <strong>{{ e['title'] }}</strong><br>
  Username: {{ e['username'] }}<br>
  Password: {{ e['password'] }}<br>
  Strength: <span class="{{ e['strength'].lower() }}">{{ e['strength'] }}</span>
  {% if e['expired'] %}<br><span class="expired">Password expired!</span>{% endif %}<br>
  <a href="/delete/{{ loop.index0 }}">Delete</a>
</div>
{% endfor %}
<h3>Theme</h3>
<button onclick="setTheme('#111', '#333')">Dark Mode</button>
<button onclick="setTheme('#fff', '#f0f0f0')">Light Mode</button>
</body></html>"""

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
