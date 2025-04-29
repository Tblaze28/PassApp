from flask import Flask, render_template_string, request, redirect, url_for, session, flash
import os
import json
import base64
import random
import string
from hashlib import sha256
from datetime import datetime, timedelta
from cryptography.fernet import Fernet

# --- CONFIGURATION ---
app = Flask(__name__)
app.secret_key = os.urandom(24)

MASTER_PASSWORD_HASH = None  # Set during first run
DATA_FILE = "passwords.enc"

# --- HTML Templates ---
login_template = """
<!doctype html>
<title>Login</title>
<h2>Login</h2>
<form method="post">
    Master Password: <input type="password" name="password">
    <input type="submit" value="Login">
</form>
"""

home_template = """
<!doctype html>
<title>Password Manager</title>
<h2>Welcome to Password Manager</h2>
<a href="{{ url_for('logout') }}">Logout</a>
<hr>
<h3>Generate New Password</h3>
<form method="post" action="/add">
    Service Title: <input name="title"><br>
    Username: <input name="username"><br>
    Password: <input name="password" id="password-field"><br>
    <button type="button" onclick="generatePassword()">Generate Password</button>
    <button type="submit">Save</button>
</form>
<script>
function generatePassword() {
    fetch("/generate-password").then(res => res.text()).then(pw => {
        document.getElementById("password-field").value = pw;
    });
}
</script>
<hr>
<h3>Search Saved Passwords</h3>
<form method="get" action="/search">
    Title: <input name="query">
    <button type="submit">Search</button>
</form>
{% if entries %}
    <h4>Results:</h4>
    {% for entry in entries %}
        <p><b>{{ entry['title'] }}</b><br>Username: {{ entry['username'] }}<br>Password: {{ entry['password'] }}<br><i>{{ entry['created'] }}</i>
        {% if entry['expired'] %}<br><span style='color:red;'>Password expired! Update soon!</span>{% endif %}</p><hr>
    {% endfor %}
{% endif %}
"""

# --- Utilities ---
def generate_key(password):
    return base64.urlsafe_b64encode(sha256(password.encode()).digest())

def encrypt_data(data, password):
    f = Fernet(generate_key(password))
    return f.encrypt(json.dumps(data).encode())

def decrypt_data(token, password):
    f = Fernet(generate_key(password))
    return json.loads(f.decrypt(token).decode())

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
            return None

def generate_strong_password(length=16):
    all_chars = string.ascii_letters + string.digits + string.punctuation
    while True:
        password = ''.join(random.choices(all_chars, k=length))
        if any(c.islower() for c in password) and any(c.isupper() for c in password) and any(c.isdigit() for c in password) and any(c in string.punctuation for c in password):
            return password

# --- Routes ---
@app.route('/', methods=['GET', 'POST'])
def login():
    global MASTER_PASSWORD_HASH
    if MASTER_PASSWORD_HASH is None:
        if os.path.exists("master.hash"):
            with open("master.hash") as f:
                MASTER_PASSWORD_HASH = f.read().strip()
        else:
            # First run setup
            if request.method == 'POST':
                pw = request.form['password']
                MASTER_PASSWORD_HASH = sha256(pw.encode()).hexdigest()
                with open("master.hash", "w") as f:
                    f.write(MASTER_PASSWORD_HASH)
                session['password'] = pw
                return redirect(url_for('home'))
            return render_template_string(login_template)

    if request.method == 'POST':
        pw = request.form['password']
        if sha256(pw.encode()).hexdigest() == MASTER_PASSWORD_HASH:
            session['password'] = pw
            return redirect(url_for('home'))
        else:
            flash("Wrong password")
            return render_template_string(login_template)
    return render_template_string(login_template)

@app.route('/home')
def home():
    if 'password' not in session:
        return redirect(url_for('login'))
    return render_template_string(home_template)

@app.route('/add', methods=['POST'])
def add():
    if 'password' not in session:
        return redirect(url_for('login'))
    title = request.form['title']
    username = request.form['username']
    password = request.form['password']

    entries = load_data(session['password']) or []
    entries.append({
        "title": title,
        "username": username,
        "password": password,
        "created": datetime.now().isoformat()
    })
    save_data(entries, session['password'])
    return redirect(url_for('home'))

@app.route('/search')
def search():
    if 'password' not in session:
        return redirect(url_for('login'))
    query = request.args.get('query', '').lower()
    entries = load_data(session['password']) or []
    results = []
    for e in entries:
        if query in e['title'].lower():
            created = datetime.fromisoformat(e['created'])
            expired = (datetime.now() - created) > timedelta(days=30)
            e['expired'] = expired
            results.append(e)
    return render_template_string(home_template, entries=results)

@app.route('/generate-password')
def generate_password():
    return generate_strong_password()

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# --- Start Server ---
if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
