
from flask import Flask, render_template_string, request, redirect, url_for, session, flash, g
import os
import sqlite3
import base64
import json
import random
import string
from hashlib import sha256
from datetime import datetime, timedelta
from cryptography.fernet import Fernet

app = Flask(__name__)
app.secret_key = os.urandom(24)
DATABASE = "vaultyx.db"

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_connection(exception):
    db = g.pop("db", None)
    if db is not None:
        db.close()

def init_db():
    db = get_db()
    db.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS entries (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        title TEXT NOT NULL,
        username TEXT NOT NULL,
        password TEXT NOT NULL,
        created TEXT NOT NULL,
        category TEXT DEFAULT '',
        favorite INTEGER DEFAULT 0,
        FOREIGN KEY(user_id) REFERENCES users(id)
    );
    """)
    db.commit()

@app.before_request
def before_request():
    init_db()

def generate_key(username, password):
    return base64.urlsafe_b64encode(sha256((username + password).encode()).digest())

def encrypt_text(text, username, password):
    return Fernet(generate_key(username, password)).encrypt(text.encode()).decode()

def decrypt_text(token, username, password):
    return Fernet(generate_key(username, password)).decrypt(token.encode()).decode()

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

@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        db = get_db()
        username = request.form["username"]
        password = request.form["password"]
        hashed = sha256(password.encode()).hexdigest()
        cur = db.execute("SELECT * FROM users WHERE username = ? AND password_hash = ?", (username, hashed))
        user = cur.fetchone()
        if user:
            session["user_id"] = user["id"]
            session["username"] = username
            session["password"] = password
            return redirect(url_for("home"))
        flash("Invalid login.")
    return render_template_string(login_html)

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        db = get_db()
        username = request.form["username"]
        password = request.form["password"]
        hashed = sha256(password.encode()).hexdigest()
        try:
            db.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, hashed))
            db.commit()
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("Username already exists.")
    return render_template_string(register_html)

@app.route("/home", methods=["GET", "POST"])
def home():
    if "user_id" not in session:
        return redirect(url_for("login"))

    db = get_db()
    uid = session["user_id"]
    uname = session["username"]
    pw = session["password"]

    if request.method == "POST":
        title = request.form["title"]
        username = encrypt_text(request.form["username"], uname, pw)
        password = encrypt_text(request.form["password"], uname, pw)
        category = request.form.get("category", "")
        favorite = 1 if request.form.get("favorite") else 0
        created = datetime.now().isoformat()
        db.execute("INSERT INTO entries (user_id, title, username, password, created, category, favorite) VALUES (?, ?, ?, ?, ?, ?, ?)",
                   (uid, title, username, password, created, category, favorite))
        db.commit()
        return redirect(url_for("home"))

    cur = db.execute("SELECT * FROM entries WHERE user_id = ? ORDER BY favorite DESC, title ASC", (uid,))
    seen_titles = set()
    entries = []
    for row in cur.fetchall():
        try:
            entry = {
                "id": row["id"],
                "title": row["title"],
                "username": decrypt_text(row["username"], uname, pw),
                "password": decrypt_text(row["password"], uname, pw),
                "created": row["created"],
                "category": row["category"],
                "favorite": row["favorite"]
            }
            entry["expired"] = (datetime.now() - datetime.fromisoformat(entry["created"])) > timedelta(days=30)
            entry["strength"] = check_strength(entry["password"])
            entry["reused"] = entry["title"] in seen_titles
            seen_titles.add(entry["title"])
            entries.append(entry)
        except:
            continue

    return render_template_string(home_html, entries=entries)

@app.route("/delete/<int:eid>")
def delete(eid):
    if "user_id" not in session:
        return redirect(url_for("login"))
    db = get_db()
    db.execute("DELETE FROM entries WHERE id = ? AND user_id = ?", (eid, session["user_id"]))
    db.commit()
    return redirect(url_for("home"))

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/generate-password")
def generate_password():
    chars = string.ascii_letters + string.digits + string.punctuation
    while True:
        pwd = ''.join(random.choices(chars, k=16))
        if check_strength(pwd) == "Strong":
            return pwd

login_html = """<!doctype html><html><head><title>Vaultyx Login</title></head><body style='background:#0A192F;color:white;padding:2rem;'>
<h2>Login to Vaultyx</h2>
<form method="post">
  Username: <input name="username"><br><br>
  Password: <input type="password" name="password"><br><br>
  <button type="submit">Login</button>
</form>
<p><a href="/register" style="color:#03A9F4;">Register</a></p></body></html>"""

register_html = """<!doctype html><html><head><title>Register Vaultyx</title></head><body style='background:#0A192F;color:white;padding:2rem;'>
<h2>Register for Vaultyx</h2>
<form method="post">
  Username: <input name="username"><br><br>
  Password: <input type="password" name="password"><br><br>
  <button type="submit">Register</button>
</form></body></html>"""

home_html = """<!doctype html><html><head>
<title>Vaultyx Dashboard</title>
<script>
function setTheme(mode) {
  localStorage.setItem("theme", mode);
  document.body.className = mode;
}
function generatePassword() {
  fetch("/generate-password").then(res => res.text()).then(pw => {
    document.getElementById("password").value = pw;
  });
}
window.onload = () => {
  let theme = localStorage.getItem("theme") || "dark";
  document.body.className = theme;
}
</script>
<style>
body.dark { background: #0A192F; color: white; }
body.light { background: white; color: black; }
input, button { padding: 0.5rem; margin-top: 0.5rem; }
.strong { color: limegreen; }
.okay { color: orange; }
.weak { color: red; }
.reused { background-color: rgba(255, 165, 0, 0.2); }
</style>
</head><body>
<h2>Vaultyx – Secure your digital world</h2>
<a href="/logout">Logout</a>
<div style="float:right;">
  <button onclick="setTheme('dark')">Dark</button>
  <button onclick="setTheme('light')">Light</button>
</div>
<hr>
<h3>Add Login</h3>
<form method="post">
  Title: <input name="title"><br>
  Username: <input name="username"><br>
  Password: <input name="password" id="password"><br>
  <button type="button" onclick="generatePassword()">Generate</button><br>
  Folder: <input name="category"><br>
  Favorite: <input type="checkbox" name="favorite"><br>
  <button type="submit">Save</button>
</form>
<hr>
<h3>Saved Logins</h3>
{% for e in entries %}
<div style="margin-bottom:1rem;" class="{{ 'reused' if e.reused else '' }}">
  <strong>{{ e.title }}</strong> {% if e.favorite %}⭐{% endif %}<br>
  Category: {{ e.category }}<br>
  Username: {{ e.username }}<br>
  Password: {{ e.password }}<br>
  Strength: <span class="{{ e.strength.lower() }}">{{ e.strength }}</span>
  {% if e.expired %}<br><span style="color:red;">Expired!</span>{% endif %}<br>
  {% if e.reused %}<span style="color:orange;">⚠ Reused Title</span><br>{% endif %}
  <a href="/delete/{{ e.id }}">Delete</a>
</div>
{% endfor %}
</body></html>"""

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
