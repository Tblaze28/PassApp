
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

# -- DATABASE CONNECTION --
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
        FOREIGN KEY(user_id) REFERENCES users(id)
    );
    """)
    db.commit()

@app.before_request
def before_request():
    init_db()

# -- ENCRYPTION UTILITY --
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

# -- ROUTES --

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
        flash("Invalid credentials.")
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
        created = datetime.now().isoformat()
        db.execute("INSERT INTO entries (user_id, title, username, password, created) VALUES (?, ?, ?, ?, ?)",
                   (uid, title, username, password, created))
        db.commit()
        return redirect(url_for("home"))

    cur = db.execute("SELECT * FROM entries WHERE user_id = ?", (uid,))
    entries = []
    for row in cur.fetchall():
        try:
            entry = {
                "title": row["title"],
                "username": decrypt_text(row["username"], uname, pw),
                "password": decrypt_text(row["password"], uname, pw),
                "created": row["created"]
            }
            entry["expired"] = (datetime.now() - datetime.fromisoformat(entry["created"])) > timedelta(days=30)
            entry["strength"] = check_strength(entry["password"])
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

# HTML templates
login_html = """<!doctype html><html><head><title>Login</title></head><body>
<h2>Login</h2>
<form method="post">
  Username: <input name="username"><br>
  Password: <input type="password" name="password"><br>
  <button type="submit">Login</button>
</form>
<p><a href="/register">Register</a></p></body></html>"""

register_html = """<!doctype html><html><head><title>Register</title></head><body>
<h2>Register</h2>
<form method="post">
  Username: <input name="username"><br>
  Password: <input type="password" name="password"><br>
  <button type="submit">Register</button>
</form></body></html>"""

home_html = """<!doctype html><html><head><title>Vaultyx</title></head><body>
<h2>Welcome {{ session['username'] }}</h2>
<a href="/logout">Logout</a><hr>
<h3>Add Login</h3>
<form method="post">
  Title: <input name="title"><br>
  Username: <input name="username"><br>
  Password: <input name="password"><br>
  <button type="submit">Save</button>
</form><hr>
<h3>Saved Entries</h3>
{% for e in entries %}
<div>
  <b>{{ e.title }}</b><br>
  Username: {{ e.username }}<br>
  Password: {{ e.password }}<br>
  Strength: <span style="color: {% if e.strength == 'Strong' %}green{% elif e.strength == 'Okay' %}orange{% else %}red{% endif %};">{{ e.strength }}</span>
  {% if e.expired %}<br><span style="color:red;">Expired</span>{% endif %}<br>
  <a href="/delete/{{ loop.index0 }}">Delete</a>
</div><hr>
{% endfor %}
</body></html>"""

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
