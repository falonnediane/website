from flask import Flask, render_template, request, redirect, session, flash
import sqlite3
import bcrypt
import datetime
import os

app = Flask(__name__, static_url_path='/static')
app.secret_key = "secretkey"

# Datenbank-Verbindung mit Row-Factory für Namenszugriff (Behebt TypeError)
def get_db():
    conn = sqlite3.connect("database.db")
    conn.row_factory = sqlite3.Row # Wichtig für user['password']
    return conn

def init_db():
    with get_db() as conn:
        conn.execute("""
        CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT
        )
        """)
        conn.execute("""
        CREATE TABLE IF NOT EXISTS logins(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            time TEXT,
            success INTEGER
        )
        """)
        conn.commit()

init_db()

@app.route("/")
def home():
    return redirect("/login")

# Registrierung mit Hashing [cite: 37]
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        try:
            with get_db() as conn:
                conn.execute(
                    "INSERT INTO users(username, password) VALUES (?, ?)",
                    (username, hashed)
                )
                conn.commit()
            return redirect("/login")
        except sqlite3.IntegrityError:
            flash("Benutzername existiert bereits.")
            
    return render_template("register.html")

# Login mit Brute-Force Schutz & Logging [cite: 21, 28, 40]
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        success = 0
        
        with get_db() as conn:
            # Sicherheitscheck: Fehlversuche der letzten 5 Min [cite: 21]
            zeit_limit = (datetime.datetime.now() - datetime.timedelta(minutes=5)).strftime("%Y-%m-%d %H:%M:%S")
            fehlversuche = conn.execute("""
                SELECT COUNT(*) FROM logins 
                WHERE username = ? AND success = 0 AND time > ?
            """, (username, zeit_limit)).fetchone()[0]

            if fehlversuche >= 5:
                flash("Konto temporär gesperrt (Brute-Force Schutz).") # [cite: 21]
                return render_template("login.html")

            # Authentifizierung [cite: 38]
            user = conn.execute("SELECT password FROM users WHERE username=?", (username,)).fetchone()

            if user and bcrypt.checkpw(password.encode('utf-8'), user['password']):
                session["user"] = username
                success = 1

            # Protokollierung für Sicherheitsanalyse [cite: 40]
            conn.execute(
                "INSERT INTO logins(username, time, success) VALUES (?, ?, ?)",
                (username, datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), success)
            )
            conn.commit()

        if success:
            return redirect("/dashboard")
        else:
            flash("Ungültige Zugangsdaten.")

    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")

@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect("/login")

    with get_db() as conn:
        # Daten für die Visualisierung von Sicherheitsereignissen [cite: 41]
        logs = conn.execute("SELECT * FROM logins ORDER BY time DESC").fetchall()

    return render_template("dashboard.html", logs=logs)

if __name__ == "__main__":
    app.run(debug=True)