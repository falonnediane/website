from flask import Flask, render_template, request, redirect, session, flash
import sqlite3
import bcrypt
import datetime
import random

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
            email TEXT UNIQUE,  -- E-Mail muss eindeutig sein [cite: 21]
            password TEXT
        )
        """)
        conn.execute("""
        CREATE TABLE IF NOT EXISTS logins(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT,
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
        email = request.form.get("email")
        password = request.form.get("password")
        hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        try:
            with get_db() as conn:
                conn.execute(
                    "INSERT INTO users(email, password) VALUES (?, ?)",
                
                    (email, hashed)
                )
                conn.commit()
            return redirect("/login")
        except sqlite3.IntegrityError:
            # Wird ausgelöst, wenn 'UNIQUE' verletzt wird
            flash("Dieser Benutzername existiert bereits!")
            
    return render_template("register.html")

# Login mit Brute-Force Schutz & Logging [cite: 21, 28, 40]
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")
        
        with get_db() as conn:
            # Brute-Force Schutz prüfen [cite: 21, 27]
            zeit_limit = (datetime.datetime.now() - datetime.timedelta(minutes=5)).strftime("%Y-%m-%d %H:%M:%S")
            fehlversuche = conn.execute("SELECT COUNT(*) FROM logins WHERE email = ? AND success = 0 AND time > ?", (email, zeit_limit)).fetchone()[0]

            if fehlversuche >= 5:
                flash("Konto wegen zu vieler Versuche gesperrt.") 
                return render_template("login.html")

            user = conn.execute("SELECT password FROM users WHERE email=?", (email,)).fetchone()

            if user and bcrypt.checkpw(password.encode('utf-8'), user['password']):
                # Passwort korrekt -> MFA starten
                mfa_code = str(random.randint(100000, 999999))
                session["mfa_email"] = email
                session["mfa_code"] = mfa_code
                print(f"--- MFA-CODE: {mfa_code} ---")
                return redirect("/mfa")
            
            # Fehlgeschlagener Versuch (falsches Passwort)
            conn.execute("INSERT INTO logins(email, time, success) VALUES (?, ?, ?)",
                         (email, datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), 0))
            conn.commit()
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
        # Wir holen alle relevanten Spalten für die Analyse [cite: 40]
        logs = conn.execute("SELECT email, time, success FROM logins ORDER BY time DESC").fetchall()

    return render_template("dashboard.html", logs=logs)

@app.route("/mfa", methods=["GET", "POST"])
def mfa():
    if "mfa_email" not in session:
        return redirect("/login")
        
    if request.method == "POST":
        eingabe = request.form.get("code")
        email = session.get("mfa_email")

        if eingabe == session.get("mfa_code"):
            # Erfolg: Log schreiben und einloggen
            with get_db() as conn:
                conn.execute("INSERT INTO logins(email, time, success) VALUES (?, ?, ?)",
                             (email, datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), 1))
                conn.commit()
            session["user"] = session.pop("mfa_email")
            session.pop("mfa_code")
            return redirect("/dashboard")
        else:
            # FEHLER: Hier wird die Nachricht für die MFA-Seite erstellt
            flash("Falscher MFA-Code! Bitte erneut versuchen.") 
            # Wir bleiben auf der MFA-Seite
            
    return render_template("mfa.html")

# Schritt 1: E-Mail eingeben (hast du schon fast fertig)
@app.route("/reset_password", methods=["GET", "POST"])
def reset_password():
    if request.method == "POST":
        email = request.form.get("email")
        # In der Realität würde man hier prüfen, ob der User existiert
        # Für den Prototyp leiten wir direkt zur Eingabe des NEUEN Passworts weiter
        session["reset_email"] = email 
        return redirect("/set_new_password")
    return render_template("reset_password.html")

# Schritt 2: Das NEUE Passwort tatsächlich speichern
@app.route("/set_new_password", methods=["GET", "POST"])
def set_new_password():
    if "reset_email" not in session:
        return redirect("/login")

    if request.method == "POST":
        new_password = request.form.get("password")
        email = session.get("reset_email")
        
        print(f"DEBUG: Passwort-Reset für {email} gestartet...") # Prüfen, ob Email da ist
        
        hashed = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())

        with get_db() as conn:
            result = conn.execute("UPDATE users SET password = ? WHERE email = ?", (hashed, email))
            conn.commit()
            print(f"DEBUG: Betroffene Zeilen: {result.rowcount}") # Muss 1 sein!
        
        session.pop("reset_email")
        flash("Passwort erfolgreich geändert! Du kannst dich jetzt einloggen.")
        return redirect("/login")

    return render_template("set_new_password.html")

if __name__ == "__main__":
    app.run(debug=True)
