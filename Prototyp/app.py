from flask import Flask, render_template, request, redirect, session, flash, g
import sqlite3
import bcrypt
import datetime
import random
import re
from datetime import timedelta
import os


app = Flask(__name__, static_url_path='/static')
app.secret_key = "secretkey"
# Die Session ist permanent, damit das Timeout greift
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=10)

@app.before_request
def make_session_permanent():
    session.permanent = True
    # Aktualisiert den Zeitstempel bei jeder Interaktion

# Datenbank-Verbindung mit Row-Factory für Namenszugriff (Behebt TypeError)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# 2. Verbinde diesen Ordner fest mit dem Dateinamen
app.config['DATABASE'] = os.path.join(BASE_DIR, 'database.db')

from flask import Flask, render_template, request, redirect, session, flash, g  # <-- g importieren

# ... (Rest deines Codes bleibt gleich)

def get_db():
    """Nutzt das Flask g-Objekt, um eine einzige Verbindung pro Request zu halten."""
    if 'db' not in g:
        db_path = app.config.get('DATABASE')
        g.db = sqlite3.connect(db_path)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(exception):
    """Schließt die Verbindung am Ende des Requests/Tests sauber."""
    db = g.pop('db', None)
    if db is not None:
        db.close()


def ist_passwort_stark(password):
    if len(password) < 8:
        return False, "Passwort muss mindestens 8 Zeichen lang sein."
    if not re.search(r"[A-Z]", password):
        return False, "Passwort muss mindestens einen Großbuchstaben enthalten."
    if not re.search(r"[0-9]", password):
        return False, "Passwort muss mindestens eine Zahl enthalten."
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False, "Passwort muss mindestens ein Sonderzeichen enthalten."
    return True, ""

@app.route("/")
def home():
    return redirect("/login")

# Registrierung mit Hashing [cite: 37]
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")
        stark, nachricht = ist_passwort_stark(password)
        if not stark:
            flash(nachricht)
            return render_template("register.html")
        hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        try:
            with get_db() as conn:
                conn.execute(
                    "INSERT INTO users(email, password) VALUES (?, ?)",
                
                    (email, hashed)
                )
                conn.commit()
                flash("Registrierung erfolgreich! Bitte einloggen.")
            return redirect("/login")
        except sqlite3.IntegrityError:
            # Wird ausgelöst, wenn 'UNIQUE' verletzt wird
            flash("Diese E-Mail-Adresse existiert bereits!")
            
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
            else:
                # Fehlgeschlagener Versuch (falsches Passwort)
                conn.execute("INSERT INTO logins(email, time, success) VALUES (?, ?, ?)",
                             (email, datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), 0))
                conn.commit()
                # NEU: Warnung beim 4. Versuch (da der aktuelle 5. gerade gespeichert wurde)
                aktuelle_fehler = fehlversuche + 1
                if aktuelle_fehler == 4:
                    flash("ACHTUNG: Dies ist Ihr vorletzter Versuch, bevor das Konto gesperrt wird!")

                elif aktuelle_fehler == 5:
                    flash("Letzter Versuch fehlgeschlagen. Konto für 5 Minuten gesperrt.")
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
        # Wir holen alle relevanten Spalten für die Analyse [cite: 40]
        logs = conn.execute("SELECT email, time, success FROM logins ORDER BY time DESC").fetchall()

    total_seconds = app.config['PERMANENT_SESSION_LIFETIME'].total_seconds()
    return render_template("dashboard.html", logs=logs, timeout=total_seconds)

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
        
        # --- Passwort-Stärke-Prüfung ---
        # Mindestens 8 Zeichen, 1 Großbuchstabe, 1 Zahl, 1 Sonderzeichen
        if len(new_password) < 8:
            flash("Passwort muss mindestens 8 Zeichen lang sein.")
            return render_template("set_new_password.html")
        
        if not re.search(r"[A-Z]", new_password):
            flash("Passwort muss mindestens einen Großbuchstaben enthalten.")
            return render_template("set_new_password.html")
            
        if not re.search(r"[0-9]", new_password):
            flash("Passwort muss mindestens eine Zahl enthalten.")
            return render_template("set_new_password.html")

        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", new_password):
            flash("Passwort muss mindestens ein Sonderzeichen enthalten.")
            return render_template("set_new_password.html")
       

        hashed = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())

        with get_db() as conn:
            result = conn.execute("UPDATE users SET password = ? WHERE email = ?", (hashed, email))
            conn.commit()
            print(f"DEBUG: Betroffene Zeilen: {result.rowcount}") # Muss 1 sein!
        
        session.pop("reset_email")
        flash("Passwort erfolgreich geändert! Du kannst dich jetzt einloggen.")
        return redirect("/login")

    return render_template("set_new_password.html")


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

# Erstellt einen temporären Kontext, damit g während init_db() verfügbar ist
with app.app_context():
    init_db()

if __name__ == "__main__":
    app.run(debug=True)
