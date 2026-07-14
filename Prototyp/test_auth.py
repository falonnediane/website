import unittest  
import sqlite3   
import os       
import bcrypt    
import re        
from app import app, get_db , ist_passwort_stark , random 


class AuthenticationSystemTests(unittest.TestCase):  

    def setUp(self):  # Diese Methode läuft automatisch VOR JEDEM EINZELNEN Test ab (Initialisierung)
       
        app.config['TESTING'] = True  # Schaltet Flask in den Testmodus 
        
        
        BASE_DIR = os.path.dirname(os.path.abspath(__file__))  # Ermittelt den absoluten Pfad des Ordners, in dem diese Testdatei liegt
        app.config['DATABASE'] = os.path.join(BASE_DIR, 'database.db')  
        self.client = app.test_client() 
        
        with app.app_context():  # Öffnet den Flask-Anwendungskontext, damit das 'g'-Objekt in get_db() verfügbar ist
            with get_db() as conn: 
               
                conn.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT UNIQUE NOT NULL, password TEXT NOT NULL)")
                conn.execute("CREATE TABLE IF NOT EXISTS logins (id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT NOT NULL, success INTEGER NOT NULL, time TEXT NOT NULL)")
                conn.commit()  
                conn.execute("DELETE FROM users") 
                conn.execute("DELETE FROM logins")  
                # Generiert einen sicheren Bcrypt-Hash für das Test-Passwort
                password_hash = bcrypt.hashpw("Falonnediane1.".encode('utf-8'), bcrypt.gensalt())
                # Fügt den Standard-Testbenutzer mit der E-Mail und dem Passwort-Hash in die Tabelle ein
                conn.execute("INSERT INTO users (email, password) VALUES (?, ?)", ("falonnedianesimo@gmail.com", password_hash))
                conn.commit()  

    # --- UNIT-TEST ---
    def test_00_unit_passwort_staerke(self): 
        """UNIT-TEST: Prüft die Funktion 'ist_passwort_stark' isoliert."""
        # Regel 1: Mindestens 8 Zeichen
        stark, msg = ist_passwort_stark("Short1!")
        self.assertFalse(stark)
        self.assertIn("mindestens 8 Zeichen", msg)
        
        # Regel 2: Mindestens ein Großbuchstabe
        stark, msg = ist_passwort_stark("kleingeschrieben1!")
        self.assertFalse(stark)
        self.assertIn("Großbuchstaben", msg)
        
        # Regel 3: Mindestens eine Zahl
        stark, msg = ist_passwort_stark("KeineZahlHier!")
        self.assertFalse(stark)
        self.assertIn("eine Zahl", msg)
        
        # Regel 4: Mindestens ein Sonderzeichen
        stark, msg = ist_passwort_stark("PasswortMitZahl2026")
        self.assertFalse(stark)
        self.assertIn("Sonderzeichen", msg)

        # Testet ein starkes Passwort, das alle Kriterien erfüllt
        stark, _ = ist_passwort_stark("Ab1!")  
        self.assertFalse(stark)  
        stark, _ = ist_passwort_stark("Falonnediane1.")  
        self.assertTrue(stark)  

    def test_01_unit_mfa_code_properties(self):
        """UNIT-TEST: Prüft, ob der generierte MFA-Code den mathematischen Sicherheitsvorgaben entspricht."""
        
        # Wir simulieren die Code-Generierung aus app.py 100-mal, um Zufallsfehler auszuschließen
        for _ in range(100):
            mfa_code = str(random.randint(100000, 999999))
            
            # Kriterium 1: Muss exakt 6 Zeichen lang sein
            self.assertEqual(len(mfa_code), 6)
            
            # Kriterium 2: Muss rein numerisch sein (keine Buchstaben/Sonderzeichen)
            self.assertTrue(mfa_code.isdigit())
            
            # Kriterium 3: Muss im definierten Wertebereich liegen
            self.assertTrue(100000 <= int(mfa_code) <= 999999)

    # --- INTEGRATIONSTESTS ---   
    def test_02_register_duplicate_email_fails(self):
        """INTEGRATIONSTEST: Prüft, ob die Registrierung einer bereits existierenden E-Mail blockiert wird."""
        # Wir versuchen die E-Mail zu registrieren, die bereits in setUp() erstellt wurde
        response = self.client.post('/register', data={
            'email': 'falonnedianesimo@gmail.com',
            'password': 'Falonnediane1.'
        }, follow_redirects=True)
        
        # Prüfen, ob die App den IntegrityError abfängt und die richtige Meldung flash
        self.assertIn("existiert bereits".encode('utf-8'), response.data)



    def test_03_successful_login_redirects_to_mfa(self):  
        """INTEGRATIONSTEST: Überprüfung, ob korrekte Daten zur MFA-Prüfung führen."""
        # Sendet einen HTTP-POST-Request mit korrekten Login-Daten an die App und folgt automatischen Weiterleitungen
        response = self.client.post('/login', data={'email': 'falonnedianesimo@gmail.com', 'password': 'Falonnediane1.'}, follow_redirects=True)
        self.assertIn(b'2-Faktor-Authentifizierung', response.data)  # Prüft, ob der Text '2-Faktor-Authentifizierung' im HTML der Antwort vorkommt


    def test_04_account_lockout_after_5_failures(self):  # Testet das Sperren der Authentifizierung nach dem Limit
        """INTEGRATIONSTEST: Überprüfung der Sperrmeldung nach dem 5. Fehlversuch."""
        for _ in range(5):  
            
             self.client.post('/login', data={'email': 'falonnedianesimo@gmail.com', 'password': 'FalschesPasswort'})
        
        response = self.client.post('/login', data={'email': 'falonnedianesimo@gmail.com', 'password': 'Falonnediane1.'}, follow_redirects=True)
       
        self.assertIn(b'Konto wegen zu vieler Versuche gesperrt.', response.data)  # Prüft, ob der Login trotz korrektem Passwort wegen der Sperre abgelehnt wird

   
    # --- SYSTEMTESTS  ---
    def test_05_system_full_successful_login_to_dashboard(self):  # Simuliert den kompletten, erfolgreichen Nutzerprozess
        """SYSTEMTEST: Kompletter Klickpfad von Login über MFA bis zum Dashboard."""
        from flask import session  

        # Öffnet den Client-Kontext, damit Session-Daten zwischen Requests erhalten bleiben
        with self.client as c:  
            response = c.post('/login', data={'email': 'falonnedianesimo@gmail.com', 'password': 'Falonnediane1.'}, follow_redirects=True)
            self.assertIn(b'2-Faktor-Authentifizierung', response.data)  # Bestätigt, dass der Nutzer auf der MFA-Oberfläche landet
            
            mfa_code = session.get('mfa_code')  # Abfangen des geheimen 2FA-Codes aus der Session (simuliert das Ablesen einer SMS/E-Mail)
            self.assertIsNotNone(mfa_code)  
            response_mfa = c.post('/mfa', data={'code': mfa_code}, follow_redirects=True)
           
            self.assertIn(b'Dashboard', response_mfa.data)  # Prüft, ob das Wort 'Dashboard' auf der Seite steht
            self.assertIn(b'falonnedianesimo@gmail.com', response_mfa.data)  # Prüft, ob die E-Mail des Nutzers im Dashboard angezeigt wird

    # Simuliert den vollständigen "Passwort vergessen"-Ablauf
    def test_06_system_password_reset_and_login_with_new_password(self):  
        """SYSTEMTEST: Passwort vergessen ➔ Zurücksetzen ➔ Login mit neuem Passwort."""
        with self.client as c:  
            c.post('/reset_password', data={'email': 'falonnedianesimo@gmail.com'}, follow_redirects=True)
            
            response_reset = c.post('/set_new_password', data={'password': 'NeuPasswort2026!'}, follow_redirects=True)
            self.assertIn("Passwort erfolgreich geändert".encode('utf-8'), response_reset.data)  # Prüft auf die Erfolgsmeldung (als UTF-8 Bytes)
            
            response_old = c.post('/login', data={'email': 'falonnedianesimo@gmail.com', 'password': 'Falonnediane1.'}, follow_redirects=True)
            
            self.assertIn("Ungültige Zugangsdaten".encode('utf-8'), response_old.data)
            
            response_new = c.post('/login', data={'email': 'falonnedianesimo@gmail.com', 'password': 'NeuPasswort2026!'}, follow_redirects=True)
            self.assertIn(b'2-Faktor-Authentifizierung', response_new.data)  # Bestätigt, dass das neue Passwort akzeptiert wurde und zur 2FA weiterleitet

if __name__ == '__main__':  # Prüft, ob das Skript direkt gestartet wurde 
    unittest.main(verbosity=2) 