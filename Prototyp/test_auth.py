import unittest  
import sqlite3   
import os       
import bcrypt    
import re        
from app import app, get_db  

class AuthenticationSystemTests(unittest.TestCase):  # Erstellt die Testklasse, die von unittest.TestCase erbt

    def setUp(self):  # Diese Methode läuft automatisch VOR JEDEM EINZELNEN Test ab (Initialisierung)
       
        app.config['TESTING'] = True  # Schaltet Flask in den Testmodus (Fehler werden direkt im Terminal angezeigt)
        app.config['WTF_CSRF_ENABLED'] = False 
        
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
                conn.commit()  # Bestätigt und speichert den neuen Testbenutzer

    # --- UNIT-TEST ---
    def test_00_unit_passwort_staerke(self): 
        """UNIT-TEST: Prüft die Funktion 'ist_passwort_stark' isoliert."""
        from app import ist_passwort_stark  
        stark, _ = ist_passwort_stark("Ab1!")  
        self.assertFalse(stark)  
        stark, _ = ist_passwort_stark("Falonnediane1.")  
        self.assertTrue(stark)  

    # --- INTEGRATIONSTESTS ---
    def test_01_successful_login_redirects_to_mfa(self):  
        """INTEGRATIONSTEST: Überprüfung, ob korrekte Daten zur MFA-Prüfung führen."""
        # Sendet einen HTTP-POST-Request mit korrekten Login-Daten an die App und folgt automatischen Weiterleitungen
        response = self.client.post('/login', data={'email': 'falonnedianesimo@gmail.com', 'password': 'Falonnediane1.'}, follow_redirects=True)
        self.assertIn(b'2-Faktor-Authentifizierung', response.data)  # Prüft, ob der Text '2-Faktor-Authentifizierung' im HTML der Antwort vorkommt


    def test_02_account_lockout_after_5_failures(self):  # Testet das Sperren der Authentifizierung nach dem Limit
        """INTEGRATIONSTEST: Überprüfung der Sperrmeldung nach dem 5. Fehlversuch."""
        for _ in range(5):  
            
             self.client.post('/login', data={'email': 'falonnedianesimo@gmail.com', 'password': 'FalschesPasswort'})
        
        response = self.client.post('/login', data={'email': 'falonnedianesimo@gmail.com', 'password': 'Falonnediane1.'}, follow_redirects=True)
       
        self.assertIn(b'Konto wegen zu vieler Versuche gesperrt.', response.data)  # Prüft, ob der Login trotz korrektem Passwort wegen der Sperre abgelehnt wird

    # --- SYSTEMTESTS (END-TO-END) ---
    def test_03_system_full_successful_login_to_dashboard(self):  # Simuliert den kompletten, erfolgreichen Nutzerprozess
        """SYSTEMTEST: Kompletter Klickpfad von Login über MFA bis zum Dashboard."""
        from flask import session  # Importiert das Flask-Session-Modul, um Sitzungsdaten während des Testverlaufs auszulesen
        
        with self.client as c:  # Öffnet den Client-Kontext, damit Session-Daten zwischen Requests erhalten bleiben
            response = c.post('/login', data={'email': 'falonnedianesimo@gmail.com', 'password': 'Falonnediane1.'}, follow_redirects=True)
            self.assertIn(b'2-Faktor-Authentifizierung', response.data)  # Bestätigt, dass der Nutzer auf der MFA-Oberfläche landet
            
            mfa_code = session.get('mfa_code')  # Abfangen des geheimen 2FA-Codes aus der Session (simuliert das Ablesen einer SMS/E-Mail)
            self.assertIsNotNone(mfa_code)  # Prüft, ob überhaupt ein Code generiert und in der Session abgelegt wurde
            response_mfa = c.post('/mfa', data={'code': mfa_code}, follow_redirects=True)
           
           
            self.assertIn(b'Dashboard', response_mfa.data)  # Prüft, ob das Wort 'Dashboard' auf der Seite steht
            self.assertIn(b'falonnedianesimo@gmail.com', response_mfa.data)  # Prüft, ob die E-Mail des Nutzers im Dashboard angezeigt wird

    def test_04_system_password_reset_and_login_with_new_password(self):  # Simuliert den vollständigen "Passwort vergessen"-Ablauf
        """SYSTEMTEST: Passwort vergessen ➔ Zurücksetzen ➔ Login mit neuem Passwort."""
        with self.client as c:  # Öffnet den Client-Kontext, um den Zustand über mehrere Schritte hinweg zu speichern
            c.post('/reset_password', data={'email': 'falonnedianesimo@gmail.com'}, follow_redirects=True)
            
            response_reset = c.post('/set_new_password', data={'password': 'NeuPasswort2026!'}, follow_redirects=True)
            self.assertIn("Passwort erfolgreich geändert".encode('utf-8'), response_reset.data)  # Prüft auf die Erfolgsmeldung (als UTF-8 Bytes)
            
            response_old = c.post('/login', data={'email': 'falonnedianesimo@gmail.com', 'password': 'Falonnediane1.'}, follow_redirects=True)
            
            self.assertIn("Ungültige Zugangsdaten".encode('utf-8'), response_old.data)
            
            response_new = c.post('/login', data={'email': 'falonnedianesimo@gmail.com', 'password': 'NeuPasswort2026!'}, follow_redirects=True)
            self.assertIn(b'2-Faktor-Authentifizierung', response_new.data)  # Bestätigt, dass das neue Passwort akzeptiert wurde und zur 2FA weiterleitet

if __name__ == '__main__':  # Prüft, ob das Skript direkt gestartet wurde 
    unittest.main(verbosity=2) 