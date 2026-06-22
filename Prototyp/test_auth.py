import unittest
import sqlite3
import bcrypt
from app import app, get_db
import os

class AuthenticationSystemTests(unittest.TestCase):

    def setUp(self):
        
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False
        
        # Bestimme den absoluten Pfad zum Prototyp-Ordner, genau wie in app.py
        BASE_DIR = os.path.dirname(os.path.abspath(__file__))
        TEST_DB_PATH = os.path.join(BASE_DIR, 'database.db')
        
        # Setze den absoluten Pfad für die Test-Datenbank
        app.config['DATABASE'] = TEST_DB_PATH 
        
        self.client = app.test_client()
        
        # NEU: Wir öffnen den App-Kontext, damit 'g' in get_db() fehlerfrei funktioniert
        with app.app_context():
            with get_db() as conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        email TEXT UNIQUE NOT NULL,
                        password TEXT NOT NULL
                    )
                """)
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS logins (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        email TEXT NOT NULL,
                        success INTEGER NOT NULL,
                        time TEXT NOT NULL
                    )
                """)
                conn.commit()
                
                # Tabellen leeren für saubere Testbedingungen
                conn.execute("DELETE FROM users")
                conn.execute("DELETE FROM logins")
                
                # Test-Benutzer einspeisen
                password_hash = bcrypt.hashpw("Falonnediane1.".encode('utf-8'), bcrypt.gensalt())
                conn.execute("INSERT INTO users (email, password) VALUES (?, ?)", 
                             ("falonnedianesimo@gmail.com", password_hash))
                conn.commit()

    def test_01_successful_login_redirects_to_mfa(self):
        """
        POSITIVTEST: Überprüfung, ob korrekte Daten zur MFA-Prüfung führen.
        """
        response = self.client.post('/login', data={
            'email': 'falonnedianesimo@gmail.com',
            'password': 'Falonnediane1.'
        }, follow_redirects=True)
        
        self.assertIn(b'2-Faktor-Authentifizierung', response.data)

    def test_02_invalid_login_logs_attempt(self):
        """
        NEGATIVTEST: Überprüfung der Protokollierung in der Datenbank bei falschem Passwort.
        """
        self.client.post('/login', data={
            'email': 'falonnedianesimo@gmail.com',
            'password': 'FalschesPasswort'
        })
        
        # Auch hier den Kontext hinzufügen, um 'g' nutzen zu können
        with app.app_context():
            with get_db() as conn:
                log = conn.execute("SELECT success FROM logins WHERE email='falonnedianesimo@gmail.com'").fetchone()
                self.assertIsNotNone(log)
                self.assertEqual(log['success'], 0)

    def test_03_brute_force_warning_stage(self):
        """
        NEGATIVTEST: Überprüfung der stufenweisen Warnmeldung beim 4. Fehlversuch.
        """
        for _ in range(3):
            self.client.post('/login', data={'email': 'falonnedianesimo@gmail.com', 'password': 'Wrong'})
            
        response = self.client.post('/login', data={
            'email': 'falonnedianesimo@gmail.com', 
            'password': 'Wrong'
        }, follow_redirects=True)
        
        self.assertIn(b'bevor das Konto gesperrt wird!', response.data)

    def test_04_account_lockout_after_5_failures(self):
        """
        NEGATIVTEST: Überprüfung der Sperrmeldung nach dem 5. Fehlversuch.
        """
        for _ in range(5):
            self.client.post('/login', data={'email': 'falonnedianesimo@gmail.com', 'password': 'Wrong'})
            
        response = self.client.post('/login', data={
            'email': 'falonnedianesimo@gmail.com', 
            'password': 'Falonnediane1.'
        }, follow_redirects=True)
        
        self.assertIn(b'Konto wegen zu vieler Versuche gesperrt.', response.data)

if __name__ == '__main__':
    unittest.main()