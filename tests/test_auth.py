import os
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault('USERS_DB_URI', 'sqlite:///:memory:')

from app import app, db  # noqa: E402


class AuthTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.old_db = app.config['HISTORY_DB']
        self.old_login_disabled = app.config.get('LOGIN_DISABLED')
        app.config['HISTORY_DB'] = str(Path(self.temp.name) / 'history.sqlite3')
        app.config['LOGIN_DISABLED'] = False
        with app.app_context():
            db.drop_all()
            db.create_all()
        self.client = app.test_client()

    def tearDown(self):
        app.config['HISTORY_DB'] = self.old_db
        app.config['LOGIN_DISABLED'] = self.old_login_disabled
        self.temp.cleanup()

    def register(self, username='analyst', password='correct-horse'):
        return self.client.post('/register', data=dict(
            username=username, password=password, confirm=password))

    def login(self, username='analyst', password='correct-horse', next_page=None):
        path = '/login' + (f'?next={next_page}' if next_page else '')
        return self.client.post(path, data=dict(username=username, password=password))

    def test_every_app_route_requires_login(self):
        for path in ('/', '/reports/abc', '/reports/abc/export/json'):
            response = self.client.get(path)
            self.assertEqual(response.status_code, 302, path)
            self.assertIn('/login', response.headers['Location'], path)
        self.assertEqual(self.client.post('/', data={'url': 'https://example.com'}).status_code, 302)

    def test_public_pages_stay_reachable(self):
        self.assertEqual(self.client.get('/login').status_code, 200)
        self.assertEqual(self.client.get('/register').status_code, 200)
        self.assertEqual(self.client.get('/css/index.css').status_code, 200)

    def test_register_login_logout(self):
        self.assertEqual(self.register().headers['Location'], '/login')
        self.assertEqual(self.login().headers['Location'], '/')
        page = self.client.get('/')
        self.assertEqual(page.status_code, 200)
        self.assertIn(b'analyst', page.data)
        self.assertEqual(self.client.get('/login').status_code, 302)
        self.assertEqual(self.client.post('/logout').headers['Location'], '/login')
        self.assertEqual(self.client.get('/').status_code, 302)

    def test_bad_credentials_are_rejected(self):
        self.register()
        self.assertIn(b'Invalid username or password', self.login(password='wrong-password').data)
        self.assertIn(b'Invalid username or password', self.login(username='nobody').data)
        self.assertEqual(self.client.get('/').status_code, 302)

    def test_registration_validation(self):
        self.assertIn(b'at least 8 characters', self.register(password='short').data)
        self.assertIn(b'do not match', self.client.post('/register', data=dict(
            username='analyst', password='correct-horse', confirm='different-horse')).data)
        self.register()
        self.assertIn(b'already taken', self.register().data)

    def test_next_only_follows_local_paths(self):
        self.register()
        self.assertEqual(self.login(next_page='/reports/abc').headers['Location'], '/reports/abc')
        for target in ('https://evil.example', '//evil.example', '/%5Cevil.example'):
            self.client.post('/logout')
            self.assertEqual(self.login(next_page=target).headers['Location'], '/', target)

    def test_passwords_are_stored_hashed(self):
        self.register()
        with app.app_context():
            stored = db.session.execute(db.text('SELECT password_hash FROM user')).scalar_one()
        self.assertNotIn('correct-horse', stored)


if __name__ == '__main__':
    unittest.main()
