import csv
import io
import json
import os
import secrets
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from dotenv import load_dotenv
from flask import Flask, Response, abort, flash, redirect, render_template, request, send_from_directory, url_for
from flask_login import LoginManager, current_user, login_user, logout_user

from models import User, db
from scanner import scan_url

load_dotenv()

app = Flask(__name__)
app.config['HISTORY_DB'] = str(Path(app.instance_path) / 'history.sqlite3')
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY') or secrets.token_hex(32)
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('USERS_DB_URI', 'sqlite:///users.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
if not os.getenv('SECRET_KEY'):
    app.logger.warning('SECRET_KEY is not set; sessions will reset on every restart.')

db.init_app(app)
with app.app_context():
    db.create_all()

login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to use the scanner.'

# Endpoints reachable without a session. Everything else requires login, so a
# newly added route is protected by default instead of depending on a decorator.
PUBLIC_ENDPOINTS = {'login', 'register', 'css', 'static'}


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


@app.before_request
def require_login():
    if app.config.get('LOGIN_DISABLED') or request.endpoint in PUBLIC_ENDPOINTS:
        return None
    if request.endpoint is None or current_user.is_authenticated:
        return None  # unknown URLs fall through to the normal 404
    return login_manager.unauthorized()


def safe_next(target):
    """Only follow same-site relative paths after login (no open redirect)."""
    if target and target.startswith('/') and not target.startswith('//') and '\\' not in target:
        return target
    return url_for('index')


@contextmanager
def history_connection():
    path = Path(app.config['HISTORY_DB'])
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path, timeout=5)
    try:
        connection.row_factory = sqlite3.Row
        with connection:
            connection.execute('''CREATE TABLE IF NOT EXISTS scans
                (id TEXT PRIMARY KEY, url TEXT NOT NULL, created_at TEXT NOT NULL,
                 result TEXT NOT NULL)''')
            yield connection
    finally:
        connection.close()


def load_scan(scan_id):
    with history_connection() as connection:
        row = connection.execute('SELECT * FROM scans WHERE id = ?', (scan_id,)).fetchone()
    if row is None:
        abort(404)
    return dict(row)


def render_workspace(result=None, url='', scan=None, notice=None):
    history = []
    try:
        with history_connection() as connection:
            rows = connection.execute('SELECT * FROM scans ORDER BY created_at DESC LIMIT 20').fetchall()
        history = [dict(row, result=json.loads(row['result'])) for row in rows]
    except (sqlite3.Error, OSError):
        app.logger.warning('Scan history is unavailable', exc_info=True)
        notice = notice or 'History is unavailable. You can still scan URLs.'
    return render_template('index.html', result=result, url=url, scan=scan,
                           history=history, notice=notice)


@app.route("/css/<path:filename>")
def css(filename):
    return send_from_directory("templates/css", filename)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        if not username or not password:
            flash('Username and password are required.')
        elif len(username) > 64:
            flash('Username must be 64 characters or fewer.')
        elif password != request.form.get('confirm', ''):
            flash('Passwords do not match.')
        elif len(password) < 8:
            flash('Password must be at least 8 characters.')
        elif User.query.filter_by(username=username).first():
            flash('Username already taken.')
        else:
            user = User(username=username)
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            flash('Account created. Please log in.')
            return redirect(url_for('login'))
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(request.form.get('password', '')):
            login_user(user)
            return redirect(safe_next(request.args.get('next')))
        flash('Invalid username or password.')
    return render_template('login.html')


@app.post('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    url = ""
    if request.method == "POST":
        url = request.form.get("url", "").strip()
        if url:
            result = scan_url(url)
            if 'error' not in result:
                scan_id = uuid4().hex
                try:
                    with history_connection() as connection:
                        connection.execute('INSERT INTO scans VALUES (?, ?, ?, ?)',
                            (scan_id, url, datetime.now(timezone.utc).isoformat(timespec='microseconds'),
                             json.dumps(result)))
                except (sqlite3.Error, OSError):
                    app.logger.warning('Could not save scan', exc_info=True)
                    return render_workspace(result, url, notice='Your analysis completed, but could not be saved to history.')
                return redirect(url_for('report', scan_id=scan_id), code=303)
    return render_workspace(result, url)


@app.get('/reports/<scan_id>')
def report(scan_id):
    try:
        scan = load_scan(scan_id)
    except (sqlite3.Error, OSError):
        return render_workspace(notice='Saved reports are temporarily unavailable.'), 503
    return render_workspace(json.loads(scan['result']), scan['url'], scan)


@app.get('/reports/<scan_id>/export/<format>')
def export_report(scan_id, format):
    if format not in ('json', 'csv'):
        abort(404)
    try:
        scan = load_scan(scan_id)
    except (sqlite3.Error, OSError):
        abort(503)
    result = json.loads(scan['result'])
    if format == 'json':
        content = json.dumps(dict(id=scan['id'], url=scan['url'],
            scanned_at=scan['created_at'], result=result), indent=2)
        mimetype = 'application/json'
    else:
        output = io.StringIO(newline='')
        writer = csv.writer(output)
        writer.writerow(['id', 'url', 'scanned_at_utc', 'heuristic_score', 'heuristic_risk',
                         'malicious', 'suspicious', 'harmless', 'undetected', 'signals'])
        # Prevent spreadsheet formula execution in text originating from scanned URLs.
        def csv_text(value):
            text = str(value)
            return "'" + text if text.lstrip().startswith(('=', '+', '-', '@')) or text.startswith(('\t', '\r', '\n')) else text
        writer.writerow([scan['id'], csv_text(scan['url']), scan['created_at'],
            result['score'], csv_text(result['risk']),
            *[result['stats'].get(key, 0) for key in ('malicious', 'suspicious', 'harmless', 'undetected')],
            csv_text('; '.join(f'{text} (+{points})' for text, points in result.get('reasons', [])))])
        content, mimetype = output.getvalue(), 'text/csv'
    return Response(content, mimetype=mimetype, headers={
        'Content-Disposition': f'attachment; filename="threatlens-{scan_id}.{format}"',
        'Cache-Control': 'no-store',
    })


if __name__ == "__main__":
    app.run(debug=True, port=5000)
