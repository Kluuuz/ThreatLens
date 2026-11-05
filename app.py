import csv
import io
import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from flask import Flask, Response, abort, redirect, render_template, request, send_from_directory, url_for

from scanner import scan_url

app = Flask(__name__)
app.config['HISTORY_DB'] = str(Path(app.instance_path) / 'history.sqlite3')


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
