import csv
import io
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app import app


class HistoryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.old_db = app.config['HISTORY_DB']
        app.config['HISTORY_DB'] = str(Path(self.temp.name) / 'history.sqlite3')
        self.client = app.test_client()
        self.result = dict(score=45, risk='MEDIUM RISK (Suspicious)',
            stats=dict(malicious=2, suspicious=1, harmless=70, undetected=10),
            reasons=[['Keyword, with comma', 10]])

    def tearDown(self):
        app.config['HISTORY_DB'] = self.old_db
        self.temp.cleanup()

    def save(self, url='https://example.com'):
        with patch('app.scan_url', return_value=self.result) as scanner:
            response = self.client.post('/', data={'url': url})
            scanner.assert_called_once_with(url)
        self.assertEqual(response.status_code, 303)
        return response.headers['Location']

    def test_save_reopen_and_exports_without_rescanning(self):
        self.assertEqual(self.client.get('/').status_code, 200)
        location = self.save()
        with patch('app.scan_url', side_effect=AssertionError('Must not rescan')):
            page = self.client.get(location)
            self.assertEqual(page.status_code, 200)
            self.assertIn(b'https://example.com', page.data)
            self.assertIn(b'action="/"', page.data)
            download = self.client.get(location + '/export/json')
            self.assertIn('attachment;', download.headers['Content-Disposition'])
            self.assertEqual(download.json['result'], self.result)
            rows = list(csv.reader(io.StringIO(self.client.get(location + '/export/csv').text)))
            self.assertEqual(rows[1][1], 'https://example.com')
            self.assertEqual(rows[1][-1], 'Keyword, with comma (+10)')
            self.assertEqual(len(rows[0]), len(rows[1]))
        self.assertIn(location.encode(), self.client.get('/').data)

    def test_errors_are_not_saved(self):
        with patch('app.scan_url', return_value={'error': 'Upstream unavailable'}):
            response = self.client.post('/', data={'url': 'https://example.com'})
        self.assertIn(b'Upstream unavailable', response.data)
        self.assertIn(b'No saved scans yet', response.data)

    def test_storage_failure_preserves_scan_result(self):
        with self.assertLogs(app.logger, level='WARNING'), patch('app.history_connection', side_effect=sqlite3.OperationalError('locked')):
            with patch('app.scan_url', return_value=self.result):
                response = self.client.post('/', data={'url': 'https://example.com'})
            self.assertEqual(response.status_code, 200)
            self.assertIn(b'45', response.data)
            self.assertIn(b'could not be saved', response.data)
            self.assertEqual(self.client.get('/reports/abc').status_code, 503)
            self.assertEqual(self.client.get('/reports/abc/export/json').status_code, 503)

    def test_missing_reports_and_formats(self):
        self.assertEqual(self.client.get('/reports/missing').status_code, 404)
        self.assertEqual(self.client.get('/reports/missing/export/json').status_code, 404)
        self.assertEqual(self.client.get('/reports/missing/export/html').status_code, 404)

    def test_escaping_and_csv_formula_protection(self):
        target = '=HYPERLINK("https://example.com")<script>alert(1)</script>'
        location = self.save(target)
        self.assertNotIn(b'<script>alert(1)</script>', self.client.get(location).data)
        rows = list(csv.reader(io.StringIO(self.client.get(location + '/export/csv').text)))
        self.assertEqual(rows[1][1], "'" + target)
        self.assertEqual(self.client.get(location + '/export/json').json['url'], target)

    def test_latest_twenty_and_zero_count_report(self):
        self.result.update(score=0, reasons=[], stats=dict.fromkeys(self.result['stats'], 0))
        for number in range(21):
            location = self.save(f'https://example.com/{number}')
        self.assertEqual(self.client.get(location).status_code, 200)
        page = self.client.get('/').text
        self.assertEqual(page.count('class="history-target"'), 20)
        self.assertNotIn('https://example.com/0<small>', page)


if __name__ == '__main__':
    unittest.main()
