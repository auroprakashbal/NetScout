from flask import Flask, render_template, request, redirect, url_for
from scanner import NetworkScanner

app = Flask(__name__)


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/scan', methods=['POST'])
def scan():
    target = request.form.get('target', '').strip()

    if not target:
        return redirect(url_for('index'))

    scanner = NetworkScanner()
    results = scanner.scan(target)

    return render_template('report.html', results=results)


if __name__ == '__main__':
    print("=" * 50)
    print("  NetScout - Network Vulnerability Scanner")
    print("  Open your browser: http://127.0.0.1:5000")
    print("=" * 50)
    app.run(debug=False, host='127.0.0.1', port=5000)
