from flask import Flask, render_template, request, send_from_directory

from scanner import scan_url

app = Flask(__name__)


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
    return render_template("index.html", result=result, url=url)


if __name__ == "__main__":
    app.run(debug=True, port=5000)
