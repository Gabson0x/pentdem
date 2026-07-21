"""Minimal vulnerable Flask app for integration testing."""
from flask import Flask, request, redirect

app = Flask(__name__)

@app.route("/")
def index():
    return """<html><body>
<h1>Vuln Test App</h1>
<ul>
<li><a href="/search?q=hello">Search (reflected XSS)</a></li>
<li><a href="/user?id=1">User (SQLi-like)</a></li>
<li><a href="/redirect?url=https://example.com">Redirect (open redirect)</a></li>
</ul>
</body></html>"""

@app.route("/search")
def search():
    q = request.args.get("q", "")
    return f"<html><body><h1>Results for: {q}</h1></body></html>"

@app.route("/user")
def user():
    uid = request.args.get("id", "1")
    return f"<html><body><p>User ID: {uid}</p></body></html>"

@app.route("/redirect")
def redir():
    return redirect(request.args.get("url", "/"))

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5001)
