"""
target_app.py
=============
A trivial, disposable test service that lives ONLY inside the sandbox
container. This stands in for the "lab-webapp" target referenced in
policy.yaml. It has no real functionality and no real data — its only
purpose is to be something Nmap/Nikto can legitimately scan in the lab.
"""
from flask import Flask

app = Flask(__name__)


@app.route("/")
def index():
    return "Lab test target — sandbox only. Not a real service."


@app.route("/health")
def health():
    return {"status": "ok"}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
