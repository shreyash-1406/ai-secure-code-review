"""
Deliberately vulnerable Flask app used to demo the scanner.
DO NOT deploy this. Every issue here is intentional.
"""
import hashlib
import os
import pickle
import sqlite3
import subprocess

import requests
from flask import Flask, request, render_template_string

app = Flask(__name__)

DB_PASSWORD = "SuperSecret123"
API_KEY = "sk_live_51HxAbCdEfGhIjKlMnOp"


@app.route("/user")
def get_user():
    user_id = request.args.get("id")
    conn = sqlite3.connect("app.db")
    # SQL injection: user input goes straight into the query
    rows = conn.execute(f"SELECT * FROM users WHERE id = {user_id}").fetchall()
    return str(rows)


@app.route("/ping")
def ping():
    host = request.args.get("host")
    return subprocess.check_output("ping -c 1 " + host, shell=True)


@app.route("/hello")
def hello():
    name = request.args.get("name", "")
    return render_template_string("<h1>Hello " + name + "</h1>")


@app.route("/download")
def download():
    return open(request.args.get("file")).read()


@app.route("/load", methods=["POST"])
def load():
    return str(pickle.loads(request.data))


def hash_password(pw):
    return hashlib.md5(pw.encode()).hexdigest()


def fetch(url):
    try:
        return requests.get(url, verify=False).text
    except:
        pass


if __name__ == "__main__":
    os.system("echo starting")
    app.run(debug=True)
