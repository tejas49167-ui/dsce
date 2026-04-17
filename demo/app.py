import os
import logging
from flask import Flask, request, render_template

app = Flask(__name__)

os.makedirs("../data/raw", exist_ok=True)


logger = logging.getLogger("aegis")
logger.setLevel(logging.INFO)

file_handler = logging.FileHandler("../data/raw/access.log")
formatter = logging.Formatter("%(asctime)s,%(message)s")
file_handler.setFormatter(formatter)

logger.addHandler(file_handler)


def log_request(status_code):
    path = request.full_path.rstrip("?")
    logger.info(f"{request.remote_addr},{request.method},{path},{status_code}")



@app.route("/")
def home():
    log_request(200)
    return render_template("index.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        if password != "admin123":
            log_request(401)
            return render_template("login.html", error="Invalid credentials"), 401

        log_request(200)
        return "<h3>Login Successful</h3>"

    log_request(200)
    return render_template("login.html")


@app.route("/search")
def search():
    query = request.args.get("q", "")
    log_request(200)
    return f"<h3>Search Result for: {query}</h3>"


if __name__ == "__main__":
    app.run(debug=True, host="127.0.0.1", port=8000)
