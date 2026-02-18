import os
import logging
from flask import Flask, request, render_template

app = Flask(__name__)

os.makedirs("../data/raw", exist_ok=True)

logging.basicConfig(
    filename="../data/raw/access.log",
    level=logging.INFO,
    format="%(asctime)s | %(message)s"
)

@app.route("/")
def home():
    logging.info(f"{request.remote_addr} GET / 200")
    return render_template("index.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        if password != "admin123":
            logging.info(f"{request.remote_addr},{request.method},/login,401")
            return render_template("login.html", error="Invalid credentials"), 401

        logging.info(f"{request.remote_addr},{request.method},/login 200")
        return "<h3>Login Successful</h3>"

    logging.info(f"{request.remote_addr} GET /login 200")
    return render_template("login.html")

@app.route("/search")
def search():
    query = request.args.get("q", "")
    logging.info(f"{request.remote_addr} GET /search?q={query} 200")
    return f"<h3>Search Result for: {query}</h3>"

if __name__ == "__main__":
    app.run(debug=True,host="127.0.0.1",port = 8000)
