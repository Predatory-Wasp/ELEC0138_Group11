from flask import Flask, render_template, request, redirect, session, jsonify
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "your_secret_key"

DATABASE = "database.db"

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        conn = get_db_connection()
        user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        conn.close()

        if user and check_password_hash(user["password"], password):
            session["user"] = username
            return redirect("/welcome")
        else:
            return "❌ Login failed. Incorrect username or password!"

    return render_template("login.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        hashed_password = generate_password_hash(password)

        conn = get_db_connection()
        existing_user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()

        if existing_user:
            conn.close()
            return "⚠️ Username already exists. Please choose another one!"

        conn.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
        conn.commit()
        conn.close()

        return redirect("/")

    return render_template("register.html")

@app.route("/welcome")
def welcome():
    if "user" not in session:
        return redirect("/")
    return render_template("welcome.html")

@app.route("/donate", methods=["GET", "POST"])
def donate():
    if "user" not in session:
        return redirect("/")

    if request.method == "POST":
        amount = request.form["amount"]
        method = request.form["method"]
        message = request.form["message"]

        print(f"✅ Received donation: £{amount} via {method}. Message: {message}")

        return redirect("/thank_you")

    return render_template("donate.html")

@app.route("/thank_you")
def thank_you():
    if "user" not in session:
        return redirect("/")  

    return render_template("thank_you.html")

@app.route("/random_loans")
def random_loans():
    conn = get_db_connection()
    data = conn.execute("SELECT * FROM loans ORDER BY RANDOM() LIMIT 10").fetchall()
    conn.close()
    
    return jsonify([dict(row) for row in data])

@app.route("/query")
def query_page():
    if "user" not in session:
        return redirect("/")
    return render_template("query.html")

@app.route("/search")
def search():
    if "user" not in session:
        return jsonify([])

    loan_id = request.args.get("id")
    conn = get_db_connection()
    
    if loan_id:
        data = conn.execute("SELECT * FROM loans WHERE id = ?", (loan_id,)).fetchall()
    else:
        data = conn.execute("SELECT * FROM loans").fetchall()

    conn.close()

    return jsonify([dict(row) for row in data])

@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect("/")

if __name__ == "__main__":
    app.run(debug=True)
