from flask import Flask, render_template, request, redirect, session, jsonify, flash
from redis import Redis
import sqlite3
import random
import string
import time
from werkzeug.security import generate_password_hash, check_password_hash
from model.detector import detect_ai_generated_text
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from datetime import datetime, timedelta

app = Flask(__name__)
app.secret_key = "your_secret_key"
# ✅ 使用 Redis 存储限速信息，确保 Flask-Limiter 稳定工作
redis_client = Redis(host="localhost", port=6379)
print("✅ Redis connection test:", redis_client.ping())
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    storage_uri="memory://",
    default_limits=["3 per minute"]
)

DATABASE = "database.db"

@app.before_request
def debug_limiter_state():
    print(f"📍 当前 endpoint: {request.endpoint} | path: {request.path}")

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

# 生成6位验证码 / Generate 6-digit code
def generate_code(length=6):
    return ''.join(random.choices(string.digits, k=length))

# 模拟发送验证码（打印代替） / Simulate sending code (print)
def send_verification_code(phone, code):
    print(f"📧 发送验证码到 {phone}：{code}")

# 登录流程：用户名+密码 → 验证码 → 验证通过 → 登录成功
# @shared_login_limit
# 全局登录尝试计数器
login_attempts = {}
@app.route("/", methods=["GET", "POST"], endpoint="login")
def login():

    ip = request.remote_addr
    now = datetime.now()

    login_attempts.setdefault(ip, [])
    login_attempts[ip] = [ts for ts in login_attempts[ip] if now - ts < timedelta(minutes=1)]

    if len(login_attempts[ip]) >= 3:
        return "⚠️ Too many login attempts from this IP. Please try again later.", 429

    login_attempts[ip].append(now)
    print(f"🔐 login triggered from IP: {ip} | 当前尝试次数: {len(login_attempts[ip])}")

    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        login_ip = request.remote_addr

        conn = get_db_connection()
        user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        conn.close()

        if user and check_password_hash(user["password"], password):
            last_ip = user["last_login_ip"]
            if last_ip and last_ip != login_ip:
                print(f"⚠️ 检测到新设备登录：当前IP={login_ip}, 上次IP={last_ip}")
            else:
                print("✅ 登录环境正常")

            code = generate_code()
            session["pending_user"] = username
            session["login_code"] = code
            session["login_code_expiry"] = time.time() + 300
            session["login_attempts"] = 0
            send_verification_code(user["phone"], code)
            return redirect("/verify")
        else:
            return "❌Login failed. Incorrect username or password！"

    return render_template("login.html")

@app.route("/verify", methods=["GET", "POST"])
def verify():
    if "pending_user" not in session:
        return redirect("/")

    if request.method == "POST":
        code_input = request.form["code"]
        if time.time() > session.get("login_code_expiry", 0):
            return "⏰ Verification code expired."
        if session.get("login_attempts", 0) >= 3:
            return "❌  Too many incorrect attempts."

        if code_input == session["login_code"]:
            session["user"] = session.pop("pending_user")
            conn = get_db_connection()
            conn.execute("UPDATE users SET last_login_ip = ? WHERE username = ?", (request.remote_addr, session["user"]))
            conn.commit()
            conn.close()
            session.pop("login_code", None)
            session.pop("login_code_expiry", None)
            session.pop("login_attempts", None)
            return redirect("/query")
        else:
            session["login_attempts"] += 1
            return "❌Incorrect code."

    return render_template("verify.html")

# 注册：填写信息 → 发送验证码 → 跳转验证码页
@limiter.limit("3 per minute", override_defaults=False)  # 限制每个IP每分钟最多注册3次
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        phone = request.form["phone"]

        if not phone.isdigit() or len(phone) != 11:
            return "⚠️Invalid phone number"

        conn = get_db_connection()
        existing_user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        existing_phone = conn.execute("SELECT * FROM users WHERE phone = ?", (phone,)).fetchone()
        if existing_phone:
            conn.close()
            return "⚠️ Phone number already registered. Please use a different phone!"

        if existing_user:
            conn.close()
            return "⚠️ Username already exists. Please choose another one!"
        code = generate_code()
        session["reg_username"] = username
        session["reg_password"] = password
        session["reg_phone"] = phone
        session["reg_code"] = code
        session["reg_code_expiry"] = time.time() + 300
        session["reg_attempts"] = 0
        send_verification_code(phone, code)
        return redirect("/register_verify")

    return render_template("register.html")

# 注册验证码验证
@app.route("/register_verify", methods=["GET", "POST"])
def register_verify():
    if "reg_username" not in session:
        return redirect("/register")

    if request.method == "POST":
        code_input = request.form["code"]
        if time.time() > session.get("reg_code_expiry", 0):
            return "⏰ Verification code expired."
        if session.get("reg_attempts", 0) >= 3:
            return "❌ Too many incorrect attempts."

        if code_input == session["reg_code"]:
            hashed_password = generate_password_hash(session["reg_password"])
            conn = get_db_connection()
            conn.execute("INSERT INTO users (username, password, phone) VALUES (?, ?, ?)", (
                session["reg_username"], hashed_password, session["reg_phone"]
            ))
            conn.commit()
            conn.close()
            # 清理 session
            for key in ["reg_username", "reg_password", "reg_phone", "reg_code", "reg_code_expiry", "reg_attempts"]:
                session.pop(key, None)
            return redirect("/")
        else:
            session["reg_attempts"] += 1
            return "❌ Incorrect code."

    return render_template("register_verify.html")

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


@app.route('/create_project', methods=['GET', 'POST'])
def create_project():
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']

        # 🔍 Use your AI detection model
        score = detect_ai_generated_text(description)
        print(f"🤖 AI Trust Score: {score}")

        # ✅ 存入数据库
        conn = get_db_connection()
        conn.execute(
            "INSERT INTO projects (title, description, ai_score) VALUES (?, ?, ?)",
            (title, description, score)
        )
        conn.commit()
        conn.close()


        if score <= 0.4:
            flash(f"❌ Rejected (Trust Score: {score})", "error")
        else:
            flash(f"✅ Accepted (Trust Score: {score})", "success")

        return render_template("create_project.html")

    return render_template("create_project.html")

@app.errorhandler(429)
def ratelimit_handler(e):
    return "⚠️ Too many requests - you are being rate limited.", 429

if __name__ == "__main__":
    app.run(debug=True)
