# vulnerable_login.py
# 취약점: SQL Injection (CWE-89)
# 탐지 도구: Bandit, Sparrow SAST, V-체커(DAST)

import sqlite3
from flask import Flask, request

app = Flask(__name__)

def get_db():
    conn = sqlite3.connect("users.db")
    return conn

@app.route("/login", methods=["POST"])
def login():
    username = request.form["username"]
    password = request.form["password"]

    conn = get_db()
    cursor = conn.cursor()

    # 취약한 쿼리: 사용자 입력을 직접 문자열에 삽입
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    cursor.execute(query)   # ← Bandit B608, CWE-89 탐지 지점
    result = cursor.fetchone()

    if result:
        return "로그인 성공"
    else:
        return "로그인 실패"

if __name__ == "__main__":
    app.run(debug=True)     # ← debug=True 도 Bandit B201로 탐지됨


