# vulnerable_deserialize.py
# 취약점: Insecure Deserialization (CWE-502)
# 탐지 도구: Bandit B301/B302, Sparrow SAST

import pickle
import base64
from flask import Flask, request

app = Flask(__name__)

@app.route("/load_session", methods=["POST"])
def load_session():
    session_data = request.form["session"]

    # 신뢰할 수 없는 입력값을 pickle로 역직렬화 — CWE-502
    decoded = base64.b64decode(session_data)
    user_obj = pickle.loads(decoded)    # ← 원격 코드 실행(RCE) 가능

    return f"사용자: {user_obj['name']}"

if __name__ == "__main__":
    app.run(debug=True)