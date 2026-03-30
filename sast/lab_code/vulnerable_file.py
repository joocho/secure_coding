# vulnerable_file.py
# 취약점: Path Traversal (CWE-22)
# 탐지 도구: Bandit B604/open() 패턴, Sparrow SAST

from flask import Flask, request

app = Flask(__name__)
BASE_DIR = "/var/www/reports/"

@app.route("/download")
def download_file():
    filename = request.args.get("file")

    # 경로 검증 없이 직접 결합 — CWE-22 취약 지점
    filepath = BASE_DIR + filename

    with open(filepath, "r") as f:   # ← 공격자가 ../../../etc/passwd 입력 가능
        content = f.read()

    return content

if __name__ == "__main__":
    app.run(debug=True)
```

**공격 예시 URL**
```
http://localhost:5000/download?file=../../../etc/passwd
http://localhost:5000/download?file=../../../etc/shadow