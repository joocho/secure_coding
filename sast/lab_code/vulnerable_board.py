# vulnerable_board.py
# 취약점: Stored/Reflected XSS (CWE-79)
# 탐지 도구: V-체커(DAST), Sparrow SAST

from flask import Flask, request, render_template_string

app = Flask(__name__)
posts = []

@app.route("/board", methods=["GET", "POST"])
def board():
    if request.method == "POST":
        content = request.form["content"]
        posts.append(content)   # 입력값 검증 없이 저장

    # 취약한 렌더링: |safe 필터로 HTML 이스케이프 비활성화
    template = """
    <h2>게시판</h2>
    <form method="POST">
      <input name="content" placeholder="내용 입력">
      <button type="submit">작성</button>
    </form>
    <ul>
    {% for post in posts %}
      <li>{{ post | safe }}</li>  <!-- ← XSS 취약 지점 -->
    {% endfor %}
    </ul>
    """
    return render_template_string(template, posts=posts)

if __name__ == "__main__":
    app.run(debug=True)