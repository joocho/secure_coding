# vulnerable_config.py
# 취약점: 하드코딩 자격증명 (CWE-798), 평문 저장 (CWE-312)
# 탐지 도구: Bandit B105/B106, Sparrow SAST

import hashlib

# 하드코딩된 자격증명 — Bandit B105로 즉시 탐지
ADMIN_PASSWORD = "admin1234"          # CWE-798
DB_CONNECTION  = "mysql://root:1234@192.168.1.10/militarydb"  # CWE-798

def save_password(plain_text):
    # MD5는 암호학적으로 취약한 해시 — Bandit B324, CWE-327
    hashed = hashlib.md5(plain_text.encode()).hexdigest()
    return hashed   # ← 레인보우 테이블로 역산 가능

def check_admin(input_password):
    # 타이밍 공격(Timing Attack) 가능한 단순 비교 — CWE-208
    if input_password == ADMIN_PASSWORD:
        return True
    return False