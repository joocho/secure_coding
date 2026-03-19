# Fuzzing Lab — 취약점 발견 실습

의도적으로 취약점을 심은 C 라이브러리(`vulnerable_lib.c`)를
AFL++, libFuzzer, Honggfuzz 세 퍼저로 퍼징하는 실습 환경입니다.

---

## 파일 구조

```
fuzzing_lab/
├── vulnerable_lib.h      취약 라이브러리 헤더
├── vulnerable_lib.c      취약점 6종이 심어진 타깃 라이브러리
├── fuzz_libfuzzer.c      libFuzzer harness
├── fuzz_aflpp.c          AFL++ harness (persistent mode)
├── fuzz_honggfuzz.c      Honggfuzz harness (HF_ITER)
├── Makefile              빌드 & 실행 자동화
└── README.md             이 파일
```

---

## 심어진 취약점 목록

| # | 함수 | 취약점 종류 | 트리거 조건 |
|---|------|------------|------------|
| 1 | `parse_header` | Stack Buffer Overflow | 입력에 `HEADER:` + 64바이트 이상 값 |
| 2 | `process_data` | Heap Buffer Overflow | `data[0]`(길이) > 실제 데이터 크기 |
| 3 | `compute_checksum` | Integer Overflow → OOB | `width * height > 65535` |
| 4 | `manage_buffer` | Use-After-Free | `data[0] == 0xFF` |
| 5 | `parse_config` | NULL Dereference | 입력에 `=` 문자 없음 |
| 6 | `decompress_rle` | Infinite Loop / DoS | `count == 0` |

---

## 1. 설치

### Ubuntu / Debian 기준

```bash
# 공통 도구
sudo apt update
sudo apt install -y clang llvm build-essential git

# AFL++
sudo apt install -y afl++
# 또는 최신 버전 소스 빌드:
# git clone https://github.com/AFLplusplus/AFLplusplus && cd AFLplusplus && make

# Honggfuzz (소스 빌드)
sudo apt install -y libbfd-dev libunwind-dev
git clone https://github.com/google/honggfuzz
cd honggfuzz && make
sudo make install   # hfuzz-clang 을 PATH 에 추가
```

---

## 2. 빌드

```bash
# 초기 시드 코퍼스 생성
make seeds

# libFuzzer 바이너리
make libfuzzer

# AFL++ 바이너리
make aflpp

# Honggfuzz 바이너리
make honggfuzz
```

---

## 3. 퍼징 실행

### libFuzzer

```bash
# 기본 실행 (2 병렬)
./fuzz_libfuzzer corpus_libfuzzer/ -max_len=512 -jobs=2 -workers=2

# 크래시가 발생하면 자동으로 crash-<hash> 파일 생성
# 재현:
./fuzz_libfuzzer crash-abcdef1234
```

### AFL++

```bash
# 단일 인스턴스
afl-fuzz -i seeds_afl -o corpus_afl -- ./fuzz_aflpp

# 병렬 (마스터 1 + 슬레이브 2)
afl-fuzz -i seeds_afl -o corpus_afl -M main   -- ./fuzz_aflpp &
afl-fuzz -i seeds_afl -o corpus_afl -S slave1 -- ./fuzz_aflpp &
afl-fuzz -i seeds_afl -o corpus_afl -S slave2 -- ./fuzz_aflpp &

# 통계 확인
afl-whatsup corpus_afl/

# 크래시 재현
cat corpus_afl/main/crashes/id:000000* | ./fuzz_aflpp
```

### Honggfuzz

```bash
# 멀티스레드 4개 (소프트웨어 커버리지)
honggfuzz -i seeds_hf -W corpus_hf -n 4 --sanitizers -- ./fuzz_honggfuzz

# Intel PT 하드웨어 커버리지 (지원 CPU 필요)
honggfuzz -i seeds_hf -W corpus_hf -n 4 --linux_perf_ipt -- ./fuzz_honggfuzz

# 크래시 확인
cat corpus_hf/HONGGFUZZ.REPORT.TXT
```

---

## 4. 크래시 분석

### AddressSanitizer 출력 읽기

크래시가 나면 ASAN이 아래와 같은 보고를 터미널에 출력합니다:

```
==12345==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x...
WRITE of size 1 at 0x... thread T0
    #0 0x... in parse_header vulnerable_lib.c:42
    ...
```

### 크래시 최소화 (libFuzzer)

```bash
./fuzz_libfuzzer -minimize_crash=1 -runs=10000 crash-<hash>
```

### 크래시 최소화 (AFL++)

```bash
afl-tmin -i corpus_afl/main/crashes/id:000000 -o minimized -- ./fuzz_aflpp
```

---

## 5. 퍼징 팁

- **코퍼스 공유**: libFuzzer 코퍼스를 AFL++ 시드로 재사용할 수 있습니다.
- **딕셔너리**: `HEADER:`, `=`, `\xFF` 같은 매직 토큰을 딕셔너리 파일로 만들어 AFL++ 에 `-x dict.txt` 옵션으로 제공하면 커버리지가 올라갑니다.
- **타임아웃**: DoS 취약점(#6)은 `-timeout=5` 로 타임아웃을 짧게 설정해야 퍼저가 감지합니다.
- **Sanitizer 조합**: `-fsanitize=address,undefined` 를 함께 쓰면 더 많은 취약점 클래스를 탐지합니다.

---

## 주의

이 코드는 **교육 목적**으로만 사용하세요.  
`vulnerable_lib.c` 를 프로덕션 환경에 절대 배포하지 마세요.
