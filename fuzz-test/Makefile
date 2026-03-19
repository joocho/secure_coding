# ─────────────────────────────────────────────────────────────────
# Makefile — 세 가지 퍼저 harness 빌드
# ─────────────────────────────────────────────────────────────────
#
# 사용법:
#   make libfuzzer      libFuzzer 바이너리 생성
#   make aflpp          AFL++ 바이너리 생성
#   make honggfuzz      Honggfuzz 바이너리 생성
#   make all            세 가지 모두 생성
#   make clean          빌드 산출물 제거
#   make seeds          초기 코퍼스 시드 생성
#   make run-libfuzzer  libFuzzer 퍼징 실행
#   make run-aflpp      AFL++ 퍼징 실행
#
# 요구 사항:
#   libFuzzer  : clang 13+
#   AFL++      : afl-clang-fast (apt install afl++)
#   Honggfuzz  : hfuzz-clang   (소스 빌드 후 PATH 추가)
# ─────────────────────────────────────────────────────────────────

CC_CLANG     ?= clang
CC_AFLPP     ?= afl-clang-fast
CC_HONGG     ?= hfuzz-clang

CFLAGS_COMMON = -g -O1 -Wall

SRCS_LIB     = vulnerable_lib.c

# ── libFuzzer ──────────────────────────────────────────────────────
libfuzzer: fuzz_libfuzzer.c $(SRCS_LIB) vulnerable_lib.h
	$(CC_CLANG) $(CFLAGS_COMMON) \
	    -fsanitize=address,fuzzer \
	    fuzz_libfuzzer.c $(SRCS_LIB) \
	    -o fuzz_libfuzzer
	@echo "✓ libFuzzer 바이너리: ./fuzz_libfuzzer"

# ── AFL++ ─────────────────────────────────────────────────────────
aflpp: fuzz_aflpp.c $(SRCS_LIB) vulnerable_lib.h
	$(CC_AFLPP) $(CFLAGS_COMMON) \
	    -fsanitize=address \
	    fuzz_aflpp.c $(SRCS_LIB) \
	    -o fuzz_aflpp
	@echo "✓ AFL++ 바이너리: ./fuzz_aflpp"

# ── Honggfuzz ──────────────────────────────────────────────────────
honggfuzz: fuzz_honggfuzz.c $(SRCS_LIB) vulnerable_lib.h
	$(CC_HONGG) $(CFLAGS_COMMON) \
	    -fsanitize=address \
	    fuzz_honggfuzz.c $(SRCS_LIB) \
	    -o fuzz_honggfuzz
	@echo "✓ Honggfuzz 바이너리: ./fuzz_honggfuzz"

all: libfuzzer aflpp honggfuzz

# ── 초기 시드 코퍼스 ───────────────────────────────────────────────
seeds:
	mkdir -p seeds_afl seeds_hf corpus_libfuzzer corpus_afl corpus_hf
	# parse_header 용 — selector=0, "HEADER:AAAA..."
	printf '\x00HEADER:hello_world' > seeds_afl/seed_header
	# process_data 용 — selector=1, length=5, "hello"
	printf '\x01\x05hello'         > seeds_afl/seed_process
	# compute_checksum 용 — selector=2, 1x1 이미지
	printf '\x02\x00\x01\x00\x01\xff' > seeds_afl/seed_checksum
	# manage_buffer 용 — selector=3, 일반 데이터
	printf '\x03\x00normal_data'   > seeds_afl/seed_manage
	# parse_config 용 — selector=4, "key=value"
	printf '\x04key=value'         > seeds_afl/seed_config
	# decompress_rle 용 — selector=5, count=3, byte=0x41
	printf '\x05\x03\x41'         > seeds_afl/seed_rle
	cp seeds_afl/* seeds_hf/
	cp seeds_afl/* corpus_libfuzzer/
	@echo "✓ 시드 생성 완료"

# ── 실행 단축 명령 ────────────────────────────────────────────────
run-libfuzzer: libfuzzer seeds
	./fuzz_libfuzzer corpus_libfuzzer/ \
	    -max_len=512 -jobs=2 -workers=2 \
	    -timeout=10

run-aflpp: aflpp seeds
	afl-fuzz -i seeds_afl -o corpus_afl -- ./fuzz_aflpp

clean:
	rm -f fuzz_libfuzzer fuzz_aflpp fuzz_honggfuzz
	@echo "✓ 빌드 산출물 제거 완료"

.PHONY: all libfuzzer aflpp honggfuzz seeds run-libfuzzer run-aflpp clean
