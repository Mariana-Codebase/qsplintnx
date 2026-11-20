# QSplintNX build
#
#   make            host build of the portable core + unit tests (Linux/WSL, gcc or clang)
#   make test       run host unit tests
#   make sanitize   unit tests under ASan + UBSan
#   make fuzz       libFuzzer target for the rule parser (needs clang)
#   make bench      host micro-benchmark of the engine
#   make qnx        cross-build QNX binaries (needs: source ~/qnx800/qnxsdp-env.sh)
#
# Only the Commander edits this file. Teams flag needed changes.

CC      ?= cc
CSTD    := -std=c11 -D_POSIX_C_SOURCE=200809L
WARN    := -Wall -Wextra -Wshadow -Wpointer-arith -Wstrict-prototypes -Wmissing-prototypes -Werror
CFLAGS  ?= -O2 -g
INC     := -Iinclude -Isrc/core
BUILD   := build/host

CORE_SRC := src/core/msg.c src/core/rules_lexer.c src/core/rules_parser.c \
            src/core/rules_format.c src/core/engine.c src/core/ratelimit.c \
            src/core/learn.c src/core/log.c
CORE_OBJ := $(CORE_SRC:src/core/%.c=$(BUILD)/core/%.o)

TESTS    := test_lexer test_rules test_engine test_learn test_log
TEST_BIN := $(TESTS:%=$(BUILD)/tests/%)

.PHONY: all host test sanitize fuzz bench qnx clean
all: host
host: $(BUILD)/libsplintcore.a $(TEST_BIN)

$(BUILD)/core/%.o: src/core/%.c include/splint/*.h src/core/*.h
	@mkdir -p $(dir $@)
	$(CC) $(CSTD) $(WARN) $(CFLAGS) $(INC) -c $< -o $@

$(BUILD)/libsplintcore.a: $(CORE_OBJ)
	ar rcs $@ $^

$(BUILD)/tests/%: tests/%.c tests/test_util.h $(BUILD)/libsplintcore.a
	@mkdir -p $(dir $@)
	$(CC) $(CSTD) $(WARN) $(CFLAGS) $(INC) -Itests $< $(BUILD)/libsplintcore.a -lpthread -o $@

test: host
	@set -e; for t in $(TEST_BIN); do echo "== $$t"; $$t; done; echo "ALL TESTS PASSED"

sanitize:
	$(MAKE) BUILD=build/san CC=clang CFLAGS="-O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=all" test

fuzz:
	@mkdir -p build/fuzz
	clang $(CSTD) -g -O1 -fsanitize=fuzzer,address,undefined $(INC) tests/fuzz_rules.c $(CORE_SRC) -o build/fuzz/fuzz_rules
	@echo "run: build/fuzz/fuzz_rules -max_total_time=60 tests/corpus"

bench: $(BUILD)/libsplintcore.a
	@mkdir -p $(BUILD)/bench
	$(CC) $(CSTD) $(WARN) -O2 $(INC) bench/bench_engine.c $(BUILD)/libsplintcore.a -lpthread -o $(BUILD)/bench/bench_engine
	$(BUILD)/bench/bench_engine

# ---------------------------------------------------------------- QNX ----
QCC      ?= qcc
QARCH    ?= gcc_ntox86_64
QBUILD   := build/qnx-$(QARCH)
QFLAGS   := -V$(QARCH) $(CSTD) -D_QNX_SOURCE -Wall -Wextra -Werror -O2 -g $(INC)

QNX_SPLINTD := src/qnx/splintd_main.c src/qnx/interpose.c src/qnx/backend.c \
               src/qnx/ctl.c src/qnx/clientinfo.c

qnx:
	@test -n "$(QNX_TARGET)" || { echo "QNX_TARGET not set: source ~/qnx800/qnxsdp-env.sh"; exit 1; }
	@mkdir -p $(QBUILD)
	$(QCC) $(QFLAGS) $(QNX_SPLINTD) $(CORE_SRC) -o $(QBUILD)/splintd
	$(QCC) $(QFLAGS) tools/splintctl/splintctl.c src/core/log.c src/core/msg.c -o $(QBUILD)/splintctl
	$(QCC) $(QFLAGS) -Idemo/include demo/vendor_can/vendor_can.c -o $(QBUILD)/vendor_can
	$(QCC) $(QFLAGS) -Idemo/include demo/clients/can_client.c -o $(QBUILD)/can_client
	$(QCC) $(QFLAGS) -Idemo/include demo/clients/exploit.c -o $(QBUILD)/exploit
	$(QCC) $(QFLAGS) -Idemo/include bench/bench_ipc.c -o $(QBUILD)/bench_ipc
	@echo "QNX binaries in $(QBUILD)"

clean:
	rm -rf build
