CC ?= cc
CXX ?= c++
CFLAGS ?= -std=c11 -O2 -g -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wsign-conversion -Werror
SANITIZE ?=
CPPFLAGS += -Iinclude -DREQ_USE_OPENSSL -D_DEFAULT_SOURCE
LDFLAGS ?=
OPENSSL_LIBS ?= -lssl -lcrypto
PTHREAD ?= -pthread
PREFIX ?= /usr/local
FUZZ_TIME ?= 30

SRC = src/req.c src/req_url.c src/req_net.c
OBJ = $(SRC:.c=.o)
HDR = include/req.h src/req_internal.h
# Tests exercise internals and OpenSSL server APIs; keep them warning-clean but not as strict.
TEST_CFLAGS = -std=c11 -O1 -g -Wall -Wextra -Werror -Wno-deprecated-declarations

ifneq ($(SANITIZE),)
CFLAGS += -fsanitize=address,undefined -fno-omit-frame-pointer
TEST_CFLAGS += -fsanitize=address,undefined -fno-omit-frame-pointer
LDFLAGS += -fsanitize=address,undefined
endif

.PHONY: all test unit integration example clean cpp fuzz install

all: libreq.a tests/test_req tests/test_unit examples/get

libreq.a: $(OBJ)
	$(AR) rcs $@ $^

src/%.o: src/%.c $(HDR)
	$(CC) $(CFLAGS) $(CPPFLAGS) -fvisibility=hidden -c $< -o $@

tests/test_req: tests/test_req.c libreq.a
	$(CC) $(TEST_CFLAGS) $(CPPFLAGS) $(PTHREAD) $< libreq.a $(OPENSSL_LIBS) $(LDFLAGS) -o $@

tests/test_unit: tests/test_unit.c libreq.a $(HDR)
	$(CC) $(TEST_CFLAGS) $(CPPFLAGS) $(PTHREAD) $< libreq.a $(OPENSSL_LIBS) $(LDFLAGS) -o $@

examples/get: examples/get.c libreq.a
	$(CC) $(CFLAGS) $(CPPFLAGS) $< libreq.a $(OPENSSL_LIBS) $(LDFLAGS) -o $@

tests/test_cpp: tests/test_cpp.cpp libreq.a
	$(CXX) -std=c++17 -Wall -Wextra -Werror $(CPPFLAGS) tests/test_cpp.cpp libreq.a $(OPENSSL_LIBS) $(LDFLAGS) -o $@

unit: tests/test_unit
	./tests/test_unit

integration: tests/test_req
	./tests/test_req

test: unit integration

cpp: tests/test_cpp
	./tests/test_cpp

example: examples/get
	./examples/get http://example.com/

# libFuzzer targets (clang only): make fuzz CC=clang FUZZ_TIME=60
FUZZ_FLAGS = -std=c11 -g -O1 -fsanitize=fuzzer,address,undefined $(CPPFLAGS)
fuzz: fuzz/fuzz_url fuzz/fuzz_response
	mkdir -p fuzz/corpus_url fuzz/corpus_response
	./fuzz/fuzz_url -max_total_time=$(FUZZ_TIME) fuzz/corpus_url fuzz/seeds_url
	./fuzz/fuzz_response -max_total_time=$(FUZZ_TIME) -max_len=8192 fuzz/corpus_response fuzz/seeds_response

fuzz/fuzz_url: fuzz/fuzz_url.c $(SRC) $(HDR)
	$(CC) $(FUZZ_FLAGS) fuzz/fuzz_url.c $(SRC) $(OPENSSL_LIBS) -o $@

fuzz/fuzz_response: fuzz/fuzz_response.c $(SRC) $(HDR)
	$(CC) $(FUZZ_FLAGS) fuzz/fuzz_response.c $(SRC) $(OPENSSL_LIBS) -o $@

install: libreq.a
	install -d $(DESTDIR)$(PREFIX)/lib $(DESTDIR)$(PREFIX)/include
	install -m 644 libreq.a $(DESTDIR)$(PREFIX)/lib/
	install -m 644 include/req.h $(DESTDIR)$(PREFIX)/include/

clean:
	rm -f $(OBJ) libreq.a tests/test_req tests/test_unit tests/test_cpp examples/get
	rm -f fuzz/fuzz_url fuzz/fuzz_response
	rm -rf build
