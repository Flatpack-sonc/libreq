CC ?= cc
CXX ?= c++
CFLAGS ?= -std=c11 -O2 -g -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Werror
SANITIZE ?=
CPPFLAGS += -Iinclude -DREQ_USE_OPENSSL -D_DEFAULT_SOURCE
LDFLAGS ?=
OPENSSL_LIBS ?= -lssl -lcrypto
PTHREAD ?= -pthread

SRC = src/req.c src/req_url.c src/req_net.c
OBJ = $(SRC:.c=.o)

ifneq ($(SANITIZE),)
CFLAGS += -fsanitize=address,undefined -fno-omit-frame-pointer
LDFLAGS += -fsanitize=address,undefined
endif

.PHONY: all test example clean cpp

all: libreq.a tests/test_req examples/get

libreq.a: $(OBJ)
	$(AR) rcs $@ $^

src/%.o: src/%.c include/req.h src/req_internal.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -fvisibility=hidden -c $< -o $@

tests/test_req: tests/test_req.c libreq.a
	$(CC) $(CFLAGS) $(CPPFLAGS) $(PTHREAD) $< libreq.a $(OPENSSL_LIBS) $(LDFLAGS) -o $@

examples/get: examples/get.c libreq.a
	$(CC) $(CFLAGS) $(CPPFLAGS) $< libreq.a $(OPENSSL_LIBS) $(LDFLAGS) -o $@

tests/test_cpp: tests/test_cpp.cpp libreq.a
	$(CXX) -std=c++17 -Wall -Wextra -Werror $(CPPFLAGS) tests/test_cpp.cpp libreq.a $(OPENSSL_LIBS) $(LDFLAGS) -o $@

test: tests/test_req
	./tests/test_req

cpp: tests/test_cpp
	./tests/test_cpp

example: examples/get
	./examples/get http://example.com/

clean:
	rm -f $(OBJ) libreq.a tests/test_req tests/test_cpp examples/get
	rm -rf build
