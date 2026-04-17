# lbr-hunt — LBR-based ROP detector
# Targets:
#   make test      run pure-logic unit tests (any host, no kernel deps)
#   make bin       build lbr-hunt CLI (Linux x86-64 only, needs perf_event_open)
#   make clean

CC       ?= cc
CSTD     ?= -std=c99
WARN     ?= -Wall -Wextra -Wshadow -Wpedantic -Wstrict-prototypes -Wmissing-prototypes
OPT      ?= -O2
CFLAGS   += $(CSTD) $(WARN) $(OPT) -Iinclude -D_GNU_SOURCE
LDFLAGS  +=
LDLIBS   += -lm

CORE_SRC := src/analyzer.c
CLI_SRC  := src/format.c src/collector.c src/main.c
SRC      := $(CORE_SRC) $(CLI_SRC)
OBJ      := $(SRC:.c=.o)
BIN      := lbr-hunt

.PHONY: all test bin clean install

# Default target: just run the portable tests. Building the CLI is an
# explicit opt-in since the collector only makes sense on Linux.
all: test

test:
	$(MAKE) -C tests run

bin: $(BIN)

$(BIN): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) $(LDLIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJ) $(BIN)
	$(MAKE) -C tests clean

install: $(BIN)
	install -Dm755 $(BIN) $(DESTDIR)/usr/local/bin/$(BIN)
