CC       ?= cc
CSTD     ?= -std=c99
WARN     ?= -Wall -Wextra -Wshadow -Wpedantic -Wstrict-prototypes -Wmissing-prototypes
OPT      ?= -O0 -g
CFLAGS   += $(CSTD) $(WARN) $(OPT) -I../include -D_GNU_SOURCE
LDLIBS   += -lm

TESTS := test_analyzer

.PHONY: all run clean
all: $(TESTS)

test_analyzer: test_analyzer.c ../src/analyzer.c
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

run: $(TESTS)
	@set -e; for t in $(TESTS); do echo "==> $$t"; ./$$t; done

clean:
	rm -f $(TESTS)
