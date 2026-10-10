CC     ?= gcc
CFLAGS ?= -std=c11 -Wall -Wextra -Werror -O2

all: tracegen

tracegen: main.o trace.o
	$(CC) $(CFLAGS) -o $@ $^

tests/test_trace: tests/test_trace.o trace.o
	$(CC) $(CFLAGS) -o $@ $^

main.o trace.o tests/test_trace.o: trace.h

test: tests/test_trace
	./tests/test_trace

check: tracegen
	./tracegen -o check.dat
	trace-cmd report check.dat > check.txt
	grep -q 'task: *barebox started' check.txt
	grep -q 'task: *booting kernel' check.txt
	test "$$(grep -c 'task:' check.txt)" -eq 8
	./tracegen -f perfetto -o check.pftrace
	python3 tests/check_pfetto.py check.pftrace
	@echo "check: OK"

clean:
	rm -f *.o tests/*.o tracegen tests/test_trace trace.dat check.dat check.txt check.pftrace tests/*.dat tests/*.pftrace

.PHONY: all test check clean
