#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "../trace.h"

#define CHECK(cond) do { \
    if (!(cond)) { \
        fprintf(stderr, "%s:%d: CHECK failed: %s\n", __FILE__, __LINE__, #cond); \
        exit(1); \
    } \
} while (0)

static void test_add_appends_and_free_resets(void)
{
    trace_free();
    CHECK(trace_count() == 0);
    CHECK(trace_add("barebox started") == 0);
    CHECK(trace_add("kernel loaded") == 0);
    CHECK(trace_count() == 2);
    trace_free();
    CHECK(trace_count() == 0);
}

static void test_add_null_is_einval(void)
{
    trace_free();
    errno = 0;
    CHECK(trace_add(NULL) == -1);
    CHECK(errno == EINVAL);
    CHECK(trace_count() == 0);
}

static void test_add_at_appends(void)
{
    trace_free();
    CHECK(trace_add_at(42, "a") == 0);
    CHECK(trace_count() == 1);
    trace_free();
}

#define TEST_OUT "tests/out.dat"

static uint8_t *read_file(const char *path, size_t *len)
{
	FILE *f = fopen(path, "rb");
	uint8_t *buf;
	long n;

	CHECK(f != NULL);
	CHECK(fseek(f, 0, SEEK_END) == 0);
	n = ftell(f);
	CHECK(n >= 0);
	rewind(f);
	buf = malloc((size_t)n + 1);
	CHECK(buf != NULL);
	CHECK(fread(buf, 1, (size_t)n, f) == (size_t)n);
	fclose(f);
	*len = (size_t)n;
	return buf;
}

/*
 * Walk a trace-cmd v6 header and return the CPU 0 flyrecord offset/size.
 * Mirrors the layout in the spec. No bounds checking: test-only code.
 */
static int parse_header(const uint8_t *b, size_t n, uint64_t *off, uint64_t *size)
{
	size_t p;
	uint32_t c, i, j;
	uint64_t s;

	if (n < 10 || memcmp(b, "\x17\x08\x44tracing", 10) != 0)
		return -1;
	p = 10;
	if (strcmp((const char *)b + p, "6") != 0)
		return -1;
	p += 2;                                   /* "6\0" */
	if (b[p] != 0 || b[p + 1] != 8)           /* little endian, long == 8 */
		return -1;
	p += 2;
	memcpy(&c, b + p, 4); p += 4;
	if (c != 4096)
		return -1;
	if (memcmp(b + p, "header_page", 12) != 0)
		return -1;
	p += 12; memcpy(&s, b + p, 8); p += 8 + s;
	if (memcmp(b + p, "header_event", 13) != 0)
		return -1;
	p += 13; memcpy(&s, b + p, 8); p += 8 + s;
	memcpy(&c, b + p, 4); p += 4;             /* ftrace events */
	for (i = 0; i < c; i++) { memcpy(&s, b + p, 8); p += 8 + s; }
	memcpy(&c, b + p, 4); p += 4;             /* event systems */
	if (c != 1)
		return -1;
	for (i = 0; i < c; i++) {
		if (strcmp((const char *)b + p, "barebox") != 0)
			return -1;
		p += strlen((const char *)b + p) + 1;
		memcpy(&j, b + p, 4); p += 4;
		if (j != 1)
			return -1;
		while (j--) {
			memcpy(&s, b + p, 8); p += 8;
			if (memcmp(b + p, "name: task\nID: 1000\n", 20) != 0)
				return -1;
			p += s;
		}
	}
	memcpy(&c, b + p, 4); p += 4 + c;         /* kallsyms */
	memcpy(&c, b + p, 4); p += 4 + c;         /* printk formats */
	memcpy(&s, b + p, 8); p += 8;             /* saved cmdlines */
	if (s != 10 || memcmp(b + p, "1 barebox\n", 10) != 0)
		return -1;
	p += s;
	memcpy(&c, b + p, 4); p += 4;             /* nr cpus */
	if (c != 1)
		return -1;
	if (memcmp(b + p, "options  ", 10) != 0)
		return -1;
	p += 10;
	for (;;) {
		uint16_t o;
		memcpy(&o, b + p, 2); p += 2;
		if (o == 0)
			break;
		memcpy(&c, b + p, 4); p += 4 + c;
	}
	if (memcmp(b + p, "flyrecord", 10) != 0)
		return -1;
	p += 10;
	memcpy(off, b + p, 8);
	memcpy(size, b + p + 8, 8);
	return 0;
}

static void test_write_empty_list(void)
{
	uint8_t *buf;
	size_t len;
	uint64_t off, size;

	trace_free();
	CHECK(trace_write(TEST_OUT) == 0);
	buf = read_file(TEST_OUT, &len);
	CHECK(parse_header(buf, len, &off, &size) == 0);
	CHECK(off % 4096 == 0);
	CHECK(size == 0);
	CHECK(off == len);
	free(buf);
}

static uint32_t rd32(const uint8_t *p) { uint32_t v; memcpy(&v, p, 4); return v; }
static uint64_t rd64(const uint8_t *p) { uint64_t v; memcpy(&v, p, 8); return v; }
static uint16_t rd16(const uint8_t *p) { uint16_t v; memcpy(&v, p, 2); return v; }

static void test_write_two_events_one_page(void)
{
	uint8_t *buf, *page, *ev;
	size_t len;
	uint64_t off, size;

	trace_free();
	CHECK(trace_add_at(1000000000ull, "barebox started") == 0);	/* 16 bytes incl NUL */
	CHECK(trace_add_at(1000005000ull, "kernel loaded") == 0);	/* 14 bytes incl NUL */
	CHECK(trace_write(TEST_OUT) == 0);
	buf = read_file(TEST_OUT, &len);
	CHECK(parse_header(buf, len, &off, &size) == 0);
	CHECK(size == 4096);
	CHECK(len == off + 4096);

	page = buf + off;
	CHECK(rd64(page) == 1000000000ull);		/* page timestamp */
	CHECK(rd64(page + 8) == 64);			/* commit: two 32-byte events */

	/* event 1: record = 12 + 16 = 28 bytes -> type_len 7, delta 0 */
	ev = page + 16;
	CHECK(rd32(ev) == 7u);
	CHECK(rd16(ev + 4) == 1000);			/* common_type */
	CHECK(ev[6] == 0 && ev[7] == 0);		/* flags, preempt_count */
	CHECK(rd32(ev + 8) == 1);			/* common_pid */
	CHECK(rd32(ev + 12) == (12u | (16u << 16)));	/* data_loc */
	CHECK(strcmp((const char *)ev + 16, "barebox started") == 0);

	/* event 2: record = 12 + 14 = 26 -> padded 28 -> type_len 7, delta 5000 */
	ev = page + 16 + 32;
	CHECK(rd32(ev) == (7u | (5000u << 5)));
	CHECK(rd32(ev + 12) == (12u | (14u << 16)));
	CHECK(strcmp((const char *)ev + 16, "kernel loaded") == 0);
	CHECK(ev[30] == 0 && ev[31] == 0);		/* padding is zeroed */
	free(buf);
}

static void test_write_time_extend(void)
{
	uint8_t *buf, *page, *ev;
	size_t len;
	uint64_t off, size;
	const uint64_t gap = (1ull << 28) + 5;	/* 268 ms: too big for 27 bits */

	trace_free();
	CHECK(trace_add_at(100, "a") == 0);		/* record 12+2 -> 16, event 20 */
	CHECK(trace_add_at(100 + gap, "b") == 0);
	CHECK(trace_write(TEST_OUT) == 0);
	buf = read_file(TEST_OUT, &len);
	CHECK(parse_header(buf, len, &off, &size) == 0);
	page = buf + off;
	CHECK(rd64(page + 8) == 20 + 8 + 20);		/* event, extend, event */

	ev = page + 16 + 20;				/* the time-extend record */
	CHECK((rd32(ev) & 0x1f) == 30);
	CHECK((rd32(ev) >> 5) == (uint32_t)(gap & ((1u << 27) - 1)));	/* low 27 bits = 5 */
	CHECK(rd32(ev + 4) == (uint32_t)(gap >> 27));			/* high bits = 2 */

	ev += 8;					/* the data event: delta must be 0 */
	CHECK(rd32(ev) == 4u);				/* type_len 4, delta 0 */
	CHECK(strcmp((const char *)ev + 16, "b") == 0);
	free(buf);
}

static void test_write_long_record_uses_length_word(void)
{
	char msg[151];
	uint8_t *buf, *page, *ev;
	size_t len;
	uint64_t off, size;

	memset(msg, 'x', 150);
	msg[150] = '\0';				/* len 151 -> record 163 -> 164 > 112 */

	trace_free();
	CHECK(trace_add_at(7, msg) == 0);
	CHECK(trace_write(TEST_OUT) == 0);
	buf = read_file(TEST_OUT, &len);
	CHECK(parse_header(buf, len, &off, &size) == 0);
	page = buf + off;
	ev = page + 16;
	CHECK(rd32(ev) == 0);				/* type_len 0, delta 0 */
	CHECK(rd32(ev + 4) == 164 + 4);			/* length word incl itself */
	CHECK(rd64(page + 8) == 4 + 4 + 164);		/* commit */
	CHECK(rd16(ev + 8) == 1000);
	CHECK(rd32(ev + 16) == (12u | (151u << 16)));
	CHECK(strcmp((const char *)ev + 20, msg) == 0);
	free(buf);
}

static void test_write_multi_page(void)
{
	/* 41-byte string incl NUL -> record 53 -> 56, event 60. 4080/60 = 68 per page. */
	char msg[41];
	uint8_t *buf;
	size_t len, i;
	uint64_t off, size;

	memset(msg, 'm', 40);
	msg[40] = '\0';

	trace_free();
	for (i = 0; i < 200; i++)
		CHECK(trace_add_at(i * 1000, msg) == 0);
	CHECK(trace_write(TEST_OUT) == 0);
	buf = read_file(TEST_OUT, &len);
	CHECK(parse_header(buf, len, &off, &size) == 0);
	CHECK(size == 3 * 4096);			/* 68 + 68 + 64 */
	CHECK(rd64(buf + off + 8) == 68 * 60);			/* page 0 commit */
	CHECK(rd64(buf + off + 4096) == 68 * 1000);		/* page 1 timestamp */
	CHECK(rd64(buf + off + 4096 + 8) == 68 * 60);		/* page 1 commit */
	CHECK(rd64(buf + off + 2 * 4096) == 136 * 1000);	/* page 2 timestamp */
	CHECK(rd64(buf + off + 2 * 4096 + 8) == 64 * 60);	/* page 2 commit */
	/* first event on page 1 has delta 0 relative to its page timestamp */
	CHECK(rd32(buf + off + 4096 + 16) == 14u);		/* type_len 56/4, delta 0 */
	free(buf);
}

static void test_write_too_long_is_emsgsize(void)
{
	char *msg = malloc(5001);

	CHECK(msg != NULL);
	memset(msg, 'z', 5000);
	msg[5000] = '\0';
	trace_free();
	CHECK(trace_add_at(1, msg) == 0);
	errno = 0;
	CHECK(trace_write(TEST_OUT) == -1);
	CHECK(errno == EMSGSIZE);
	free(msg);
}

static void test_write_non_monotonic_clamps_delta(void)
{
	uint8_t *buf, *ev;
	size_t len;
	uint64_t off, size;

	trace_free();
	CHECK(trace_add_at(100, "a") == 0);
	CHECK(trace_add_at(50, "b") == 0);		/* goes backwards */
	CHECK(trace_add_at(107, "c") == 0);		/* 7 ns after "a" */
	CHECK(trace_write(TEST_OUT) == 0);
	buf = read_file(TEST_OUT, &len);
	CHECK(parse_header(buf, len, &off, &size) == 0);
	CHECK(rd64(buf + off + 8) == 60);		/* no time-extend inserted */
	ev = buf + off + 16 + 20;
	CHECK(rd32(ev) == 4u);				/* "b": delta 0 */
	ev += 20;
	/* "c" is measured from the reader's clock (100), not from "b" (50) */
	CHECK(rd32(ev) == (4u | (7u << 5)));
	free(buf);
}

static void test_write_bad_path(void)
{
	trace_free();
	CHECK(trace_add_at(1, "a") == 0);
	errno = 0;
	CHECK(trace_write("/nonexistent-dir-for-tracegen/x.dat") == -1);
	CHECK(errno == ENOENT);
	errno = 0;
	CHECK(trace_write(NULL) == -1);
	CHECK(errno == EINVAL);
}

int main(void)
{
    test_add_appends_and_free_resets();
    test_add_null_is_einval();
    test_add_at_appends();
    test_write_empty_list();
    test_write_two_events_one_page();
    test_write_time_extend();
    test_write_long_record_uses_length_word();
    test_write_multi_page();
    test_write_too_long_is_emsgsize();
    test_write_non_monotonic_clamps_delta();
    test_write_bad_path();
    printf("all tests passed\n");
    return 0;
}
