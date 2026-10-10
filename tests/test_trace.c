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

/* ================================================================== */
/* Perfetto writer tests                                              */
/* ================================================================== */

#define TEST_OUT_PF "tests/out.pftrace"

/* wire types */
#define W_VARINT 0u
#define W_LEN    2u

/* TrackEvent.Type */
#define TE_SLICE_BEGIN 1u
#define TE_SLICE_END   2u
#define TE_INSTANT     3u

/* One decoded protobuf field. */
struct pfield {
    unsigned num;
    unsigned wire;
    uint64_t v;         /* wire == W_VARINT */
    const uint8_t *p;   /* wire == W_LEN */
    size_t n;
};

/* Read a base-128 varint; advance *pp past it. */
static int rd_varint(const uint8_t **pp, const uint8_t *end, uint64_t *out)
{
    const uint8_t *p = *pp;
    uint64_t v = 0;
    unsigned shift = 0;

    while (p < end && shift <= 63) {
        v |= (uint64_t)(*p & 0x7f) << shift;
        if (!(*p & 0x80)) {
            *pp = p + 1;
            *out = v;
            return 0;
        }
        p++;
        shift += 7;
    }
    return -1;
}

/* Parse the next field in [p, end). Only varints and length-delimited
 * fields exist in what the writer emits. Returns 1 at the clean end of
 * the message, -1 on malformed input. */
static int pbf_next(const uint8_t **pp, const uint8_t *end, struct pfield *f)
{
    const uint8_t *p = *pp;
    uint64_t key;

    if (p == end)
        return 1;
    if (rd_varint(&p, end, &key) < 0)
        return -1;
    f->num = (unsigned)(key >> 3);
    f->wire = (unsigned)(key & 7);
    if (f->wire == W_VARINT) {
        if (rd_varint(&p, end, &f->v) < 0)
            return -1;
    } else if (f->wire == W_LEN) {
        uint64_t n;

        if (rd_varint(&p, end, &n) < 0 || (uint64_t)(end - p) < n)
            return -1;
        f->p = p;
        f->n = (size_t)n;
        p += n;
    } else {
        return -1;
    }
    *pp = p;
    return 0;
}

/* The parts of one framed TracePacket the tests care about. */
struct pfpacket {
    int has_clock_snapshot;
    int has_track_event;
    int has_track_descriptor;
    int has_ts;
    uint64_t ts;            /* field 8 */
    uint64_t seq_id;        /* field 10 */
    uint64_t clock_id;      /* field 58 */
    uint64_t seq_flags;     /* field 13 */
    uint64_t td_uuid;       /* TrackDescriptor.uuid */
    char td_name[64];       /* TrackDescriptor.name */
    uint64_t te_type;       /* TrackEvent.type */
    uint64_t te_track;      /* TrackEvent.track_uuid */
    char te_name[256];      /* TrackEvent.name */
    int te_has_name;
};

/* Copy a length-delimited field into a char[] of size sz. */
static void copy_str(char *dst, size_t sz, const struct pfield *f)
{
    CHECK(f->n < sz);
    memcpy(dst, f->p, f->n);
    dst[f->n] = '\0';
}

/*
 * Decode the next framed packet in the Trace stream at *pp.
 * Returns 0 and fills *o; 1 at end of buffer; -1 on malformed input.
 */
static int pf_next(const uint8_t **pp, const uint8_t *end, struct pfpacket *o)
{
    const uint8_t *p = *pp, *sub_end, *q;
    struct pfield f, sf;
    int r;

    memset(o, 0, sizeof *o);
    if (p == end)
        return 1;
    if (pbf_next(&p, end, &f) < 0 || f.num != 1 || f.wire != W_LEN)
        return -1;                      /* every packet is field 1, LEN */
    sub_end = f.p + f.n;
    p = f.p;                            /* iterate the packet's own fields */
    while ((r = pbf_next(&p, sub_end, &f)) == 0) {
        switch (f.num) {
        case 8:
            o->has_ts = 1;
            o->ts = f.v;
            break;
        case 10:
            o->seq_id = f.v;
            break;
        case 13:
            o->seq_flags = f.v;
            break;
        case 58:
            o->clock_id = f.v;
            break;
        case 6:
            o->has_clock_snapshot = 1;
            break;
        case 11:                        /* track_event */
            o->has_track_event = 1;
            q = f.p;
            while ((r = pbf_next(&q, sub_end, &sf)) == 0) {
                if (sf.num == 9 && sf.wire == W_VARINT)
                    o->te_type = sf.v;
                else if (sf.num == 11 && sf.wire == W_VARINT)
                    o->te_track = sf.v;
                else if (sf.num == 23 && sf.wire == W_LEN) {
                    copy_str(o->te_name, sizeof o->te_name, &sf);
                    o->te_has_name = 1;
                }
            }
            if (r < 0)
                return -1;
            break;
        case 60:                        /* track_descriptor */
            o->has_track_descriptor = 1;
            q = f.p;
            while ((r = pbf_next(&q, sub_end, &sf)) == 0) {
                if (sf.num == 1 && sf.wire == W_VARINT)
                    o->td_uuid = sf.v;
                else if (sf.num == 2 && sf.wire == W_LEN)
                    copy_str(o->td_name, sizeof o->td_name, &sf);
            }
            if (r < 0)
                return -1;
            break;
        default:
            break;
        }
    }
    if (r < 0)
        return -1;
    *pp = sub_end;
    return 0;
}

/* Assert that pk is a TrackEvent with the expected contents. */
static void check_ev(const struct pfpacket *pk, uint64_t ts, unsigned type,
                     uint64_t track, const char *name)
{
    CHECK(pk->has_track_event);
    CHECK(pk->has_ts);
    CHECK(pk->ts == ts);
    CHECK(pk->seq_id == 1u);               /* trusted_packet_sequence_id */
    CHECK(pk->clock_id == 3u);          /* BuiltinClock MONOTONIC */
    CHECK(pk->te_type == type);
    CHECK(pk->te_track == track);
    if (name) {
        CHECK(pk->te_has_name);
        CHECK(strcmp(pk->te_name, name) == 0);
    } else {
        CHECK(!pk->te_has_name);
    }
}

static void test_perfetto_empty_list(void)
{
    uint8_t *buf;
    size_t len;
    const uint8_t *p;
    struct pfpacket pk;

    trace_free();
    CHECK(trace_write_perfetto(TEST_OUT_PF) == 0);
    buf = read_file(TEST_OUT_PF, &len);
    p = buf;

    CHECK(pf_next(&p, buf + len, &pk) == 0);    /* clock snapshot */
    CHECK(pk.has_clock_snapshot);
    CHECK(pk.seq_flags == 1u);                  /* incremental state cleared */
    CHECK(pk.seq_id == 1u);                     /* one writer sequence */
    CHECK(pf_next(&p, buf + len, &pk) == 0);    /* track 1: tasks */
    CHECK(pk.has_track_descriptor);
    CHECK(pk.td_uuid == 1u);
    CHECK(strcmp(pk.td_name, "barebox tasks") == 0);
    CHECK(pf_next(&p, buf + len, &pk) == 0);    /* track 2: stages */
    CHECK(pk.td_uuid == 2u);
    CHECK(strcmp(pk.td_name, "barebox stages") == 0);
    CHECK(pf_next(&p, buf + len, &pk) == 1);    /* exactly three packets */
    free(buf);
}

static void test_perfetto_two_events(void)
{
    uint8_t *buf;
    size_t len;
    const uint8_t *p;
    struct pfpacket pk;

    trace_free();
    CHECK(trace_add_at(1000000000ull, "barebox started") == 0);
    CHECK(trace_add_at(1000005000ull, "kernel loaded") == 0);
    CHECK(trace_write_perfetto(TEST_OUT_PF) == 0);
    buf = read_file(TEST_OUT_PF, &len);
    p = buf;

    /* skip the three header packets (clock snapshot + two descriptors) */
    CHECK(pf_next(&p, buf + len, &pk) == 0);
    CHECK(pf_next(&p, buf + len, &pk) == 0);
    CHECK(pf_next(&p, buf + len, &pk) == 0);

    /* stage 1 opens its slice and marks the instant */
    CHECK(pf_next(&p, buf + len, &pk) == 0);
    check_ev(&pk, 1000000000ull, TE_SLICE_BEGIN, 2u, "barebox started");
    CHECK(pf_next(&p, buf + len, &pk) == 0);
    check_ev(&pk, 1000000000ull, TE_INSTANT, 1u, "barebox started");

    /* stage 2: previous slice ends (before the new one begins), then
     * begin + instant, then the final slice end at the same timestamp */
    CHECK(pf_next(&p, buf + len, &pk) == 0);
    check_ev(&pk, 1000005000ull, TE_SLICE_END, 2u, NULL);
    CHECK(pf_next(&p, buf + len, &pk) == 0);
    check_ev(&pk, 1000005000ull, TE_SLICE_BEGIN, 2u, "kernel loaded");
    CHECK(pf_next(&p, buf + len, &pk) == 0);
    check_ev(&pk, 1000005000ull, TE_INSTANT, 1u, "kernel loaded");
    CHECK(pf_next(&p, buf + len, &pk) == 0);
    check_ev(&pk, 1000005000ull, TE_SLICE_END, 2u, NULL);

    CHECK(pf_next(&p, buf + len, &pk) == 1);    /* no further packets */
    free(buf);
}

static void test_perfetto_bad_path(void)
{
    trace_free();
    CHECK(trace_add_at(1, "a") == 0);
    errno = 0;
    CHECK(trace_write_perfetto("/nonexistent-dir-for-tracegen/x.pftrace") == -1);
    CHECK(errno == ENOENT);
    errno = 0;
    CHECK(trace_write_perfetto(NULL) == -1);
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
    test_perfetto_empty_list();
    test_perfetto_two_events();
    test_perfetto_bad_path();
    printf("all tests passed\n");
    return 0;
}
