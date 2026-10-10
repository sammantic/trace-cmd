#!/usr/bin/env python3
"""Independently decode a .pftrace written by tracegen and sanity-check it.

Usage: check_pfetto.py TRACE.pftrace

Decodes the protobuf wire format by hand (varints and length-delimited
fields are all the trace uses) and asserts the packet sequence tracegen
produces: one clock snapshot, two track descriptors, then per recorded
message a slice begin, an instant, and slice ends at the next message's
timestamp.
"""

import sys

W_VARINT, W_LEN = 0, 2
TYPE_BEGIN, TYPE_END, TYPE_INSTANT = 1, 2, 3


def rd_varint(buf, pos):
    v, shift = 0, 0
    while True:
        b = buf[pos]
        pos += 1
        v |= (b & 0x7F) << shift
        if not b & 0x80:
            return v, pos
        shift += 7


def fields(buf):
    """Yield (field number, wire type, value/bytes) for each field."""
    pos = 0
    while pos < len(buf):
        key, pos = rd_varint(buf, pos)
        num, wire = key >> 3, key & 7
        if wire == W_VARINT:
            val, pos = rd_varint(buf, pos)
        elif wire == W_LEN:
            n, pos = rd_varint(buf, pos)
            val = buf[pos:pos + n]
            assert len(val) == n, "length-delimited field overruns buffer"
            pos += n
        else:
            raise AssertionError(f"unsupported wire type {wire}")
        yield num, wire, val


def packets(buf):
    """Yield the framed TracePackets of the trace stream."""
    pos = 0
    while pos < len(buf):
        key, pos = rd_varint(buf, pos)
        assert key == 0x0A, f"expected Trace.packet, got key {key:#x}"
        n, pos = rd_varint(buf, pos)
        pkt = buf[pos:pos + n]
        assert len(pkt) == n, "packet framing overruns file"
        pos += n
        yield pkt


def subfields_of(pkt, num):
    """Yield the sub-message bytes of each occurrence of field num."""
    for fnum, _wire, val in fields(pkt):
        if fnum == num:
            yield val


def track_event(pkt):
    for ev_bytes in subfields_of(pkt, 11):
        ev = {}
        for fnum, _wire, val in fields(ev_bytes):
            if fnum == 9:
                ev["type"] = val
            elif fnum == 11:
                ev["track"] = val
            elif fnum == 23:
                ev["name"] = val.decode()
        return ev
    return None


def track_descriptor(pkt):
    for td_bytes in subfields_of(pkt, 60):
        td = {}
        for fnum, _wire, val in fields(td_bytes):
            if fnum == 1:
                td["uuid"] = val
            elif fnum == 2:
                td["name"] = val.decode()
        return td
    return None


def packet_ts(pkt):
    ts = clock_id = seq_id = None
    for num, _wire, val in fields(pkt):
        if num == 8:
            ts = val
        elif num == 10:
            seq_id = val
        elif num == 58:
            clock_id = val
    return ts, clock_id, seq_id


def main():
    with open(sys.argv[1], "rb") as f:
        buf = f.read()
    pkts = list(packets(buf))

    # header: clock snapshot, then the two track descriptors
    clocks, primary = [], None
    for num, _wire, val in fields(pkts[0]):
        if num != 6:
            continue
        for fnum, _fw, sub in fields(val):
            if fnum == 1:                   # repeated Clock, length-delimited
                cid = ts_val = None
                for cnum, _cw, cval in fields(sub):
                    if cnum == 1:
                        cid = cval
                    elif cnum == 2:
                        ts_val = cval
                assert cid is not None and ts_val is not None, "empty clock"
                clocks.append((cid, ts_val))
            elif fnum == 2:                 # primary_trace_clock, varint
                primary = sub
    ids = sorted(c for c, _t in clocks)
    assert ids == [1, 3, 6], f"clock ids {ids}, want REALTIME/MONOTONIC/BOOTTIME"
    by_id = dict(clocks)
    assert by_id[6] >= by_id[3], "BOOTTIME before MONOTONIC"
    assert by_id[1] > by_id[3], "REALTIME before MONOTONIC (host booted before 1970?)"
    assert primary == 3, "trace clock is not CLOCK_MONOTONIC"
    tracks = [track_descriptor(p) for p in pkts[1:3]]
    assert tracks[0] == {"uuid": 1, "name": "barebox tasks"}, tracks[0]
    assert tracks[1] == {"uuid": 2, "name": "barebox stages"}, tracks[1]

    events = []
    for p in pkts[3:]:
        ts, clock_id, seq_id = packet_ts(p)
        ev = track_event(p)
        assert ev is not None, "unexpected non-event packet after header"
        assert clock_id == 3, "event not in the CLOCK_MONOTONIC domain"
        assert seq_id == 1, "packet without trusted_packet_sequence_id"
        events.append((ts, ev))

    by_type = {t: [e for e in events if e[1]["type"] == t]
               for t in (TYPE_BEGIN, TYPE_END, TYPE_INSTANT)}
    begins, ends, instants = (by_type[TYPE_BEGIN], by_type[TYPE_END],
                              by_type[TYPE_INSTANT])
    assert len(begins) == len(ends) == len(instants) >= 1, (
        f"{len(begins)} begins, {len(ends)} ends, {len(instants)} instants")
    assert all(e[1]["name"] for e in begins), "slice without a name"

    # each message is one instant on track 1 mirroring its slice begin
    for (bts, b), (its, i) in zip(begins, instants):
        assert bts == its, "instant and slice begin disagree on time"
        assert b["name"] == i["name"]
        assert i["track"] == 1
        assert b["track"] == 2

    # slice k spans [ts_k, ts_{k+1}); the last one ends where it began
    for k, (bts, _b) in enumerate(begins):
        assert ends[k][1]["track"] == 2
        if k + 1 < len(begins):
            assert ends[k][0] == begins[k + 1][0], "slice end != next begin"
            assert ends[k][0] > bts, "timestamps went backwards"
        else:
            assert ends[k][0] == bts, "last slice must have duration 0"

    # file order: begin+instant for the first message, then for each
    # following one end+begin+instant, finally the zero-length end of the
    # last slice
    expected = [TYPE_BEGIN, TYPE_INSTANT]
    expected += [TYPE_END, TYPE_BEGIN, TYPE_INSTANT] * (len(begins) - 1)
    expected.append(TYPE_END)
    actual = [e[1]["type"] for e in events]
    assert actual == expected, f"unexpected event sequence: {actual}"

    print(f"check_pfetto: OK ({len(instants)} messages, {len(begins)} slices)")


if __name__ == "__main__":
    main()
