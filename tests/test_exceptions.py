"""Exception-registry + body-pin tests for the chain-verify path.

Covers:
  - declared exception + matching bytes -> verify ok, exception reported
  - declared exception + rewritten body (hash copied) -> pinned body mismatch
  - undeclared tamper -> existing tamper problem (unchanged behavior)
  - empty registry -> behavior unchanged (no exceptions, no problems)
  - canonical body-digest snapshot (payload-minus-hash blob)
  - Store.verify / CLI verify report shape carries "exceptions", exit 0
"""
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import shutil

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from orda2.orda2_events import ZERO_HASH, event_hash, verify_chain, write_events
from orda2.orda2_exceptions import NONCONFORMING_SEGMENTS, body_sha256
from orda2.orda2_store import Store

ROOT = os.path.join(os.path.dirname(__file__), "..")


def run(args, cwd=None):
    return subprocess.run(args, cwd=cwd, capture_output=True, text=True)


def _event(seq, prev_hash, writer="tester", note="note", kind="note"):
    ev = {
        "seq": seq,
        "prev_hash": prev_hash,
        "revision": seq,
        "ts": "2026-10-07T00:00:0%dZ" % seq,
        "writer": writer,
        "kind": kind,
        "project": None,
        "note": note,
    }
    tmp = dict(ev)
    ev["hash"] = event_hash(prev_hash, tmp)
    return ev


def make_chain_with_gap():
    """Three-event chain where seq 2 is non-conforming by construction.

    seq 2 carries a recorded hash that is NOT event_hash(prev, event)
    (as if a foreign append primitive hashed a different view of the
    bytes); seq 3 links onto seq 2's recorded hash normally.
    """
    e1 = _event(1, ZERO_HASH, note="first")
    e2 = _event(2, e1["hash"], note="foreign-append bytes")
    recorded = "f" * 64
    assert recorded != e2["hash"]
    e2["hash"] = recorded
    e3 = _event(3, recorded, note="third")
    return [e1, e2, e3]


def declare(monkeypatch, events, seq):
    target = next(e for e in events if e["seq"] == seq)
    monkeypatch.setitem(
        NONCONFORMING_SEGMENTS,
        seq,
        {"hash": target["hash"], "body_sha256": body_sha256(target)},
    )
    return target


def test_declared_exception_matching_bytes_verify_ok(monkeypatch):
    events = make_chain_with_gap()
    declare(monkeypatch, events, 2)
    problems, exceptions = verify_chain(events)
    assert problems == []
    assert exceptions == ["seq 2: declared non-conforming segment"]


def test_declared_exception_rewritten_body_pinned_mismatch(monkeypatch):
    events = make_chain_with_gap()
    declare(monkeypatch, events, 2)
    # rewrite the body but copy the pinned recorded hash
    events[1]["note"] = "rewritten after the fact"
    problems, exceptions = verify_chain(events)
    assert exceptions == []
    assert any("seq 2: pinned body mismatch" in p for p in problems)


def test_undeclared_tamper_still_hash_mismatch():
    events = make_chain_with_gap()
    # no registry entry anywhere: seq 2's foreign hash is plain tamper
    problems, exceptions = verify_chain(events)
    assert exceptions == []
    assert any("hash mismatch" in p for p in problems)


def test_empty_registry_intact_chain_unchanged():
    e1 = _event(1, ZERO_HASH, note="first")
    e2 = _event(2, e1["hash"], note="second")
    problems, exceptions = verify_chain([e1, e2])
    assert problems == []
    assert exceptions == []


def test_body_digest_canonical_snapshot():
    event = _event(1, ZERO_HASH, note="snapshot")
    payload_minus_hash = {k: v for k, v in event.items() if k != "hash"}
    canonical = json.dumps(payload_minus_hash, sort_keys=True, separators=(",", ":"))
    expected = hashlib.sha256(canonical.encode()).hexdigest()
    assert body_sha256(event) == expected


def _store_home_with(events):
    home = tempfile.mkdtemp()
    run(["git", "init", "-b", "main"], cwd=home)
    run(["git", "config", "user.email", "orda2@local"], cwd=home)
    run(["git", "config", "user.name", "orda2"], cwd=home)
    write_events(os.path.join(home, "events.jsonl"), events)
    last_rev = events[-1]["revision"] if events else 0
    with open(os.path.join(home, "state.json"), "w") as f:
        json.dump({"revision": last_rev, "projects": {}}, f)
    return home


def test_store_verify_reports_exceptions_and_stays_ok(monkeypatch):
    events = make_chain_with_gap()
    declare(monkeypatch, events, 2)
    home = _store_home_with(events)
    try:
        report = Store(home).verify()
        assert report["ok"] is True
        assert report["problems"] == []
        assert report["exceptions"] == ["seq 2: declared non-conforming segment"]
        assert report["events"] == 3
    finally:
        shutil.rmtree(home, ignore_errors=True)


def test_cli_verify_shape_carries_exceptions_key():
    e1 = _event(1, ZERO_HASH, note="first")
    e2 = _event(2, e1["hash"], note="second")
    home = _store_home_with([e1, e2])
    try:
        r = run(
            [sys.executable, "-m", "orda2.orda2_cli", "verify", "--home", home],
            cwd=ROOT,
        )
        assert r.returncode == 0, r.stdout + r.stderr
        out = json.loads(r.stdout)
        assert out.get("ok") is True
        assert out.get("exceptions") == []
    finally:
        shutil.rmtree(home, ignore_errors=True)
