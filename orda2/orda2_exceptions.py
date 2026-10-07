#!/usr/bin/env python3
"""Declared non-conforming segment registry for the chain-verify path.

A non-conforming segment is an event whose recorded ``hash`` can never
equal ``event_hash(prev, event)`` under this tool's algorithm — the
characteristic shape is an append primitive written by a different author
that hashed a different view of the same bytes — while its link fields
(``seq`` position, ``prev_hash``) are intact.

Such an event is verifiable-by-pin: the registry records the exact
recorded hash AND an independent digest of the recorded body bytes, so
verify can tell "known non-conforming bytes, unchanged" apart from
"bytes rewritten after the fact".

Constraints:
- Source-level constant. No CLI flag, environment variable, or config
  file can widen it; adding an entry costs a source edit plus review.
- Never large. One entry per known-bad seq, exact hash match required —
  no ranges, no prefixes.
- Never replaces restore. It excuses exactly the recorded hash of the
  listed seqs; any body rewrite still fails, and it never rebuilds data.
"""
import hashlib
import json

# seq -> {"hash": <recorded chain hash>, "body_sha256": <body digest>}
# Empty by default: with no entries verify behaves exactly as before.
NONCONFORMING_SEGMENTS: dict = {}


def body_sha256(event):
    """sha256 of the canonical payload-minus-hash blob.

    Canonical form: ``json.dumps(payload_minus_hash, sort_keys=True,
    separators=(',', ':'))`` encoded as UTF-8.
    """
    payload = dict(event)
    payload.pop("hash", None)
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode()).hexdigest()
