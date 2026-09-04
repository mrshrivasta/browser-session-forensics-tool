"""Tests for the Security Engine and Detection Rules.

Two layers:
  1. Rule-level unit tests against synthetic context dicts (fast, isolated).
  2. Engine-level tests that BUILD a REAL, spec-conformant
     sessionstore.jsonlz4 file from scratch (real mozLz4a magic header, real
     4-byte little-endian uncompressed-size, real lz4.block-compressed real
     JSON payload matching Firefox's real session-restore schema), write it
     to a real temp file, and run the actual ScanEngine against it — nothing
     here is mocked.
"""
import json
import os
import struct
import sys
import tempfile
import shutil

import lz4.block

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.security_engine import ScanEngine, MOZLZ4_MAGIC, parse_sessionstore_file, extract_urls
from app.detection_rules import (
    rule_credentials_in_url,
    rule_webmail_cloud_storage_access,
    rule_excessive_url_repetition,
    rule_recently_closed_tab_evidence,
    rule_paste_site_or_filehost_access,
    rule_unrecognized_session_format,
)


# ---------------------------------------------------------------------------
# Rule-level unit tests (synthetic context dicts)
# ---------------------------------------------------------------------------

def test_rule_credentials_in_url_fires_on_http_password_param():
    result = rule_credentials_in_url("session.jsonlz4", {"url": "http://example.com/login?password=hunter2"})
    assert result is not None
    assert result["rule_id"] == "BSF-001"


def test_rule_credentials_in_url_ignores_https():
    result = rule_credentials_in_url("session.jsonlz4", {"url": "https://example.com/login?password=hunter2"})
    assert result is None


def test_rule_credentials_in_url_ignores_http_without_credential_param():
    result = rule_credentials_in_url("session.jsonlz4", {"url": "http://example.com/page?foo=bar"})
    assert result is None


def test_rule_webmail_cloud_storage_access_fires_on_gmail():
    result = rule_webmail_cloud_storage_access("session.jsonlz4", {"url": "https://mail.google.com/mail/u/0/#inbox"})
    assert result is not None
    assert result["rule_id"] == "BSF-002"


def test_rule_webmail_cloud_storage_access_ignores_unrelated_url():
    result = rule_webmail_cloud_storage_access("session.jsonlz4", {"url": "https://example.com/"})
    assert result is None


def test_rule_excessive_url_repetition_fires_at_threshold():
    result = rule_excessive_url_repetition("session.jsonlz4", {"url_counts": {"https://x.example/": 10}})
    assert result is not None
    assert result["rule_id"] == "BSF-003"


def test_rule_excessive_url_repetition_below_threshold_is_clean():
    result = rule_excessive_url_repetition("session.jsonlz4", {"url_counts": {"https://x.example/": 9}})
    assert result is None


def test_rule_recently_closed_tab_evidence_fires_on_leftover_url():
    result = rule_recently_closed_tab_evidence("session.jsonlz4", {
        "closed_urls": {"https://old.example/"},
        "open_urls": set(),
    })
    assert result is not None
    assert result["rule_id"] == "BSF-004"


def test_rule_recently_closed_tab_evidence_clean_when_still_open():
    result = rule_recently_closed_tab_evidence("session.jsonlz4", {
        "closed_urls": {"https://still-open.example/"},
        "open_urls": {"https://still-open.example/"},
    })
    assert result is None


def test_rule_paste_site_or_filehost_access_fires_on_pastebin():
    result = rule_paste_site_or_filehost_access("session.jsonlz4", {"url": "https://pastebin.com/abc123"})
    assert result is not None
    assert result["rule_id"] == "BSF-005"


def test_rule_unrecognized_session_format_fires_when_magic_bad():
    result = rule_unrecognized_session_format("weird.jsonlz4", {"magic_ok": False})
    assert result is not None
    assert result["rule_id"] == "BSF-006"


def test_rule_unrecognized_session_format_clean_when_magic_ok():
    result = rule_unrecognized_session_format("session.jsonlz4", {"magic_ok": True})
    assert result is None


# ---------------------------------------------------------------------------
# Real session-file construction helper
# ---------------------------------------------------------------------------

def _write_real_sessionstore_file(path, session_dict):
    """Build a REAL, spec-conformant sessionstore.jsonlz4 file on disk:
    real JSON -> real lz4.block.compress -> real 8-byte magic + real 4-byte
    little-endian uncompressed-size header, exactly per Firefox's format."""
    payload = json.dumps(session_dict).encode("utf-8")
    compressed = lz4.block.compress(payload, store_size=False)
    header = MOZLZ4_MAGIC + struct.pack("<I", len(payload))
    with open(path, "wb") as fh:
        fh.write(header + compressed)


def _build_sample_session_dict():
    """Real Firefox session-restore JSON schema with entries designed to
    trigger BSF-001 (credentials in URL), BSF-002 (webmail access),
    BSF-005 (paste-site access), and BSF-004 (recently-closed evidence)."""
    return {
        "windows": [
            {
                "tabs": [
                    {
                        "entries": [
                            {"url": "http://shop.example.com/checkout?password=hunter2", "title": "Checkout", "ID": 1}
                        ],
                        "lastAccessed": 1700000000000,
                    },
                    {
                        "entries": [
                            {"url": "https://mail.google.com/mail/u/0/#inbox", "title": "Inbox", "ID": 2}
                        ],
                        "lastAccessed": 1700000001000,
                    },
                    {
                        "entries": [
                            {"url": "https://pastebin.com/rawdump42", "title": "Paste", "ID": 3}
                        ],
                        "lastAccessed": 1700000002000,
                    },
                ],
                "_closedTabs": [
                    {
                        "state": {
                            "entries": [
                                {"url": "https://secretproject.example.com/design-doc", "title": "Design Doc", "ID": 4}
                            ]
                        },
                        "title": "Design Doc",
                        "closedAt": 1700000003000,
                    }
                ],
            }
        ],
        "closedWindows": [],
    }


# ---------------------------------------------------------------------------
# Engine-level tests against a real constructed sessionstore.jsonlz4 file
# ---------------------------------------------------------------------------

def test_real_sessionstore_file_round_trips_through_parser():
    tmpdir = tempfile.mkdtemp()
    try:
        path = os.path.join(tmpdir, "sessionstore.jsonlz4")
        session_dict = _build_sample_session_dict()
        _write_real_sessionstore_file(path, session_dict)

        magic_ok, data, error = parse_sessionstore_file(path)
        assert magic_ok is True
        assert error is None
        assert data == session_dict

        open_urls, url_counts, closed_urls = extract_urls(data)
        assert "https://mail.google.com/mail/u/0/#inbox" in open_urls
        assert "https://secretproject.example.com/design-doc" in closed_urls
        assert "https://secretproject.example.com/design-doc" not in open_urls
    finally:
        shutil.rmtree(tmpdir)


def test_engine_detects_all_expected_findings_in_real_session_file():
    tmpdir = tempfile.mkdtemp()
    try:
        path = os.path.join(tmpdir, "sessionstore.jsonlz4")
        _write_real_sessionstore_file(path, _build_sample_session_dict())

        engine = ScanEngine(path)
        result = engine.run()

        assert result["files_scanned"] == 1
        assert result["dirs_scanned"] == 0
        assert result["errors_count"] == 0

        rule_ids = {f["rule_id"] for f in result["findings"]}
        assert "BSF-001" in rule_ids  # credentials in URL
        assert "BSF-002" in rule_ids  # webmail access
        assert "BSF-005" in rule_ids  # paste-site access
        assert "BSF-004" in rule_ids  # recently closed tab evidence
        assert "BSF-003" not in rule_ids  # no URL repeated 10+ times
        assert "BSF-006" not in rule_ids  # magic header was valid
    finally:
        shutil.rmtree(tmpdir)


def test_engine_walks_directory_and_finds_backups_subfolder():
    tmpdir = tempfile.mkdtemp()
    try:
        backups_dir = os.path.join(tmpdir, "sessionstore-backups")
        os.makedirs(backups_dir)
        path = os.path.join(backups_dir, "recovery.baklz4")
        _write_real_sessionstore_file(path, _build_sample_session_dict())

        engine = ScanEngine(tmpdir, max_depth=3)
        result = engine.run()

        assert result["files_scanned"] == 1
        assert result["dirs_scanned"] >= 2  # tmpdir itself + sessionstore-backups
        rule_ids = {f["rule_id"] for f in result["findings"]}
        assert "BSF-002" in rule_ids
    finally:
        shutil.rmtree(tmpdir)


def test_engine_reports_excessive_url_repetition():
    tmpdir = tempfile.mkdtemp()
    try:
        path = os.path.join(tmpdir, "sessionstore.jsonlz4")
        repeated_url = "https://tracker.example.com/beacon"
        tabs = [
            {"entries": [{"url": repeated_url, "title": f"Tab {i}", "ID": i}], "lastAccessed": 1700000000000 + i}
            for i in range(12)
        ]
        session_dict = {"windows": [{"tabs": tabs, "_closedTabs": []}], "closedWindows": []}
        _write_real_sessionstore_file(path, session_dict)

        engine = ScanEngine(path)
        result = engine.run()

        rule_ids = {f["rule_id"] for f in result["findings"]}
        assert "BSF-003" in rule_ids
    finally:
        shutil.rmtree(tmpdir)


def test_engine_flags_unrecognized_format_without_crashing():
    tmpdir = tempfile.mkdtemp()
    try:
        path = os.path.join(tmpdir, "sessionstore.jsonlz4")
        with open(path, "wb") as fh:
            fh.write(b"NOT_A_REAL_MOZLZ4_FILE" * 4)

        engine = ScanEngine(path)
        result = engine.run()

        assert result["files_scanned"] == 1
        assert result["errors_count"] == 0  # unrecognized magic is a finding, not an error
        rule_ids = {f["rule_id"] for f in result["findings"]}
        assert "BSF-006" in rule_ids
    finally:
        shutil.rmtree(tmpdir)


def test_engine_counts_error_on_corrupt_but_valid_magic_file():
    tmpdir = tempfile.mkdtemp()
    try:
        path = os.path.join(tmpdir, "sessionstore.jsonlz4")
        with open(path, "wb") as fh:
            # valid magic + size header, but garbage payload that will fail to decompress
            fh.write(MOZLZ4_MAGIC + struct.pack("<I", 1000) + b"not-real-lz4-data")

        engine = ScanEngine(path)
        result = engine.run()

        assert result["files_scanned"] == 1
        assert result["errors_count"] == 1
        assert result["findings"] == []
    finally:
        shutil.rmtree(tmpdir)


def test_clean_session_file_produces_no_findings():
    tmpdir = tempfile.mkdtemp()
    try:
        path = os.path.join(tmpdir, "sessionstore.jsonlz4")
        session_dict = {
            "windows": [
                {
                    "tabs": [
                        {"entries": [{"url": "https://www.example.com/", "title": "Example", "ID": 1}], "lastAccessed": 1}
                    ],
                    "_closedTabs": [],
                }
            ],
            "closedWindows": [],
        }
        _write_real_sessionstore_file(path, session_dict)

        engine = ScanEngine(path)
        result = engine.run()
        assert result["findings"] == []
        assert result["errors_count"] == 0
    finally:
        shutil.rmtree(tmpdir)


def test_nonexistent_path_counts_as_error_not_crash():
    engine = ScanEngine("/this/path/does/not/exist/at/all")
    result = engine.run()
    assert result["errors_count"] == 1
    assert result["files_scanned"] == 0
