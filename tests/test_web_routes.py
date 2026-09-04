import json
import os
import struct
import tempfile
import shutil

import lz4.block

from app.security_engine import MOZLZ4_MAGIC


def _write_real_sessionstore_file(path):
    """Build a REAL, spec-conformant sessionstore.jsonlz4 file (real JSON,
    real lz4.block compression, real mozLz4a header) with an entry that
    triggers a real finding (BSF-002: webmail access)."""
    session_dict = {
        "windows": [
            {
                "tabs": [
                    {
                        "entries": [
                            {"url": "https://mail.google.com/mail/u/0/#inbox", "title": "Inbox", "ID": 1}
                        ],
                        "lastAccessed": 1700000000000,
                    }
                ],
                "_closedTabs": [],
            }
        ],
        "closedWindows": [],
    }
    payload = json.dumps(session_dict).encode("utf-8")
    compressed = lz4.block.compress(payload, store_size=False)
    header = MOZLZ4_MAGIC + struct.pack("<I", len(payload))
    with open(path, "wb") as fh:
        fh.write(header + compressed)


def test_full_scan_alert_incident_workflow(registered_client):
    tmpdir = tempfile.mkdtemp()
    try:
        session_path = os.path.join(tmpdir, "sessionstore.jsonlz4")
        _write_real_sessionstore_file(session_path)

        # Run a real scan against a real, freshly-built sessionstore.jsonlz4 file
        resp = registered_client.post("/scan/run", data={"target_path": session_path}, follow_redirects=True)
        assert resp.status_code == 200
        assert b"Scan complete" in resp.data

        # Logs page should show at least one scan
        resp = registered_client.get("/logs")
        assert session_path.encode() in resp.data

        # Alerts page should load (a medium-severity BSF-002 finding should have alerted)
        resp = registered_client.get("/alerts")
        assert resp.status_code == 200

        # Analytics JSON endpoint returns real aggregated data
        resp = registered_client.get("/analytics/data")
        assert resp.status_code == 200
        assert resp.is_json

        # Reports CSV export works
        resp = registered_client.get("/reports/export.csv")
        assert resp.status_code == 200
        assert resp.headers["Content-Type"].startswith("text/csv")
        assert b"BSF-002" in resp.data
    finally:
        shutil.rmtree(tmpdir)


def test_settings_page_round_trip(registered_client):
    resp = registered_client.post("/settings", data={
        "default_scan_path": "/tmp",
        "scan_depth_limit": "3",
        "exclude_paths": "/proc,/sys",
        "alert_on_severity": "high",
    }, follow_redirects=True)
    assert b"Settings saved" in resp.data

    resp = registered_client.get("/settings")
    assert b"/tmp" in resp.data


def test_all_nav_pages_load(registered_client):
    for path in ["/", "/logs", "/alerts", "/incidents", "/analytics", "/reports", "/settings"]:
        resp = registered_client.get(path)
        assert resp.status_code == 200, f"{path} failed with {resp.status_code}"


def test_404_page(registered_client):
    resp = registered_client.get("/this-page-does-not-exist")
    assert resp.status_code == 404
