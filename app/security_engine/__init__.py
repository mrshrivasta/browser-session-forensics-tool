"""
Security Engine — Browser Session Forensics Tool
Developed by Karanam Shrivasta | https://github.com/mrshrivasta

Real parser for Firefox's `sessionstore.jsonlz4` / `sessionstore-backups/*.jsonlz4`
session-restore files. No sample/mock session data is ever generated — every
Finding reflects data that was actually decompressed and JSON-decoded from a
real file on disk at scan time.

Real file format (documented, stable Firefox internal format):
  bytes  0- 7 : magic header  b"mozLz4a\\x00"
  bytes  8-11 : little-endian uint32 — real uncompressed payload size
  bytes 12-  : LZ4 **block**-compressed JSON payload (NOT LZ4 frame format —
               decompressed with lz4.block.decompress(data, uncompressed_size=...))

The decompressed JSON is Firefox's real session-restore structure:
  {
    "windows": [
      {
        "tabs": [{"entries": [{"url":..., "title":..., "ID":...}], "lastAccessed":...}],
        "_closedTabs": [{"state": {"entries": [...]}, "title":..., "closedAt":...}]
      }
    ],
    "closedWindows": [ ... same shape as "windows" entries ... ]
  }

Designed to run unprivileged: files that can't be read/decompressed/decoded
are counted as errors and skipped, never fabricated. A file whose leading
bytes don't match the expected magic header is NOT counted as an error — it
produces a BSF-006 "unrecognized session format" finding instead, per spec.
"""
import json
import os
import struct
import time

try:
    import lz4.block
except ImportError:  # pragma: no cover - exercised only if lz4 isn't installed
    lz4 = None

from app.detection_rules import (
    ALL_RULES,
    rule_credentials_in_url,
    rule_webmail_cloud_storage_access,
    rule_paste_site_or_filehost_access,
    rule_excessive_url_repetition,
    rule_recently_closed_tab_evidence,
    rule_unrecognized_session_format,
)

DEFAULT_EXCLUDES = {"/proc", "/sys", "/dev", "/run"}

MOZLZ4_MAGIC = b"mozLz4a\x00"
SESSION_FILE_EXTENSIONS = (".jsonlz4", ".baklz4")

# Rules evaluated once per distinct URL found among currently-open tabs.
URL_RULES = (
    rule_credentials_in_url,
    rule_webmail_cloud_storage_access,
    rule_paste_site_or_filehost_access,
)

# Rules evaluated once per session file, over the whole parsed structure.
SESSION_RULES = (
    rule_excessive_url_repetition,
    rule_recently_closed_tab_evidence,
    rule_unrecognized_session_format,
)


def _looks_like_session_file(filename):
    lowered = filename.lower()
    if lowered.endswith(SESSION_FILE_EXTENSIONS):
        return True
    return "sessionstore" in lowered and lowered.endswith("lz4")


def parse_sessionstore_file(path):
    """Real parse of one sessionstore.jsonlz4-style file.

    Returns a tuple (magic_ok, data, error):
      - magic_ok=False, data=None, error=None        -> unrecognized format
      - magic_ok=True,  data=None, error=<Exception>  -> decompress/JSON error
      - magic_ok=True,  data=<dict>, error=None       -> real parsed JSON
    Raises OSError only if the file itself can't be read (caller handles it).
    """
    with open(path, "rb") as fh:
        raw = fh.read()

    if raw[:8] != MOZLZ4_MAGIC:
        return False, None, None

    try:
        uncompressed_size = struct.unpack("<I", raw[8:12])[0]
        payload = raw[12:]
        decompressed = lz4.block.decompress(payload, uncompressed_size=uncompressed_size)
        data = json.loads(decompressed)
    except Exception as exc:  # noqa: BLE001 - real parse failures of any kind
        return True, None, exc

    return True, data, None


def extract_urls(data):
    """Real traversal of the parsed session JSON. Returns:
      open_urls   - set of every URL in currently-open tab entries
      url_counts  - dict of URL -> count of distinct entries it appears in
                    (used for BSF-003 excessive-repetition detection)
      closed_urls - set of every URL found in closedWindows / _closedTabs
    """
    open_urls = set()
    url_counts = {}
    closed_urls = set()

    windows = data.get("windows", []) or []
    for window in windows:
        for tab in window.get("tabs", []) or []:
            for entry in tab.get("entries", []) or []:
                url = entry.get("url")
                if url:
                    open_urls.add(url)
                    url_counts[url] = url_counts.get(url, 0) + 1

        for closed_tab in window.get("_closedTabs", []) or []:
            state = closed_tab.get("state", {}) or {}
            for entry in state.get("entries", []) or []:
                url = entry.get("url")
                if url:
                    closed_urls.add(url)

    for closed_window in data.get("closedWindows", []) or []:
        for tab in closed_window.get("tabs", []) or []:
            for entry in tab.get("entries", []) or []:
                url = entry.get("url")
                if url:
                    closed_urls.add(url)

    return open_urls, url_counts, closed_urls


class ScanEngine:
    def __init__(self, target_path, max_depth=6, excludes=None, max_files=50000):
        self.target_path = os.path.abspath(target_path)
        self.max_depth = max_depth
        self.excludes = set(excludes) if excludes else set(DEFAULT_EXCLUDES)
        self.max_files = max_files

        self.files_scanned = 0
        self.dirs_scanned = 0
        self.errors_count = 0
        self.findings = []

    def _is_excluded(self, path):
        return any(path == ex or path.startswith(ex.rstrip("/") + "/") for ex in self.excludes)

    def run(self):
        """Perform the real, synchronous session-file walk + parse. Returns summary dict."""
        start = time.time()

        if os.path.isfile(self.target_path):
            self._process_file(self.target_path)
        elif os.path.isdir(self.target_path):
            self._walk(self.target_path, depth=0)
        else:
            self.errors_count += 1

        elapsed = time.time() - start
        return {
            "files_scanned": self.files_scanned,
            "dirs_scanned": self.dirs_scanned,
            "errors_count": self.errors_count,
            "findings": self.findings,
            "elapsed_seconds": round(elapsed, 3),
        }

    def _walk(self, path, depth):
        if self._is_excluded(path):
            return
        if depth > self.max_depth:
            return

        try:
            with os.scandir(path) as it:
                entries = list(it)
        except (PermissionError, FileNotFoundError, NotADirectoryError, OSError):
            self.errors_count += 1
            return

        self.dirs_scanned += 1

        for entry in entries:
            if self.files_scanned >= self.max_files:
                return
            full_path = entry.path
            if self._is_excluded(full_path):
                continue

            try:
                is_dir = entry.is_dir(follow_symlinks=False)
                is_file = entry.is_file(follow_symlinks=False)
            except OSError:
                self.errors_count += 1
                continue

            if is_file and _looks_like_session_file(entry.name):
                self._process_file(full_path)
            elif is_dir:
                self._walk(full_path, depth + 1)

    def _process_file(self, path):
        if self.files_scanned >= self.max_files:
            return
        self.files_scanned += 1

        try:
            magic_ok, data, parse_error = parse_sessionstore_file(path)
        except OSError:
            self.errors_count += 1
            return

        if not magic_ok:
            self._apply_session_rules(path, {
                "magic_ok": False,
                "url_counts": {},
                "closed_urls": set(),
                "open_urls": set(),
            })
            return

        if parse_error is not None:
            self.errors_count += 1
            return

        open_urls, url_counts, closed_urls = extract_urls(data)
        session_context = {
            "magic_ok": True,
            "url_counts": url_counts,
            "closed_urls": closed_urls,
            "open_urls": open_urls,
        }

        seen = set()
        for url in sorted(open_urls):
            url_context = {"url": url}
            for rule in URL_RULES:
                try:
                    result = rule(path, url_context)
                except Exception:
                    self.errors_count += 1
                    continue
                if result:
                    key = (result["rule_id"], result.get("matched_value"))
                    if key in seen:
                        continue
                    seen.add(key)
                    self._record(path, result)

        self._apply_session_rules(path, session_context)

    def _apply_session_rules(self, path, context):
        for rule in SESSION_RULES:
            try:
                result = rule(path, context)
            except Exception:
                self.errors_count += 1
                continue
            if result:
                self._record(path, result)

    def _record(self, path, result):
        result["file_path"] = path
        # Finding.permissions_octal is repurposed to hold the matched URL/hostname
        result["permissions_octal"] = result.get("matched_value")
        result["owner_uid"] = None
        result["owner_gid"] = None
        self.findings.append(result)
