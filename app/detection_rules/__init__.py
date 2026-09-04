"""
Detection Rules — Browser Session Forensics Tool
Developed by Karanam Shrivasta | https://github.com/mrshrivasta

Each rule is a pure function that inspects a REAL context dict built from the
actual, decompressed Firefox `sessionstore.jsonlz4` JSON structure (or from
one parsed tab entry / session file) and returns a Finding dict if the
condition is met. Rules take no filesystem access of their own — the Security
Engine (app/security_engine) is solely responsible for the real mozLz4a
header check, real lz4.block.decompress, and real json.loads; these rules
only look at the resulting real data so they can be unit-tested in isolation
with synthetic context dicts that mirror the real schema.

Context dict shapes consumed by these rules:

  URL/entry-level context (used by rule_credentials_in_url,
  rule_webmail_cloud_storage_access, rule_paste_site_or_filehost_access):
      {"url": "<real tab entry URL string>"}

  Session-file-level context (used by rule_excessive_url_repetition,
  rule_recently_closed_tab_evidence, rule_unrecognized_session_format):
      {
        "url_counts": {"<url>": <int count across all open tabs/entries>, ...},
        "closed_urls": {"<url>", ...},          # from closedWindows/_closedTabs
        "open_urls": {"<url>", ...},             # from currently open tabs
        "magic_ok": True/False,
      }

Each rule returns a dict with rule_id/rule_name/severity/description (and, for
URL-level rules, the matched value under "matched_value" which the engine
copies into Finding.permissions_octal) or None.
"""
import re

# Severity scale used consistently across the whole project
SEVERITY_CRITICAL = "critical"
SEVERITY_HIGH = "high"
SEVERITY_MEDIUM = "medium"
SEVERITY_LOW = "low"

# Query-string parameter names that suggest cleartext credentials/tokens
CREDENTIAL_PARAM_RE = re.compile(r"(?:^|[?&])(password|token|api_key|session|auth)=", re.IGNORECASE)

# Common webmail / cloud-storage / file-sharing hostnames
WEBMAIL_CLOUD_HOSTS = (
    "mail.google.com",
    "outlook.office.com",
    "drive.google.com",
    "dropbox.com",
    "wetransfer.com",
    "mega.nz",
)

# Known paste-site / anonymous-file-host domains
PASTE_FILEHOST_DOMAINS = (
    "pastebin.com",
    "paste.ee",
    "anonfiles.com",
    "transfer.sh",
    "ngrok.io",
)

# Threshold above which the same URL/hostname appearing across distinct
# tabs/entries in one session file is considered an automated-browsing
# or tab-bombing anomaly.
EXCESSIVE_REPETITION_THRESHOLD = 10

MOZLZ4_MAGIC = b"mozLz4a\x00"


def rule_credentials_in_url(path, context):
    """BSF-001: A parsed tab-entry URL uses http:// (not https) AND contains a
    query-string parameter name suggestive of credentials/tokens (password=,
    token=, api_key=, session=, auth=). Forensic relevance: cleartext
    credentials/session tokens preserved in browsing session history are a
    real, recoverable exposure risk even after the site session ends."""
    url = context.get("url", "")
    if url.lower().startswith("http://") and CREDENTIAL_PARAM_RE.search(url):
        return {
            "rule_id": "BSF-001",
            "rule_name": "Cleartext Credentials in Session URL",
            "severity": SEVERITY_MEDIUM,
            "matched_value": url,
            "description": (
                f"A tab entry in {path} references the plaintext HTTP URL "
                f"{url!r}, which carries a parameter name suggestive of a "
                f"credential or session token. This URL is preserved in "
                f"Firefox's session-restore data even though the page was "
                f"not encrypted in transit."
            ),
        }
    return None


def rule_webmail_cloud_storage_access(path, context):
    """BSF-002: A parsed tab-entry URL's hostname matches a common webmail /
    cloud-storage / file-sharing service. Forensic relevance: evidence of a
    potential data-exfiltration channel (attacker or insider moving files
    off-host via personal webmail/cloud storage) preserved in session
    history."""
    url = context.get("url", "")
    lowered = url.lower()
    for host in WEBMAIL_CLOUD_HOSTS:
        if host in lowered:
            return {
                "rule_id": "BSF-002",
                "rule_name": "Webmail / Cloud-Storage Access",
                "severity": SEVERITY_MEDIUM,
                "matched_value": host,
                "description": (
                    f"A tab entry in {path} references {url!r}, whose "
                    f"hostname matches known webmail/cloud-storage service "
                    f"{host!r}. Review for potential data-exfiltration "
                    f"channel usage."
                ),
            }
    return None


def rule_excessive_url_repetition(path, context):
    """BSF-003: The same URL (or hostname) appears across an unusually high
    count of distinct tabs/entries in one session file (10+). Forensic
    relevance: real evidence of automated/scripted browsing or a
    tab-bombing/pop-up-spam incident, computed from the actual parsed tab
    structure rather than assumed."""
    url_counts = context.get("url_counts") or {}
    for url, count in url_counts.items():
        if count >= EXCESSIVE_REPETITION_THRESHOLD:
            return {
                "rule_id": "BSF-003",
                "rule_name": "Excessive URL Repetition Across Tabs",
                "severity": SEVERITY_LOW,
                "matched_value": url,
                "description": (
                    f"URL {url!r} appears in {count} distinct tabs/entries "
                    f"within {path} (threshold {EXCESSIVE_REPETITION_THRESHOLD}), "
                    f"suggesting automated/scripted browsing or a "
                    f"tab-bombing anomaly."
                ),
            }
    return None


def rule_recently_closed_tab_evidence(path, context):
    """BSF-004: closedWindows/_closedTabs data contains entries not present
    in any currently-open tab. Forensic relevance: recently-closed browsing
    activity survives in session-restore data even after the tab was closed
    (and possibly after browser history/cache were separately cleared) — an
    analyst should independently review it."""
    closed_urls = context.get("closed_urls") or set()
    open_urls = context.get("open_urls") or set()
    leftover = sorted(u for u in closed_urls if u not in open_urls)
    if leftover:
        sample = leftover[0]
        return {
            "rule_id": "BSF-004",
            "rule_name": "Recently Closed Tab Evidence",
            "severity": SEVERITY_LOW,
            "matched_value": sample,
            "description": (
                f"{path} retains {len(leftover)} closed-tab/closed-window "
                f"URL(s) not present among currently open tabs (e.g. "
                f"{sample!r}). This session-restore leftover data may "
                f"survive even if browser history/cache has already been "
                f"cleared and should be independently reviewed."
            ),
        }
    return None


def rule_paste_site_or_filehost_access(path, context):
    """BSF-005: A parsed tab-entry URL points to a known paste-site or
    anonymous-file-host domain. Forensic relevance: potential data-staging /
    exfiltration or command-and-control payload delivery channel."""
    url = context.get("url", "")
    lowered = url.lower()
    for domain in PASTE_FILEHOST_DOMAINS:
        if domain in lowered:
            return {
                "rule_id": "BSF-005",
                "rule_name": "Paste-Site / Anonymous File-Host Access",
                "severity": SEVERITY_MEDIUM,
                "matched_value": domain,
                "description": (
                    f"A tab entry in {path} references {url!r}, whose "
                    f"hostname matches known paste-site/anonymous-file-host "
                    f"{domain!r}. Review for potential data-staging/exfil "
                    f"or C2 delivery channel."
                ),
            }
    return None


def rule_unrecognized_session_format(path, context):
    """BSF-006: The file's leading magic bytes did not match the expected
    mozLz4a\\x00 signature. Forensic relevance: unrecognized/unsupported
    session-file format — reported as a parse-note so the analyst knows the
    file was not silently skipped."""
    if context.get("magic_ok") is False:
        return {
            "rule_id": "BSF-006",
            "rule_name": "Unrecognized Session File Format",
            "severity": SEVERITY_LOW,
            "matched_value": "unrecognized-format",
            "description": (
                f"{path} does not begin with the expected Firefox mozLz4a "
                f"session-store magic header ({MOZLZ4_MAGIC!r}). It was not "
                f"parsed as a sessionstore.jsonlz4 file; this may be a "
                f"different browser's format (e.g. Chrome SNSS) or a "
                f"corrupted/truncated file."
            ),
        }
    return None


ALL_RULES = [
    rule_credentials_in_url,
    rule_webmail_cloud_storage_access,
    rule_excessive_url_repetition,
    rule_recently_closed_tab_evidence,
    rule_paste_site_or_filehost_access,
    rule_unrecognized_session_format,
]
