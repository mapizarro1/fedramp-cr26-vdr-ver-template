#!/usr/bin/env python3
# =============================================================================
# SUPERSEDED 2026-07-30 (decision 0005). Do not deploy.
# Replaced by ../bin/FedRAMP-SchemaWatch.ps1 (PowerShell port; no Python runtime
# on the boundary host). Kept for reference only. Design rationale for WHAT is
# watched: decision 0002.
# =============================================================================
"""
fedramp_schema_watch.py

Watches the FedRAMP Consolidated Rules for 2026 for changes that matter to a
Rev5 Moderate (Class C) vulnerability-management and ConMon program, and alerts
when something moves.

What it catches, in one pass:
  1. rules    : new / removed / re-versioned JSON schemas, plus VER and VDR rule
                text and PAIN timeframe changes, plus VDR/VER effective dates.
                This is the primary signal (one authoritative file).
  2. schemas  : content hash and liveness (HTTP status) of each referenced
                schema file, so an in-place edit or a 404 -> 200 go-live is seen.
  3. feeds    : GitHub commit/release Atom feeds for the source repos (early
                warning, fires before a content diff would).
  4. rss      : FedRAMP Public Notices and Changelog feeds (human cross-check).

Design notes:
  - Standard library only. No pip install. Runs on a locked-down host.
  - First run establishes a baseline and does not alert (unless ALERT_ON_BASELINE).
  - State is a single JSON file. Last-write-wins. Safe to run from cron / Task
    Scheduler at any cadence (daily is plenty; rules move on the order of weeks).
  - Alerting is pluggable. SMTP and Jira are each independent and no-op if their
    config is left blank, so the script runs end to end before you wire creds.

Egress required (allowlist these if the host is filtered):
  raw.githubusercontent.com, github.com, www.fedramp.gov, fedramp.gov

Author note: plain stdlib, ASCII only.
"""

import json
import os
import sys
import ssl
import hashlib
import smtplib
import urllib.request
import urllib.error
from datetime import datetime, timezone
from email.mime.text import MIMEText
import xml.etree.ElementTree as ET

# ----------------------------------------------------------------------------
# CONFIG
# ----------------------------------------------------------------------------

# Which layers to run. Turn any off without touching code below.
WATCH = {
    "rules": True,
    "schemas": True,
    "feeds": True,
    "rss": True,
}

# Primary source of truth: the canonical machine-readable ruleset.
RULES_URL = "https://raw.githubusercontent.com/FedRAMP/rules/main/fedramp-consolidated-rules.json"

# The schema that defines the shape of the ruleset file itself (format guard).
RULES_DATASET_SCHEMA_URL = "https://raw.githubusercontent.com/FedRAMP/rules/main/schemas/fedramp-consolidated-rules.schema.json"

# Base used to fetch each referenced report/package schema. The ruleset stores
# absolute fedramp.gov URLs; if those ever 404, the swap helper tries www<->apex.
# (No base needed; URLs come straight out of the ruleset.)

# Source repos to watch via Atom (commits + releases).
ATOM_FEEDS = [
    "https://github.com/FedRAMP/rules/commits/main.atom",
    "https://github.com/FedRAMP/rules/releases.atom",
    "https://github.com/FedRAMP/docs/commits/main.atom",
    "https://github.com/FedRAMP/2026/commits/main.atom",
]

# FedRAMP RSS. CONFIRM these exact feed URLs against the live site before relying
# on them; the layer tolerates a 404 and simply reports the feed as unreachable.
RSS_FEEDS = [
    "https://www.fedramp.gov/notices/index.xml",
    "https://www.fedramp.gov/changelog/index.xml",
]

# Rule families fingerprinted for text/timeframe changes.
#   VDR/VER : vulnerability detection, response, evaluation, reporting
#   IEC     : incident evaluation and communication (IIR/OIR/FIR, reportability)
#   CCM     : collaborative continuous monitoring (OCR cadence/availability)
# The incident-report and ongoing-certification-report schemas these reference
# are already covered by the schemas layer (it pulls every schema in the ruleset).
RULE_FAMILIES = ["VDR", "VER", "IEC", "CCM"]

# State file. Keep it on persistent storage, not a temp dir.
STATE_PATH = os.environ.get("FRWATCH_STATE", "fedramp_schema_watch_state.json")

ALERT_ON_BASELINE = False  # set True to get one "baseline established" notice

# ---- SMTP (leave SMTP_HOST blank to disable) ----
SMTP_HOST = os.environ.get("FRWATCH_SMTP_HOST", "")   # e.g. smtp.office365.com or your Google relay
SMTP_PORT = int(os.environ.get("FRWATCH_SMTP_PORT", "587"))
SMTP_USER = os.environ.get("FRWATCH_SMTP_USER", "")
SMTP_PASS = os.environ.get("FRWATCH_SMTP_PASS", "")
SMTP_STARTTLS = True
MAIL_FROM = os.environ.get("FRWATCH_MAIL_FROM", "fedramp-watch@example.com")
MAIL_TO = [x for x in os.environ.get("FRWATCH_MAIL_TO", "").split(",") if x]

# ---- Jira (leave JIRA_BASE blank to disable) ----
JIRA_BASE = os.environ.get("FRWATCH_JIRA_BASE", "")   # e.g. https://jira.example.com
JIRA_PROJECT = os.environ.get("FRWATCH_JIRA_PROJECT", "OC")
JIRA_ISSUETYPE = os.environ.get("FRWATCH_JIRA_ISSUETYPE", "Task")
# Provide a ready-to-send auth header value, e.g. "Bearer <PAT>" or "Basic <b64>".
JIRA_AUTH_HEADER = os.environ.get("FRWATCH_JIRA_AUTH", "")

HTTP_TIMEOUT = 30
USER_AGENT = "fedramp-schema-watch/1.0 (+stdlib)"

# ----------------------------------------------------------------------------
# HTTP
# ----------------------------------------------------------------------------

_SSL_CTX = ssl.create_default_context()


def http_get(url, retries=2):
    """Return (status_code, body_bytes). status_code 0 on transport failure."""
    last = None
    for attempt in range(retries + 1):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT,
                                                       "Accept": "*/*"})
            with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT, context=_SSL_CTX) as r:
                return r.getcode(), r.read()
        except urllib.error.HTTPError as e:
            return e.code, (e.read() if hasattr(e, "read") else b"")
        except Exception as e:  # noqa
            last = e
    sys.stderr.write("GET failed %s: %s\n" % (url, last))
    return 0, b""


def swap_host(url):
    if "://www.fedramp.gov" in url:
        return url.replace("://www.fedramp.gov", "://fedramp.gov")
    if "://fedramp.gov" in url:
        return url.replace("://fedramp.gov", "://www.fedramp.gov")
    return None


def sha256_hex(b):
    return hashlib.sha256(b).hexdigest()


# ----------------------------------------------------------------------------
# RULES LAYER
# ----------------------------------------------------------------------------

def is_rule_id(s):
    return isinstance(s, str) and len(s) == 11 and s[3] == "-" and s[7] == "-"


def extract_schema_refs(rules):
    refs = {}

    def walk(o, last_rule):
        if isinstance(o, dict):
            if isinstance(o.get("schema"), dict) and "url" in o["schema"]:
                refs.setdefault(o["schema"]["url"], set()).add(last_rule)
            for k, v in o.items():
                walk(v, k if is_rule_id(k) else last_rule)
        elif isinstance(o, list):
            for v in o:
                walk(v, last_rule)

    walk(rules, None)
    return {u: sorted(x for x in s if x) for u, s in refs.items()}


def fingerprint_family(rules, fam):
    out = {}
    try:
        data = rules["FRR"][fam]["data"]
    except (KeyError, TypeError):
        return out
    for _scope, subsets in data.items():
        for _subset, rs in subsets.items():
            for rid, r in rs.items():
                fp = {"name": r.get("name"),
                      "statement": r.get("statement"),
                      "force": r.get("force")}
                if "varies_by_class" in r:
                    fp["varies_by_class"] = {
                        cls: {"statement": cd.get("statement"),
                              "timeframe_num": cd.get("timeframe_num"),
                              "pain_timeframes": cd.get("pain_timeframes")}
                        for cls, cd in r["varies_by_class"].items()
                    }
                out[rid] = fp
    return out


def family_effective(rules, fam):
    try:
        return rules["FRR"][fam]["info"].get("effective")
    except (KeyError, TypeError):
        return None


def snapshot_rules():
    status, body = http_get(RULES_URL)
    if status != 200 or not body:
        return None, "rules file unreachable (HTTP %s)" % status
    try:
        rules = json.loads(body)
    except Exception as e:  # noqa
        return None, "rules file did not parse: %s" % e
    snap = {
        "schemas": extract_schema_refs(rules),
        "families": {fam: fingerprint_family(rules, fam) for fam in RULE_FAMILIES},
        "effective": {fam: family_effective(rules, fam) for fam in RULE_FAMILIES},
        "rules_version": (rules.get("info") or {}).get("version"),
    }
    return snap, None


def diff_rules(old, new):
    lines = []
    if old is None:
        return lines
    ov = old.get("rules_version")
    nv = new.get("rules_version")
    if ov != nv:
        lines.append("[rules] ruleset version: %s -> %s" % (ov, nv))

    # schema URL set
    old_urls = set((old.get("schemas") or {}).keys())
    new_urls = set((new.get("schemas") or {}).keys())
    for u in sorted(new_urls - old_urls):
        lines.append("[schema-ref NEW] %s  (referenced by %s)"
                     % (u, ", ".join(new["schemas"][u]) or "?"))
    for u in sorted(old_urls - new_urls):
        lines.append("[schema-ref REMOVED] %s" % u)
    for u in sorted(old_urls & new_urls):
        if old["schemas"][u] != new["schemas"][u]:
            lines.append("[schema-ref REMAPPED] %s : %s -> %s"
                         % (u, old["schemas"][u], new["schemas"][u]))

    # rule text / timeframes
    for fam in RULE_FAMILIES:
        of = (old.get("families") or {}).get(fam, {})
        nf = (new.get("families") or {}).get(fam, {})
        for rid in sorted(set(nf) - set(of)):
            lines.append("[%s NEW RULE] %s :: %s" % (fam, rid, nf[rid].get("name")))
        for rid in sorted(set(of) - set(nf)):
            lines.append("[%s RULE REMOVED] %s" % (fam, rid))
        for rid in sorted(set(of) & set(nf)):
            if of[rid] != nf[rid]:
                lines.append("[%s RULE CHANGED] %s :: %s" % (fam, rid, nf[rid].get("name")))
                _detail_rule_change(lines, of[rid], nf[rid])
        oe = (old.get("effective") or {}).get(fam)
        ne = (new.get("effective") or {}).get(fam)
        if oe != ne:
            lines.append("[%s EFFECTIVE DATES CHANGED] %s -> %s"
                         % (fam, json.dumps(oe), json.dumps(ne)))
    return lines


def _detail_rule_change(lines, o, n):
    if o.get("statement") != n.get("statement"):
        lines.append("    statement changed")
    ov = o.get("varies_by_class") or {}
    nv = n.get("varies_by_class") or {}
    for cls in sorted(set(ov) | set(nv)):
        if ov.get(cls) != nv.get(cls):
            ot = (ov.get(cls) or {}).get("timeframe_num")
            nt = (nv.get(cls) or {}).get("timeframe_num")
            if ot != nt:
                lines.append("    class %s timeframe_num: %s -> %s" % (cls.upper(), ot, nt))
            op = (ov.get(cls) or {}).get("pain_timeframes")
            np_ = (nv.get(cls) or {}).get("pain_timeframes")
            if op != np_:
                lines.append("    class %s PAIN matrix changed" % cls.upper())
            os_ = (ov.get(cls) or {}).get("statement")
            ns_ = (nv.get(cls) or {}).get("statement")
            if os_ != ns_ and ot == nt:
                lines.append("    class %s statement changed" % cls.upper())


# ----------------------------------------------------------------------------
# SCHEMAS LAYER
# ----------------------------------------------------------------------------

def snapshot_schemas(schema_urls):
    out = {}
    urls = list(schema_urls) + [RULES_DATASET_SCHEMA_URL]
    for u in urls:
        status, body = http_get(u)
        if status != 200:
            alt = swap_host(u)
            if alt:
                status, body = http_get(alt)
        out[u] = {"status": status,
                  "sha256": sha256_hex(body) if (status == 200 and body) else None,
                  "bytes": len(body) if body else 0}
    return out


def diff_schemas(old, new):
    lines = []
    if old is None:
        # still flag any schema that is referenced but not live yet
        for u, s in sorted(new.items()):
            if s["status"] != 200:
                lines.append("[schema NOT-LIVE @baseline] %s (HTTP %s)" % (u, s["status"]))
        return lines
    for u in sorted(set(new) - set(old)):
        lines.append("[schema ADDED to watch] %s (HTTP %s)" % (u, new[u]["status"]))
    for u in sorted(set(old) - set(new)):
        lines.append("[schema DROPPED from watch] %s" % u)
    for u in sorted(set(old) & set(new)):
        o, n = old[u], new[u]
        if o["status"] != n["status"]:
            tag = "WENT LIVE" if (o["status"] != 200 and n["status"] == 200) else "STATUS"
            lines.append("[schema %s] %s : HTTP %s -> %s" % (tag, u, o["status"], n["status"]))
        if o["sha256"] != n["sha256"] and n["status"] == 200 and o["status"] == 200:
            lines.append("[schema CONTENT CHANGED] %s (sha %s -> %s, %d -> %d bytes)"
                         % (u, (o["sha256"] or "none")[:12], (n["sha256"] or "none")[:12],
                            o["bytes"], n["bytes"]))
    return lines


# ----------------------------------------------------------------------------
# FEEDS LAYER (Atom)
# ----------------------------------------------------------------------------

ATOM_NS = "{http://www.w3.org/2005/Atom}"


def snapshot_atom(url):
    status, body = http_get(url)
    if status != 200 or not body:
        return {"status": status, "entries": []}
    try:
        root = ET.fromstring(body)
    except Exception:  # noqa
        return {"status": status, "entries": []}
    entries = []
    for e in root.findall(ATOM_NS + "entry"):
        eid = e.findtext(ATOM_NS + "id") or ""
        title = (e.findtext(ATOM_NS + "title") or "").strip()
        updated = e.findtext(ATOM_NS + "updated") or ""
        entries.append({"id": eid, "title": title, "updated": updated})
    return {"status": status, "entries": entries[:20]}


def diff_atom(url, old, new):
    lines = []
    new_ids = [e["id"] for e in new.get("entries", [])]
    if old is None:
        return lines
    old_ids = set(e["id"] for e in old.get("entries", []))
    fresh = [e for e in new.get("entries", []) if e["id"] not in old_ids]
    for e in fresh[:8]:
        lines.append("[feed] %s : %s" % (url.split("github.com/")[-1], e["title"]))
    if len(fresh) > 8:
        lines.append("[feed] %s : +%d more" % (url, len(fresh) - 8))
    return lines


# ----------------------------------------------------------------------------
# RSS LAYER
# ----------------------------------------------------------------------------

def snapshot_rss(url):
    status, body = http_get(url)
    if status != 200 or not body:
        alt = swap_host(url)
        if alt:
            status, body = http_get(alt)
    if status != 200 or not body:
        return {"status": status, "items": []}
    try:
        root = ET.fromstring(body)
    except Exception:  # noqa
        return {"status": status, "items": []}
    items = []
    for it in root.iter("item"):
        guid = (it.findtext("guid") or it.findtext("link") or "").strip()
        title = (it.findtext("title") or "").strip()
        items.append({"guid": guid, "title": title})
    return {"status": status, "items": items[:30]}


def diff_rss(url, old, new):
    lines = []
    if old is None:
        return lines
    old_g = set(i["guid"] for i in old.get("items", []))
    fresh = [i for i in new.get("items", []) if i["guid"] not in old_g]
    for i in fresh[:10]:
        lines.append("[rss] %s : %s" % (url.rsplit("/", 2)[-2] if "/" in url else url, i["title"]))
    return lines


# ----------------------------------------------------------------------------
# STATE
# ----------------------------------------------------------------------------

def load_state():
    if not os.path.exists(STATE_PATH):
        return None
    try:
        with open(STATE_PATH, "r") as f:
            return json.load(f)
    except Exception:  # noqa
        return None


def save_state(state):
    tmp = STATE_PATH + ".tmp"
    with open(tmp, "w") as f:
        json.dump(state, f, sort_keys=True, indent=1)
    os.replace(tmp, STATE_PATH)


# ----------------------------------------------------------------------------
# ALERTING
# ----------------------------------------------------------------------------

def alert_smtp(subject, body):
    if not (SMTP_HOST and MAIL_TO):
        return
    msg = MIMEText(body, "plain", "utf-8")
    msg["Subject"] = subject
    msg["From"] = MAIL_FROM
    msg["To"] = ", ".join(MAIL_TO)
    try:
        s = smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=HTTP_TIMEOUT)
        if SMTP_STARTTLS:
            s.starttls(context=_SSL_CTX)
        if SMTP_USER:
            s.login(SMTP_USER, SMTP_PASS)
        s.sendmail(MAIL_FROM, MAIL_TO, msg.as_string())
        s.quit()
        print("SMTP alert sent to %s" % ", ".join(MAIL_TO))
    except Exception as e:  # noqa
        sys.stderr.write("SMTP send failed: %s\n" % e)


def alert_jira(summary, description):
    if not (JIRA_BASE and JIRA_AUTH_HEADER):
        return
    payload = json.dumps({"fields": {
        "project": {"key": JIRA_PROJECT},
        "summary": summary[:250],
        "description": description,
        "issuetype": {"name": JIRA_ISSUETYPE},
    }}).encode("utf-8")
    req = urllib.request.Request(
        JIRA_BASE.rstrip("/") + "/rest/api/2/issue",
        data=payload, method="POST",
        headers={"Content-Type": "application/json",
                 "Authorization": JIRA_AUTH_HEADER,
                 "User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT, context=_SSL_CTX) as r:
            data = json.loads(r.read())
            print("Jira issue created: %s" % data.get("key"))
    except urllib.error.HTTPError as e:
        sys.stderr.write("Jira create failed HTTP %s: %s\n" % (e.code, e.read()[:300]))
    except Exception as e:  # noqa
        sys.stderr.write("Jira create failed: %s\n" % e)


# ----------------------------------------------------------------------------
# MAIN
# ----------------------------------------------------------------------------

def main():
    now = datetime.now(timezone.utc).isoformat()
    prev = load_state()
    first_run = prev is None
    prev = prev or {}

    state = {"checked_at": now}
    changes = []

    # rules
    if WATCH["rules"]:
        snap, err = snapshot_rules()
        if err:
            changes.append("[rules ERROR] %s" % err)
            state["rules"] = prev.get("rules")  # keep last good
        else:
            state["rules"] = snap
            changes += diff_rules(prev.get("rules"), snap)
    else:
        state["rules"] = prev.get("rules")

    # schemas (uses the schema URL set from the current rules snapshot)
    if WATCH["schemas"]:
        urls = list(((state.get("rules") or {}).get("schemas") or {}).keys())
        snap = snapshot_schemas(urls)
        state["schemas"] = snap
        changes += diff_schemas(prev.get("schemas"), snap)
    else:
        state["schemas"] = prev.get("schemas")

    # feeds
    if WATCH["feeds"]:
        feeds = {}
        prev_feeds = prev.get("feeds") or {}
        for url in ATOM_FEEDS:
            snap = snapshot_atom(url)
            feeds[url] = snap
            changes += diff_atom(url, prev_feeds.get(url), snap)
        state["feeds"] = feeds
    else:
        state["feeds"] = prev.get("feeds")

    # rss
    if WATCH["rss"]:
        rss = {}
        prev_rss = prev.get("rss") or {}
        for url in RSS_FEEDS:
            snap = snapshot_rss(url)
            rss[url] = snap
            changes += diff_rss(url, prev_rss.get(url), snap)
        state["rss"] = rss
    else:
        state["rss"] = prev.get("rss")

    save_state(state)

    if first_run:
        msg = ("FedRAMP schema watch baseline established at %s\n"
               "Schemas tracked: %d\n"
               "Rule families fingerprinted: %s\n"
               "No alerts on baseline run."
               % (now,
                  len(((state.get("rules") or {}).get("schemas") or {})),
                  ", ".join(RULE_FAMILIES)))
        print(msg)
        if ALERT_ON_BASELINE:
            alert_smtp("FedRAMP schema watch: baseline established", msg)
        return 0

    if not changes:
        print("No changes detected at %s" % now)
        return 0

    header = "FedRAMP Consolidated Rules / schema change(s) detected at %s\n%s\n" % (
        now, "-" * 60)
    body = header + "\n".join(changes) + "\n\nSource: %s\n" % RULES_URL
    print(body)
    subject = "FedRAMP rules/schema change: %d item(s)" % len(changes)
    alert_smtp(subject, body)
    alert_jira(subject, body)
    return 0


if __name__ == "__main__":
    sys.exit(main())
