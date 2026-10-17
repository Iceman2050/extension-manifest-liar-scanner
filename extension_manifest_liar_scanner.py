"""extension-manifest-liar-scanner
==============================

In October 2026, Socket found 16 malicious Firefox extensions
impersonating Rabby and OKX wallets: they intercepted 12/24-word
recovery phrases and private keys during wallet import, exfiltrating
them to Cloudflare Workers. Every single manifest declared the
extension collected NO data.

Extension scanners look for malware signatures. Nobody checks the
structural gap: the LIE between what the manifest declares and what
the code does. This tool compares a manifest.json's declared
permissions and data-collection claims against static code analysis
(recovery-phrase handling, private-key interception, clipboard hooks,
exfil endpoints) and flags the mismatch. stdlib only.

What this does NOT do: it cannot read minified intent — findings are
pattern-based and a "lie" flag means the code handles sensitive
material the manifest does not disclose, not a legal verdict. A
clean result is not a safety certification.
"""

import argparse
import json
import re
import sys

CODE_PATTERNS = (
    (re.compile(r"mnemonic|seed[\s_-]?phrase|recovery[\s_-]?phrase",
                re.I), "RECOVERY_PHRASE", "CRITICAL",
     "Code handles wallet recovery/seed phrases."),
    (re.compile(r"private[\s_-]?key", re.I), "PRIVATE_KEY", "CRITICAL",
     "Code handles private keys."),
    (re.compile(r"navigator\.clipboard\.readText|clipboard\.read",
                re.I), "CLIPBOARD_READ", "HIGH",
     "Code reads the clipboard — a classic phrase-stealing vector."),
    (re.compile(r"fetch\s*\(\s*[\"']https?://(?!localhost|127\.0\.0\.1)",
                re.I), "EXTERNAL_EXFIL", "HIGH",
     "Code sends data to an external URL."),
    (re.compile(r"workers\.dev|pages\.dev", re.I), "WORKER_EXFIL",
     "HIGH",
     "Code targets serverless worker infrastructure — the Oct 2026 "
     "campaign exfiltrated to Cloudflare Workers."),
)

SENSITIVE_PERMISSIONS = ("clipboardRead", "debugger", "proxy",
                         "webRequestBlocking", "nativeMessaging")


def manifest_claims_no_collection(manifest):
    """True when the manifest claims it collects no user data."""
    mc = manifest.get("data_collection") or {}
    if isinstance(mc, dict):
        declared = str(mc.get("collects", "")).strip().lower()
        if declared in ("none", "no", "false", ""):
            # explicit "none" or absent claims while handling secrets
            # is the lie pattern; treat absent conservatively below
            pass
    # Chrome/Firefox manifests: no standard field — the lie is in the
    # store listing. We model it via an explicit declared field.
    return bool(manifest.get("claims_no_data_collection"))


def analyze_code(files):
    """files: dict of filename -> source text. Returns code findings."""
    findings = []
    for fname, text in (files or {}).items():
        for rx, flag, severity, desc in CODE_PATTERNS:
            if rx.search(text or ""):
                findings.append({"flag": flag, "severity": severity,
                                 "location": fname, "description": desc})
    return findings


def audit_extension(manifest_text, files):
    """Compare manifest claims vs code. Deterministic."""
    try:
        manifest = json.loads(manifest_text)
    except json.JSONDecodeError as exc:
        raise ValueError("invalid manifest.json: %s" % exc)
    code_findings = analyze_code(files)
    findings = []
    lies = manifest_claims_no_collection(manifest)
    handles_secrets = any(f["severity"] == "CRITICAL"
                          for f in code_findings)
    if lies and (handles_secrets or code_findings):
        findings.append({"flag": "MANIFEST_LIE", "severity": "CRITICAL",
                         "location": "manifest.json",
                         "description": "Manifest claims no data "
                                        "collection but the code "
                                        "handles sensitive material — "
                                        "the exact pattern of the Oct "
                                        "2026 wallet-stealer campaign."})
    for perm in SENSITIVE_PERMISSIONS:
        if perm in (manifest.get("permissions") or []):
            findings.append({"flag": "SENSITIVE_PERMISSION",
                             "severity": "MEDIUM",
                             "location": "manifest.json",
                             "description": "Declares sensitive "
                                            "permission '%s'." % perm})
    findings += code_findings
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}
    findings.sort(key=lambda f: order.get(f["severity"], 3))
    worst = findings[0]["severity"] if findings else "CLEAN"
    return {"worst": worst, "findings": findings,
            "manifest_claims_no_collection": lies}


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Check extension manifest honesty vs code.")
    ap.add_argument("--manifest", required=True,
                    help="path to manifest.json")
    ap.add_argument("--code", nargs="*", default=[],
                    help="JS files to analyze (path=label not needed; "
                         "plain paths)")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    try:
        with open(args.manifest, encoding="utf-8") as fh:
            manifest_text = fh.read()
    except OSError as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 2
    files = {}
    for p in args.code:
        try:
            with open(p, encoding="utf-8", errors="replace") as fh:
                files[p] = fh.read()
        except OSError as exc:
            print("warning: %s" % exc, file=sys.stderr)
    try:
        report = audit_extension(manifest_text, files)
    except ValueError as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print("Worst finding: %s" % report["worst"])
        for f in report["findings"]:
            print("[%s] %s (%s): %s" % (f["severity"], f["flag"],
                                        f["location"], f["description"]))
        if not report["findings"]:
            print("No mismatches found — not a safety certification.")
    return 1 if report["worst"] in ("CRITICAL", "HIGH") else 0


if __name__ == "__main__":
    sys.exit(main())
