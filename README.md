# extension-manifest-liar-scanner

**Extension scanners look for malware. Nobody checks the lie.**

In October 2026, Socket found **16 malicious Firefox extensions** impersonating Rabby and OKX crypto wallets: they intercepted 12/24-word recovery phrases and private keys during wallet import and exfiltrated them to Cloudflare Workers. **Every single manifest declared the extension collected no data.**

The structural gap is not the malice — it is the mismatch between what the manifest **declares** and what the code **does**. This tool compares a `manifest.json`'s declared permissions and data-collection claims against static code analysis and flags the lie.

## What it flags

| Flag | Severity | Meaning |
|------|----------|---------|
| `MANIFEST_LIE` | CRITICAL | Manifest claims no data collection but code handles recovery phrases, private keys, or exfiltrates |
| `RECOVERY_PHRASE` / `PRIVATE_KEY` | CRITICAL | Code handles wallet secrets |
| `CLIPBOARD_READ` | HIGH | Code reads the clipboard (phrase-stealing vector) |
| `EXTERNAL_EXFIL` / `WORKER_EXFIL` | HIGH | Code sends data to external/serverless endpoints |
| `SENSITIVE_PERMISSION` | MEDIUM | Manifest declares clipboardRead, debugger, proxy, etc. |

Declare the store-listing claim in the manifest as `"claims_no_data_collection": true` (browser manifests have no standard field for this — the lie lives in the store listing, so you declare what the listing said).

## Usage

```bash
python3 extension_manifest_liar_scanner.py --manifest manifest.json --code background.js content.js
python3 extension_manifest_liar_scanner.py --manifest manifest.json --code *.js --json
```

## What this does NOT do

- Pattern-based, not intent-reading: minified code can hide behavior. A `MANIFEST_LIE` flag means the code handles sensitive material the manifest does not disclose — not a legal verdict.
- A clean result is not a safety certification.

Python standard library only. No network, no dependencies.

## Built by Ingenious AI

This tool is built and maintained by **Ingenious AI**. Get early access to our AI security platforms:

- https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20DisclosureGuard
- https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20ModelMinder
- https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20TermsWatch
- https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20Vibe-Code%20Audit
- https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20Rogue-Agent%20Defense
- https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20BreachHunter
- https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20ChatBreaker
- https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20Agent%20Flight%20Recorder
- https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20Agent%20Auth%20Gateway
- https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20DomainGuard
- https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20ContentCraft%20AI


> Built by Ingenious AI with Muse — get free tokens with invite code `2HCQH1`
