"""Prepare public upload metadata and a local one-time encryption key."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess

REPO = "UMEDJON12/smartvoice-tj-updates"
PACKAGE = "tts.smartvoice.umedjon"
CERT = "5d1d676dfddad74da47b5486b4dbe9bf66b68e67c7c256d144ec0bdf3f0ed95b"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apk", type=Path, required=True)
    parser.add_argument("--version-name", required=True)
    parser.add_argument("--version-code", type=int, required=True)
    parser.add_argument("--release-id", type=int, default=0)
    parser.add_argument("--production", action="store_true")
    parser.add_argument("--tag-name", default="")
    parser.add_argument("--notes-file", type=Path)
    args = parser.parse_args()
    assert args.apk.is_file() and re.fullmatch(r"SmartVoice[-A-Za-z0-9_.]+\.apk", args.apk.name)
    assert args.version_code > 0 and (args.release_id > 0 or re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+-TJ", args.tag_name))
    os.umask(0o077)
    root = Path(__file__).resolve().parent.parent
    private = root / ".release-upload-private" / "direct"
    private.mkdir(parents=True, mode=0o700, exist_ok=True)
    for command in (["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:3072", "-out", str(private / "client-private.pem")],
                    ["openssl", "pkey", "-in", str(private / "client-private.pem"), "-pubout", "-out", str(private / "client-public.pem")]):
        result = subprocess.run(command, capture_output=True)
        if result.returncode:
            raise RuntimeError("One-time key generation failed")
    public = (private / "client-public.pem").read_text()
    target = root / "release-upload-work" / "input" / args.apk.name
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.resolve() != args.apk.resolve():
        shutil.copy2(args.apk, target)
    request = {"schemaVersion": 1, "requestId": secrets.token_hex(12), "repository": REPO,
        "publicKeyPem": public, "publicKeySha256": hashlib.sha256(public.encode()).hexdigest(),
        "releaseId": args.release_id, "filename": target.name, "sizeBytes": target.stat().st_size,
        "sha256": hashlib.sha256(target.read_bytes()).hexdigest(), "packageName": PACKAGE,
        "versionCode": args.version_code, "versionName": args.version_name,
        "signingCertificateSha256": CERT, "testOnly": not args.production, "tagName": args.tag_name,
        "releaseNotes": args.notes_file.read_text() if args.notes_file else ""}
    serialized = json.dumps(request, ensure_ascii=False, indent=2) + "\n"
    (private / "request.json").write_text(serialized)
    checks = root / "checks"
    checks.mkdir(exist_ok=True)
    (checks / "upload-request.json").write_text(serialized)
    print(json.dumps({"requestId": request["requestId"], "publicRequestFile": str(checks / "upload-request.json"),
        "privateDirectory": str(private), "filename": target.name, "sha256": request["sha256"]}))


if __name__ == "__main__":
    main()
