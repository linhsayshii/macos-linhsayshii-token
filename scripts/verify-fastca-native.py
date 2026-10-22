#!/usr/bin/env python3
"""Recheck the retained public FastCA native test signature; no token/PIN needed."""
import base64
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
evidence = root / "docs/re/evidence"
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--app", action="store_true", help="verify the integrated app SignHash test")
arguments = parser.parse_args()
if arguments.app:
    record = json.loads((evidence / "fastca-app-signing-validation.json").read_text())
    message = record["SignHash"]["message"].encode("utf-8")
    signature = base64.b64decode(record["SignHash"]["signatureB64"], validate=True)
    public_key = evidence / "fastca-app-public.pem"
    hashes = {"message.bin": record["SignHash"]["SHA256"],
              "signature.bin": record["signatureSHA256"], "public.pem": record["publicKeySHA256"]}
else:
    record = json.loads((evidence / "fastca-native-signing-validation.json").read_text())
    message = record["message"].encode("utf-8")
    signature = base64.b64decode(record["signatureB64"], validate=True)
    public_key = evidence / "fastca-native-public.pem"
    hashes = record["sha256"]
for name, data in [("message.bin", message), ("signature.bin", signature),
                   ("public.pem", public_key.read_bytes())]:
    if hashlib.sha256(data).hexdigest() != hashes[name]:
        raise SystemExit(f"Evidence hash mismatch: {name}")
with tempfile.TemporaryDirectory(prefix="fastca-verify-") as temporary:
    directory = Path(temporary)
    (directory / "message").write_bytes(message)
    (directory / "signature").write_bytes(signature)
    subprocess.run(["openssl", "dgst", "-sha256", "-verify", str(public_key),
                    "-signature", str(directory / "signature"),
                    str(directory / "message")], check=True)
