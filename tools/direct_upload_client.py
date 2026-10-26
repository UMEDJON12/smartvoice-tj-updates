import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
import subprocess
import urllib.parse
import urllib.request

REPO = "UMEDJON12/smartvoice-tj-updates"
API = "https://api.github.com"
ROOT = Path(__file__).resolve().parent.parent
PRIVATE = ROOT / ".release-upload-private" / "direct"


def main():
    os.umask(0o077)
    request = json.loads((PRIVATE / "request.json").read_text())
    session = json.loads((PRIVATE / "session.json").read_text())
    assert session["requestId"] == request["requestId"]
    assert session["repository"] == request["repository"] == REPO
    assert session["publicKeySha256"] == request["publicKeySha256"]
    encrypted = base64.b64decode(session["encryptedToken"], validate=True)
    wrapped = base64.b64decode(session["wrappedKeys"], validate=True)
    iv = base64.b64decode(session["iv"], validate=True)
    assert len(iv) == 16 and len(wrapped) == 384
    result = subprocess.run(["openssl", "pkeyutl", "-decrypt", "-inkey", str(PRIVATE / "client-private.pem"),
        "-pkeyopt", "rsa_padding_mode:oaep", "-pkeyopt", "rsa_oaep_md:sha256", "-pkeyopt", "rsa_mgf1_md:sha256"],
        input=wrapped, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode:
        raise RuntimeError("Secure session decryption failed")
    keys = result.stdout
    assert len(keys) == 64
    context = b"SmartVoice scoped upload token v1\0" + request["requestId"].encode() + b"\0" + REPO.encode() + b"\0"
    expected_mac = hmac.new(keys[32:], context + iv + encrypted, hashlib.sha256).hexdigest()
    assert hmac.compare_digest(expected_mac, session["hmacSha256"])
    decrypted = subprocess.run(["openssl", "enc", "-d", "-aes-256-cbc", "-K", keys[:32].hex(), "-iv", iv.hex()],
        input=encrypted, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if decrypted.returncode:
        raise RuntimeError("Secure session decryption failed")
    token = decrypted.stdout.decode().strip()
    assert token and len(token) < 16384

    def api(path, method="GET", data=None, content_type="application/json"):
        url = API + "/repos/" + REPO + path if path.startswith("/") else path
        parsed = urllib.parse.urlsplit(url)
        assert parsed.scheme == "https" and parsed.hostname in ("api.github.com", "uploads.github.com")
        assert parsed.path.startswith("/repos/" + REPO + "/")
        raw = json.dumps(data).encode() if isinstance(data, (dict, list)) else data
        req = urllib.request.Request(url, data=raw, method=method, headers={
            "Authorization": "Bearer " + token, "Accept": "application/vnd.github+json",
            "Content-Type": content_type, "X-GitHub-Api-Version": "2026-03-10"})
        with urllib.request.urlopen(req, timeout=300) as response:
            body = response.read()
            return json.loads(body) if body else None

    apk = ROOT / "release-upload-work" / "input" / request["filename"]
    assert apk.stat().st_size == request["sizeBytes"]
    assert hashlib.sha256(apk.read_bytes()).hexdigest() == request["sha256"]
    release = api("/releases/" + str(session["releaseId"]))
    assert release["draft"] is True
    print("Scoped API access confirmed; APK integrity verified locally", flush=True)
    upload_url = release["upload_url"].split("{", 1)[0]
    assert upload_url.startswith("https://uploads.github.com/repos/" + REPO + "/releases/")

    def upload(name, data, content_type):
        digest = "sha256:" + hashlib.sha256(data).hexdigest()
        current = api("/releases/" + str(release["id"]))
        assert current["draft"] is True
        existing = next((x for x in current["assets"] if x["name"] == name), None)
        if existing:
            assert existing["size"] == len(data) and existing["digest"] == digest
            return existing
        obj = api(upload_url + "?name=" + urllib.parse.quote(name), "POST", data, content_type)
        assert obj["state"] == "uploaded" and obj["size"] == len(data) and obj["digest"] == digest
        return obj

    print("Uploading APK directly to draft", flush=True)
    apk_asset = upload(request["filename"], apk.read_bytes(), "application/vnd.android.package-archive")
    print("APK uploaded; server SHA-256 matches", flush=True)
    update = {"schemaVersion": 1, "testOnly": True, "variant": "standard", "packageName": request["packageName"],
        "versionCode": request["versionCode"], "versionName": request["versionName"], "apkFileName": request["filename"],
        "apkUrl": apk_asset["browser_download_url"], "sizeBytes": request["sizeBytes"], "sha256": request["sha256"],
        "signingCertificateSha256": request["signingCertificateSha256"], "minSdk": 21,
        "releaseNotes": "Проверка загрузки уже выпущенной обычной версии SmartVoice. Новая версия приложения не создавалась."}
    update_bytes = (json.dumps(update, ensure_ascii=False, indent=2) + "\n").encode()
    update_asset = upload("update.json", update_bytes, "application/json")
    release = api("/releases/" + str(release["id"]), "PATCH", {
        "name": "SmartVoice " + request["versionName"] + " — проверка загрузки",
        "body": "Проверка загрузки последнего готового APK и update.json. Черновик для владельца. Не публиковать как новое обновление.",
        "draft": True, "prerelease": True, "make_latest": "false"})
    assert release["draft"] is True
    client_result = {"schemaVersion": 1, "requestId": request["requestId"], "status": "uploaded",
        "releaseId": release["id"], "apkAssetId": apk_asset["id"], "updateAssetId": update_asset["id"],
        "apkSha256": request["sha256"], "updateSha256": hashlib.sha256(update_bytes).hexdigest(), "published": False}
    try:
        current = api("/contents/checks/upload-client-result.json?ref=main")
    except urllib.error.HTTPError as exc:
        if exc.code != 404:
            raise
        current = None
    body = {"message": "Request independent verification of uploaded draft APK and JSON", "branch": "main",
        "content": base64.b64encode((json.dumps(client_result, indent=2) + "\n").encode()).decode()}
    if current:
        body["sha"] = current["sha"]
    api("/contents/checks/upload-client-result.json", "PUT", body)
    (PRIVATE / "client-result.json").write_text(json.dumps(client_result, indent=2) + "\n")
    print(json.dumps(client_result), flush=True)


if __name__ == "__main__":
    main()
