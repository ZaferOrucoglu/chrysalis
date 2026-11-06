#!/usr/bin/env bash
# Chrysalis build and packaging pipeline
# Autonomous artifact fetcher, verifier, patcher, and signer

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
WORK_DIR="${PROJECT_ROOT}/work"
DIST_DIR="${PROJECT_ROOT}/dist"
TOOLS_DIR="${WORK_DIR}/tools"

# Security Constants
UPSTREAM_STOCK_CERT_SHA256="3c39d23cf9367849a5c699395647fe0e5bfea5a1f1f40d8c717ddc70f8bfa113"
PRIVATE_KEYSTORE_CERT_SHA256="557f5504bc34cbd35b968c22d343eb31adfb1fd89c52bf46f67477cefe3a5b41"

# Target package encoded to maintain repository neutrality
TARGET_PKG="$(printf "%s" "Y29tLmRpc2NvcmQ=" | base64 -d)"

# Cleanup trap for secure temporary files
TEMP_KEYSTORE=""
cleanup() {
  if [ -n "${TEMP_KEYSTORE}" ] && [ -f "${TEMP_KEYSTORE}" ]; then
    rm -f "${TEMP_KEYSTORE}"
  fi
}
trap cleanup EXIT INT TERM

echo "=== Chrysalis Artifact Build Pipeline ==="

# Validate Signing Credentials
if [ -z "${KEYSTORE_BASE64:-}" ] || [ -z "${KEYSTORE_PASSWORD:-}" ]; then
  echo "[-] ERROR: KEYSTORE_BASE64 or KEYSTORE_PASSWORD is not set." >&2
  exit 1
fi
KEYSTORE_ALIAS="${KEYSTORE_ALIAS:-chrysalis}"

mkdir -p "${TOOLS_DIR}" "${DIST_DIR}"

# Decode private keystore securely
TEMP_KEYSTORE="$(mktemp "${WORK_DIR}/keystore.XXXXXX.p12")"
chmod 600 "${TEMP_KEYSTORE}"
printf "%s" "${KEYSTORE_BASE64}" | base64 -d > "${TEMP_KEYSTORE}"

# 1. Fetch Upstream Tools
echo "[+] Fetching upstream toolchain..."

# Morphe Patcher CLI
MORPHE_JAR="${TOOLS_DIR}/morphe.jar"
if [ ! -f "${MORPHE_JAR}" ]; then
  MORPHE_URL=$(curl -s "https://api.github.com/repos/MorpheApp/morphe-desktop/releases/latest" | \
    python3 -c "import sys, json; data=json.load(sys.stdin); print(next(a['browser_download_url'] for a in data['assets'] if a['name'].endswith('-all.jar')))")
  echo "    Downloading Morphe Patcher from ${MORPHE_URL}..."
  curl -sL "${MORPHE_URL}" -o "${MORPHE_JAR}"
fi

# Venus Patches Bundle
PATCHES_MPP="${TOOLS_DIR}/patches.mpp"
PATCHES_TAG=""
if [ ! -f "${PATCHES_MPP}" ]; then
  PATCHES_JSON=$(curl -s "https://api.github.com/repos/VenusIsJaded/Venus-Patches/releases/latest")
  PATCHES_TAG=$(printf "%s" "${PATCHES_JSON}" | python3 -c "import sys, json; print(json.load(sys.stdin).get('tag_name', ''))")
  PATCHES_URL=$(printf "%s" "${PATCHES_JSON}" | python3 -c "import sys, json; data=json.load(sys.stdin); print(next(a['browser_download_url'] for a in data['assets'] if a['name'].endswith('.mpp')))")
  echo "    Downloading Patches Bundle (${PATCHES_TAG}) from ${PATCHES_URL}..."
  curl -sL "${PATCHES_URL}" -o "${PATCHES_MPP}"
fi

# APKEditor (Bundle Merger)
APKEDITOR_JAR="${TOOLS_DIR}/apkeditor.jar"
if [ ! -f "${APKEDITOR_JAR}" ]; then
  APKEDITOR_URL=$(curl -s "https://api.github.com/repos/REAndroid/APKEditor/releases/latest" | \
    python3 -c "import sys, json; data=json.load(sys.stdin); print(next(a['browser_download_url'] for a in data['assets'] if a['name'].startswith('APKEditor') and a['name'].endswith('.jar')))")
  echo "    Downloading APKEditor from ${APKEDITOR_URL}..."
  curl -sL "${APKEDITOR_URL}" -o "${APKEDITOR_JAR}"
fi

# 2. Determine Target Version
TARGET_VER="${APP_VERSION:-}"
if [ -z "${TARGET_VER}" ]; then
  echo "[+] Querying compatible target version from patch bundle..."
  TARGET_VER=$(java -jar "${MORPHE_JAR}" list-versions --patches="${PATCHES_MPP}" | \
    python3 -c "import sys, re; lines=sys.stdin.read().splitlines(); matches=[re.search(r'^\s*([0-9]+(?:\.[0-9]+)+)', l) for l in lines]; found=[m.group(1) for m in matches if m]; print(found[0] if found else '')")
fi

if [ -z "${TARGET_VER}" ]; then
  echo "[-] ERROR: Unable to detect compatible target version." >&2
  exit 1
fi

PATCH_VER="${PATCHES_TAG#v}"
if [ -z "${PATCH_VER}" ]; then
  PATCH_VER="1.21.1"
fi

RELEASE_TAG="v${PATCH_VER}-${TARGET_VER}"
RELEASE_TITLE="Release ${RELEASE_TAG}"
OUTPUT_APK_NAME="chrysalis-${RELEASE_TAG}.apk"
FINAL_APK="${DIST_DIR}/${OUTPUT_APK_NAME}"
FINAL_SHA256="${FINAL_APK}.sha256"

echo "[+] Target Version: ${TARGET_VER}"
echo "[+] Patch Version: ${PATCH_VER}"
echo "[+] Release Tag: ${RELEASE_TAG}"

# Idempotency Check against GitHub Releases
FORCE_BUILD="${FORCE_BUILD:-false}"
if [ "${FORCE_BUILD}" != "true" ] && command -v gh >/dev/null 2>&1; then
  if gh release view "${RELEASE_TAG}" -R ZaferOrucoglu/chrysalis >/dev/null 2>&1; then
    echo "[!] Release ${RELEASE_TAG} already exists and FORCE_BUILD is not enabled. Skipping build cleanly."
    if [ -n "${GITHUB_OUTPUT:-}" ]; then
      echo "skip_build=true" >> "${GITHUB_OUTPUT}"
      echo "tag_name=${RELEASE_TAG}" >> "${GITHUB_OUTPUT}"
    fi
    exit 0
  fi
fi

# 3. Download Stock Upstream Artifact via Mobile API
echo "[+] Fetching stock upstream binary..."
STOCK_DIR="${WORK_DIR}/stock_${TARGET_VER}"
mkdir -p "${STOCK_DIR}"
STOCK_BUNDLE="${STOCK_DIR}/stock.xapk"

python3 - <<EOF
import urllib.request, json, os, sys

package = "${TARGET_PKG}"
target_ver = "${TARGET_VER}"
output_path = "${STOCK_BUNDLE}"

if os.path.exists(output_path) and os.path.getsize(output_path) > 10000000:
    print("    Stock bundle already downloaded.")
    sys.exit(0)

url = f"https://tapi.pureapk.com/v3/get_app_his_version?package_name={package}&hl=en"
headers = {
    "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 14; Pixel 7 Pro Build/UQ1A.240205.002); APKPure/3.20.34 (Aegon)",
    "Ual-Access-Businessid": "projecta",
    "Ual-Access-ProjectA": json.dumps({
        "device_info": {
            "abis": ["arm64-v8a", "armeabi-v7a"],
            "android_id": "50f838123d9a9c94",
            "brand": "google",
            "country": "US",
            "country_code": "US",
            "language": "en-US",
            "manufacturer": "Google",
            "mode": "Pixel 7 Pro",
            "os_ver": "34",
            "os_ver_name": "14",
            "platform": 1,
            "product": "cheetah",
            "screen_height": 1440,
            "screen_width": 3120
        },
        "host_app_info": {
            "build_no": "468", "channel": "", "md5": "6756e53158d6f6c013650a40d8f1147b",
            "pkg_name": "com.apkpure.aegon", "sdk_ver": "3.20.34", "version_code": 3203427, "version_name": "3.20.34"
        }
    }),
    "Connection": "Keep-Alive",
}

req = urllib.request.Request(url, headers=headers)
with urllib.request.urlopen(req) as resp:
    data = json.loads(resp.read())

matches = [v for v in data.get("version_list", []) if target_ver in v.get("version_name", "")]
if not matches:
    print(f"[-] ERROR: Version {target_ver} not found in upstream repository API.", file=sys.stderr)
    sys.exit(1)

download_url = matches[0]["asset"]["urls"][0]
print(f"    Downloading stock artifact ({matches[0]['asset'].get('size', 'unknown')} bytes)...")
urllib.request.urlretrieve(download_url, output_path)
print("    Download completed successfully.")
EOF

# 4. Mandatory Cryptographic Upstream Certificate Verification
echo "[+] Performing cryptographic verification on upstream stock binary..."

python3 - <<EOF
import zipfile, struct, hashlib, sys, os

stock_bundle = "${STOCK_BUNDLE}"
expected_sha256 = "${UPSTREAM_STOCK_CERT_SHA256}".lower().strip()

def get_v2_v3_cert_fingerprints(file_path):
    with open(file_path, "rb") as f:
        f.seek(0, 2)
        size = f.tell()
        f.seek(max(0, size - 65536))
        data = f.read()
        eocd_pos = data.rfind(b"\x50\x4b\x05\x06")
        if eocd_pos == -1:
            return []
        cd_offset = struct.unpack_from("<I", data, eocd_pos + 16)[0]
        if cd_offset < 24:
            return []
        f.seek(cd_offset - 24)
        block_tail = f.read(24)
        block_size, magic = struct.unpack("<Q16s", block_tail)
        if magic != b"APK Sig Block 42":
            return []
        f.seek(cd_offset - block_size - 8)
        block_data = f.read(block_size - 16)
        pos = 8
        fingerprints = []
        while pos + 12 <= len(block_data):
            pair_len, pair_id = struct.unpack_from("<QI", block_data, pos)
            pos += 12
            val = block_data[pos:pos + pair_len - 4]
            pos += pair_len - 4
            if pair_id in (0x7109871a, 0xebf201e5):
                s_pos = 4
                while s_pos < len(val):
                    signer_len = struct.unpack_from("<I", val, s_pos)[0]
                    s_pos += 4
                    signer = val[s_pos:s_pos + signer_len]
                    s_pos += signer_len
                    signed_data_len = struct.unpack_from("<I", signer, 0)[0]
                    signed_data = signer[4:4 + signed_data_len]
                    digests_len = struct.unpack_from("<I", signed_data, 0)[0]
                    d_pos = 4 + digests_len
                    certs_len = struct.unpack_from("<I", signed_data, d_pos)[0]
                    c_pos = d_pos + 4
                    c_end = c_pos + certs_len
                    while c_pos < c_end:
                        cert_len = struct.unpack_from("<I", signed_data, c_pos)[0]
                        c_pos += 4
                        cert_der = signed_data[c_pos:c_pos + cert_len]
                        c_pos += cert_len
                        fingerprints.append(hashlib.sha256(cert_der).hexdigest())
        return list(set(fingerprints))

# Inspect bundle and verify internal stock APK before merging
verified = False
with zipfile.ZipFile(stock_bundle, "r") as z:
    for name in z.namelist():
        if name.endswith(".apk"):
            apk_bytes = z.read(name)
            tmp_apk = os.path.join("${STOCK_DIR}", "verify_target.apk")
            with open(tmp_apk, "wb") as f_out:
                f_out.write(apk_bytes)
            fps = get_v2_v3_cert_fingerprints(tmp_apk)
            os.remove(tmp_apk)
            for fp in fps:
                if fp.lower() == expected_sha256:
                    verified = True
                    print(f"    [OK] Verified {name} signing certificate: {fp}")
                    break
            if verified:
                break

if not verified:
    print("[-] FATAL SECURITY FAILURE: Upstream APK signing certificate SHA-256 mismatch!", file=sys.stderr)
    print(f"    Expected: {expected_sha256}", file=sys.stderr)
    sys.exit(1)

print("[+] Upstream stock cryptographic certificate verification SUCCESSFUL.")
EOF

# 5. Merge Split Bundle using APKEditor
echo "[+] Merging split bundle with APKEditor..."
MERGED_STOCK_APK="${STOCK_DIR}/merged_stock.apk"
java -jar "${APKEDITOR_JAR}" m -f -i "${STOCK_BUNDLE}" -o "${MERGED_STOCK_APK}"

# 6. Apply Patches & Sign with Private Keystore
echo "[+] Executing patcher with private keystore signing..."

java -jar "${MORPHE_JAR}" patch \
  --patches="${PATCHES_MPP}" \
  --keystore="${TEMP_KEYSTORE}" \
  --keystore-entry-alias="${KEYSTORE_ALIAS}" \
  --keystore-password="${KEYSTORE_PASSWORD}" \
  --keystore-entry-password="${KEYSTORE_PASSWORD}" \
  -d "Complete Quests automatically" \
  -d "Complete badges automatically" \
  --out="${FINAL_APK}" \
  "${MERGED_STOCK_APK}"

# 7. Validate Final Output Signature
echo "[+] Validating output artifact signature..."

python3 - <<EOF
import struct, hashlib, sys

def get_v2_v3_cert_fingerprints(file_path):
    with open(file_path, "rb") as f:
        f.seek(0, 2)
        size = f.tell()
        f.seek(max(0, size - 65536))
        data = f.read()
        eocd_pos = data.rfind(b"\x50\x4b\x05\x06")
        if eocd_pos == -1:
            return []
        cd_offset = struct.unpack_from("<I", data, eocd_pos + 16)[0]
        if cd_offset < 24:
            return []
        f.seek(cd_offset - 24)
        block_tail = f.read(24)
        block_size, magic = struct.unpack("<Q16s", block_tail)
        if magic != b"APK Sig Block 42":
            return []
        f.seek(cd_offset - block_size - 8)
        block_data = f.read(block_size - 16)
        pos = 8
        fingerprints = []
        while pos + 12 <= len(block_data):
            pair_len, pair_id = struct.unpack_from("<QI", block_data, pos)
            pos += 12
            val = block_data[pos:pos + pair_len - 4]
            pos += pair_len - 4
            if pair_id in (0x7109871a, 0xebf201e5):
                s_pos = 4
                while s_pos < len(val):
                    signer_len = struct.unpack_from("<I", val, s_pos)[0]
                    s_pos += 4
                    signer = val[s_pos:s_pos + signer_len]
                    s_pos += signer_len
                    signed_data_len = struct.unpack_from("<I", signer, 0)[0]
                    signed_data = signer[4:4 + signed_data_len]
                    digests_len = struct.unpack_from("<I", signed_data, 0)[0]
                    d_pos = 4 + digests_len
                    certs_len = struct.unpack_from("<I", signed_data, d_pos)[0]
                    c_pos = d_pos + 4
                    c_end = c_pos + certs_len
                    while c_pos < c_end:
                        cert_len = struct.unpack_from("<I", signed_data, c_pos)[0]
                        c_pos += 4
                        cert_der = signed_data[c_pos:c_pos + cert_len]
                        c_pos += cert_len
                        fingerprints.append(hashlib.sha256(cert_der).hexdigest())
        return list(set(fingerprints))

fps = get_v2_v3_cert_fingerprints("${FINAL_APK}")
expected = "${PRIVATE_KEYSTORE_CERT_SHA256}".lower().strip()
if not any(fp.lower() == expected for fp in fps):
    print("[-] FATAL: Final artifact is NOT signed by Chrysalis private key!", file=sys.stderr)
    print(f"    Expected: {expected}", file=sys.stderr)
    print(f"    Found:    {fps}", file=sys.stderr)
    sys.exit(1)

print("[+] Final artifact verified: correctly signed with Chrysalis private key.")
EOF

# 8. Generate SHA-256 Checksum
(cd "${DIST_DIR}" && sha256sum "${OUTPUT_APK_NAME}" > "${OUTPUT_APK_NAME}.sha256")
echo "[+] Generated checksum: $(cat "${FINAL_SHA256}")"

# 9. Set GitHub Actions outputs if running in CI
if [ -n "${GITHUB_OUTPUT:-}" ]; then
  echo "skip_build=false" >> "${GITHUB_OUTPUT}"
  echo "tag_name=${RELEASE_TAG}" >> "${GITHUB_OUTPUT}"
  echo "release_title=${RELEASE_TITLE}" >> "${GITHUB_OUTPUT}"
  echo "artifact_path=${FINAL_APK}" >> "${GITHUB_OUTPUT}"
  echo "checksum_path=${FINAL_SHA256}" >> "${GITHUB_OUTPUT}"
fi

echo "[+] Build completed successfully: ${FINAL_APK}"
