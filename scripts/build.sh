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

# Validate Signing Credentials at start (ephemeral decoding occurs delayed in Step 6)
if [ -z "${KEYSTORE_BASE64:-}" ] || [ -z "${KEYSTORE_PASSWORD:-}" ]; then
  echo "[-] ERROR: KEYSTORE_BASE64 or KEYSTORE_PASSWORD is not set." >&2
  exit 1
fi
KEYSTORE_ALIAS="${KEYSTORE_ALIAS:-chrysalis}"

mkdir -p "${TOOLS_DIR}" "${DIST_DIR}"

# Mandatory apksigner resolution for strict CI cryptographic verification
find_apksigner() {
  if command -v apksigner >/dev/null 2>&1; then
    command -v apksigner
    return 0
  fi
  local search_dirs=()
  [ -n "${ANDROID_HOME:-}" ] && search_dirs+=("${ANDROID_HOME}/build-tools")
  [ -n "${ANDROID_SDK_ROOT:-}" ] && search_dirs+=("${ANDROID_SDK_ROOT}/build-tools")
  search_dirs+=("/usr/local/lib/android/sdk/build-tools")
  for d in "${search_dirs[@]}"; do
    if [ -d "$d" ]; then
      local candidate
      candidate="$(find "$d" -name apksigner -type f -perm -u+x 2>/dev/null | sort -V | tail -n 1)"
      if [ -n "${candidate}" ] && [ -x "${candidate}" ]; then
        echo "${candidate}"
        return 0
      fi
    fi
  done
  return 1
}

APKSIGNER_BIN="$(find_apksigner || true)"
if [ -z "${APKSIGNER_BIN}" ] || [ ! -x "${APKSIGNER_BIN}" ]; then
  echo "[-] FATAL: apksigner tool not found. Mandatory for cryptographic signature verification on CI." >&2
  exit 1
fi
echo "[+] Using apksigner: ${APKSIGNER_BIN}"

# Authenticated & Resilient GitHub API Helper
curl_gh_api() {
  local endpoint="$1"
  local url="$endpoint"
  if [[ ! "$url" =~ ^https:// ]]; then
    url="https://api.github.com/repos/${endpoint}"
  fi
  local -a auth_args=()
  if [ -n "${GH_TOKEN:-}" ]; then
    auth_args=(-H "Authorization: Bearer ${GH_TOKEN}")
  fi
  curl -fsSL --proto '=https' --tlsv1.2 --retry 3 --connect-timeout 10 \
    -H "Accept: application/vnd.github+json" \
    "${auth_args[@]}" \
    "${url}"
}

# Unified Cryptographic APK Signature & Certificate Verification via Mandatory apksigner
verify_apk_certs() {
  local target_path="$1"
  local expected_sha256="$2"
  local mode="$3"

  python3 - "${target_path}" "${expected_sha256}" "${mode}" "${APKSIGNER_BIN}" <<'EOF'
import sys, os, zipfile, tempfile, shutil, subprocess

target_path = sys.argv[1]
expected_sha256 = sys.argv[2].lower().strip().replace(":", "").replace(" ", "")
mode = sys.argv[3]
apksigner_bin = sys.argv[4] if len(sys.argv) > 4 else ""

if not apksigner_bin or not os.path.isfile(apksigner_bin):
    print("[-] FATAL: apksigner binary path is missing or invalid.", file=sys.stderr)
    sys.exit(1)

def verify_single_apk(apk_path, display_name):
    res = subprocess.run(
        [apksigner_bin, "verify", "--verbose", "--print-certs", apk_path],
        capture_output=True,
        text=True
    )
    if res.returncode != 0:
        print(f"[-] ERROR: apksigner cryptographic verification failed on {display_name}:", file=sys.stderr)
        print(res.stderr or res.stdout, file=sys.stderr)
        return False
    out_clean = (res.stdout + "\n" + res.stderr).lower().replace(":", "").replace(" ", "")
    if expected_sha256 not in out_clean:
        print(f"[-] ERROR: apksigner certificate fingerprint mismatch on {display_name}!", file=sys.stderr)
        print(f"    Expected SHA-256: {expected_sha256}", file=sys.stderr)
        print(res.stdout, file=sys.stderr)
        return False
    return True

if mode == "xapk":
    apk_count = 0
    with zipfile.ZipFile(target_path, "r") as z:
        for name in z.namelist():
            if name.endswith(".apk"):
                apk_count += 1
                with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as tmp_apk:
                    tmp_apk_path = tmp_apk.name
                    with z.open(name) as src:
                        shutil.copyfileobj(src, tmp_apk, 1024 * 1024)
                try:
                    if not verify_single_apk(tmp_apk_path, name):
                        sys.exit(1)
                    print(f"    [OK] Verified split: {name} (apksigner RSA/ECDSA cert valid)")
                finally:
                    if os.path.exists(tmp_apk_path):
                        os.remove(tmp_apk_path)

    if apk_count == 0:
        print(f"[-] FATAL: No .apk entries found in {target_path}!", file=sys.stderr)
        sys.exit(1)
    print(f"[+] All {apk_count} split APKs cryptographically verified successfully.")

elif mode == "apk":
    if not verify_single_apk(target_path, os.path.basename(target_path)):
        sys.exit(1)
    print(f"[+] Artifact cryptographically verified: {target_path} (apksigner RSA/ECDSA cert valid)")

else:
    print(f"[-] ERROR: Unknown verification mode: {mode}", file=sys.stderr)
    sys.exit(1)
EOF
}

# Parse GitHub release JSON for tag and matching asset download URL
# Uses jq cleanly when present (e.g. on ubuntu-latest CI), with Python fallback
parse_gh_release_asset() {
  local json="$1"
  local pattern="$2"
  if command -v jq >/dev/null 2>&1; then
    printf "%s" "$json" | jq -r --arg pat "$pattern" '
      .tag_name as $tag |
      (.assets[] | select(.name | test($pat)) | .browser_download_url) as $url |
      "\($tag) \($url)"
    ' | head -n 1
  else
    python3 -c "
import sys, json, re
data = json.loads(sys.argv[1])
tag = data.get('tag_name', '')
pat = re.compile(sys.argv[2])
url = next((a['browser_download_url'] for a in data.get('assets', []) if pat.search(a['name'])), '')
print(f'{tag} {url}')
" "$json" "$pattern"
  fi
}

# 1. Fetch Upstream Tools (Parallel Morphe & Venus-Patches)
echo "[+] Fetching upstream toolchain (parallel metadata & downloads)..."

fetch_morphe() {
  local json morphe_tag morphe_url
  json="$(curl_gh_api "MorpheApp/morphe-desktop/releases/latest")"
  read -r morphe_tag morphe_url < <(parse_gh_release_asset "$json" '-all\.jar$')
  if [ -z "${morphe_tag}" ] || [ -z "${morphe_url}" ]; then
    echo "[-] ERROR: Failed to resolve Morphe download URL." >&2
    return 1
  fi
  local target_jar="${TOOLS_DIR}/morphe-${morphe_tag}.jar"
  if [ ! -f "${target_jar}" ]; then
    echo "    Downloading Morphe Patcher (${morphe_tag})..."
    curl -fsSL --proto '=https' --tlsv1.2 --retry 3 --connect-timeout 10 "${morphe_url}" -o "${target_jar}.tmp"
    mv "${target_jar}.tmp" "${target_jar}"
  else
    echo "    Morphe Patcher (${morphe_tag}) already cached."
  fi
  find "${TOOLS_DIR}" -maxdepth 1 -name 'morphe-*.jar' ! -name "morphe-${morphe_tag}.jar" -delete
  ln -sf "morphe-${morphe_tag}.jar" "${TOOLS_DIR}/morphe.jar"
  echo "${morphe_tag}" > "${TOOLS_DIR}/morphe.tag"
}

fetch_patches() {
  local json patches_tag patches_url
  json="$(curl_gh_api "VenusIsJaded/Venus-Patches/releases/latest")"
  read -r patches_tag patches_url < <(parse_gh_release_asset "$json" '\.mpp$')
  if [ -z "${patches_tag}" ] || [ -z "${patches_url}" ]; then
    echo "[-] ERROR: Failed to resolve Patches download URL." >&2
    return 1
  fi
  local target_mpp="${TOOLS_DIR}/patches-${patches_tag}.mpp"
  if [ ! -f "${target_mpp}" ]; then
    echo "    Downloading Patches Bundle (${patches_tag})..."
    curl -fsSL --proto '=https' --tlsv1.2 --retry 3 --connect-timeout 10 "${patches_url}" -o "${target_mpp}.tmp"
    mv "${target_mpp}.tmp" "${target_mpp}"
  else
    echo "    Patches Bundle (${patches_tag}) already cached."
  fi
  find "${TOOLS_DIR}" -maxdepth 1 -name 'patches-*.mpp' ! -name "patches-${patches_tag}.mpp" -delete
  ln -sf "patches-${patches_tag}.mpp" "${TOOLS_DIR}/patches.mpp"
  echo "${patches_tag}" > "${TOOLS_DIR}/patches.tag"
}

fetch_morphe &
pid_morphe=$!
fetch_patches &
pid_patches=$!
wait "${pid_morphe}"
wait "${pid_patches}"

PATCHES_TAG="$(cat "${TOOLS_DIR}/patches.tag")"
PATCH_VER="${PATCHES_TAG#v}"

# 2. Determine Target Version & Early Idempotency Check
TARGET_VER="${APP_VERSION:-}"
if [ -z "${TARGET_VER}" ]; then
  echo "[+] Querying compatible target version from patch bundle..."
  TARGET_VER=$(java -XX:TieredStopAtLevel=1 -jar "${TOOLS_DIR}/morphe.jar" list-versions --patches="${TOOLS_DIR}/patches.mpp" | \
    python3 -c "
import sys, re
pattern = re.compile(r'^\s*([0-9]+(?:\.[0-9]+)+)')
match = next((m.group(1) for line in sys.stdin for m in [pattern.search(line)] if m), '')
print(match)
")
fi

if [ -z "${TARGET_VER}" ]; then
  echo "[-] ERROR: Unable to detect compatible target version." >&2
  exit 1
fi

# Strict input character validation
if [[ ! "${TARGET_VER}" =~ ^[0-9A-Za-z._-]+$ ]]; then
  echo "[-] ERROR: TARGET_VER '${TARGET_VER}' contains invalid characters." >&2
  exit 1
fi

if [[ ! "${PATCH_VER}" =~ ^[0-9A-Za-z._-]+$ ]]; then
  echo "[-] ERROR: PATCH_VER '${PATCH_VER}' contains invalid characters." >&2
  exit 1
fi

RELEASE_TAG="v${PATCH_VER}-${TARGET_VER}"
RELEASE_TITLE="Release ${RELEASE_TAG}"
OUTPUT_APK_NAME="chrysalis-${RELEASE_TAG}.apk"
FINAL_APK="${DIST_DIR}/${OUTPUT_APK_NAME}"
FINAL_SHA256="${FINAL_APK}.sha256"

echo "[+] Target Version: ${TARGET_VER}"
echo "[+] Patch Version: ${PATCH_VER}"
echo "[+] Release Tag: ${RELEASE_TAG}"

# Early Idempotency Check against GitHub Releases (BEFORE downloading APKEditor)
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

# Fetch REAndroid/APKEditor (Only after idempotency check passes)
fetch_apkeditor() {
  local json apkeditor_tag apkeditor_url
  json="$(curl_gh_api "REAndroid/APKEditor/releases/latest")"
  read -r apkeditor_tag apkeditor_url < <(parse_gh_release_asset "$json" '^APKEditor.*\.jar$')
  if [ -z "${apkeditor_tag}" ] || [ -z "${apkeditor_url}" ]; then
    echo "[-] ERROR: Failed to resolve APKEditor download URL." >&2
    return 1
  fi
  local target_jar="${TOOLS_DIR}/apkeditor-${apkeditor_tag}.jar"
  if [ ! -f "${target_jar}" ]; then
    echo "    Downloading APKEditor (${apkeditor_tag})..."
    curl -fsSL --proto '=https' --tlsv1.2 --retry 3 --connect-timeout 10 "${apkeditor_url}" -o "${target_jar}.tmp"
    mv "${target_jar}.tmp" "${target_jar}"
  else
    echo "    APKEditor (${apkeditor_tag}) already cached."
  fi
  find "${TOOLS_DIR}" -maxdepth 1 -name 'apkeditor-*.jar' ! -name "apkeditor-${apkeditor_tag}.jar" -delete
  ln -sf "apkeditor-${apkeditor_tag}.jar" "${TOOLS_DIR}/apkeditor.jar"
  echo "${apkeditor_tag}" > "${TOOLS_DIR}/apkeditor.tag"
}
fetch_apkeditor

# 3. Download Stock Upstream Artifact via Mobile API
echo "[+] Fetching stock upstream binary..."
STOCK_DIR="${WORK_DIR}/stock_${TARGET_VER}"
mkdir -p "${STOCK_DIR}"
STOCK_BUNDLE="${STOCK_DIR}/stock.xapk"

python3 - "${TARGET_PKG}" "${TARGET_VER}" "${STOCK_BUNDLE}" <<'EOF'
import urllib.request, urllib.parse, json, os, sys, re, shutil

package = sys.argv[1]
target_ver = sys.argv[2]
output_path = sys.argv[3]

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
with urllib.request.urlopen(req, timeout=30) as resp:
    data = json.loads(resp.read().decode("utf-8"))

ver_pattern = re.compile(rf'(?:^|\b){re.escape(target_ver)}(?:\b|$)')
matches = [v for v in data.get("version_list", []) if ver_pattern.search(v.get("version_name", ""))]
if not matches:
    print(f"[-] ERROR: Version {target_ver} not found in upstream repository API.", file=sys.stderr)
    sys.exit(1)

asset = matches[0].get("asset", {})
download_urls = asset.get("urls", [])
if not download_urls:
    print("[-] ERROR: Download URL not found in API response.", file=sys.stderr)
    sys.exit(1)

download_url = download_urls[0]
parsed_url = urllib.parse.urlparse(download_url)
if parsed_url.scheme != "https":
    print(f"[-] ERROR: Insecure download URL scheme: {parsed_url.scheme}", file=sys.stderr)
    sys.exit(1)

try:
    expected_size = int(asset.get("size", 0))
except (ValueError, TypeError):
    expected_size = 0
if os.path.exists(output_path):
    actual_size = os.path.getsize(output_path)
    if (expected_size > 0 and actual_size == expected_size) or (expected_size <= 0 and actual_size > 10000000):
        print("    Stock bundle already downloaded and valid size.")
        sys.exit(0)
    else:
        print(f"    Cached stock bundle size mismatch (expected: {expected_size}, actual: {actual_size}). Re-downloading...")
        os.remove(output_path)

print(f"    Downloading stock artifact ({expected_size} bytes)...")
tmp_output = f"{output_path}.tmp"
dl_req = urllib.request.Request(download_url, headers={"User-Agent": headers["User-Agent"]})
with urllib.request.urlopen(dl_req, timeout=60) as resp, open(tmp_output, "wb") as f_out:
    shutil.copyfileobj(resp, f_out, length=1024 * 1024)

downloaded_size = os.path.getsize(tmp_output)
if (expected_size > 0 and downloaded_size != expected_size) or (expected_size <= 0 and downloaded_size <= 10000000):
    print(f"[-] ERROR: Downloaded file size mismatch ({downloaded_size} vs expected {expected_size})", file=sys.stderr)
    if os.path.exists(tmp_output):
        os.remove(tmp_output)
    sys.exit(1)

os.replace(tmp_output, output_path)
print("    Download completed successfully.")
EOF

# 4. Mandatory Cryptographic Upstream Certificate Verification
echo "[+] Performing cryptographic verification on upstream stock binary..."
verify_apk_certs "${STOCK_BUNDLE}" "${UPSTREAM_STOCK_CERT_SHA256}" "xapk"

# 5. Merge Split Bundle using APKEditor
echo "[+] Merging split bundle with APKEditor..."
MERGED_STOCK_APK="${STOCK_DIR}/merged_stock.apk"
java ${JAVA_OPTS:--Xmx4g -XX:+UseParallelGC} -jar "${TOOLS_DIR}/apkeditor.jar" m -f -i "${STOCK_BUNDLE}" -o "${MERGED_STOCK_APK}"

# 6. Apply Patches & Sign with Private Keystore (Ephemeral Keystore Decoding)
echo "[+] Executing patcher with private keystore signing..."

if [ -d "/dev/shm" ] && [ -w "/dev/shm" ]; then
  TMP_BASE="/dev/shm"
else
  TMP_BASE="${WORK_DIR}"
fi

old_umask="$(umask)"
umask 077
TEMP_KEYSTORE="$(mktemp "${TMP_BASE}/keystore.XXXXXX.p12")"
umask "${old_umask}"
chmod 600 "${TEMP_KEYSTORE}"
printf "%s" "${KEYSTORE_BASE64}" | base64 -d > "${TEMP_KEYSTORE}"

java ${JAVA_OPTS:--Xmx4g -XX:+UseParallelGC} -jar "${TOOLS_DIR}/morphe.jar" patch \
  --patches="${TOOLS_DIR}/patches.mpp" \
  --keystore="${TEMP_KEYSTORE}" \
  --keystore-entry-alias="${KEYSTORE_ALIAS}" \
  --keystore-password="${KEYSTORE_PASSWORD}" \
  --keystore-entry-password="${KEYSTORE_PASSWORD}" \
  --striplibs=arm64-v8a \
  -d "Complete badges automatically" \
  --out="${FINAL_APK}" \
  "${MERGED_STOCK_APK}"

# Immediately purge decrypted keystore from RAM/disk
rm -f "${TEMP_KEYSTORE}"
TEMP_KEYSTORE=""

# 7. Validate Final Output Signature
echo "[+] Validating output artifact signature..."
verify_apk_certs "${FINAL_APK}" "${PRIVATE_KEYSTORE_CERT_SHA256}" "apk"

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
