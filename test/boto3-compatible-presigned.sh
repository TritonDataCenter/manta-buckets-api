#!/bin/bash
# AWS SigV4 presigned URL generator that matches boto3's algorithm exactly
# This script replicates the same canonical request construction as boto3

set -euo pipefail

# Configuration
AWS_ACCESS_KEY_ID=${AWS_ACCESS_KEY_ID:-"AKIA123456789EXAMPLE"}
AWS_SECRET_ACCESS_KEY=${AWS_SECRET_ACCESS_KEY:-"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}
S3_ENDPOINT=${S3_ENDPOINT:-"https://localhost:8080"}
AWS_REGION=${AWS_REGION:-"us-east-1"}

# Parse command line arguments
GENERATE_ONLY=false
UPLOAD_ID=""
PART_NUMBER=""

# Parse flags first
while [[ $# -gt 0 ]]; do
    case $1 in
        --generate-only|-g)
            GENERATE_ONLY=true
            shift
            ;;
        --upload-id)
            UPLOAD_ID="$2"
            shift 2
            ;;
        --part-number)
            PART_NUMBER="$2"
            shift 2
            ;;
        -*)
            echo "Unknown option $1" >&2
            exit 1
            ;;
        *)
            break
            ;;
    esac
done

METHOD="${1:-GET}"  # GET or PUT
BUCKET="${2:-test-bucket}"
OBJECT="${3:-test-object.txt}"
EXPIRES="${4:-300}"  # 5 minutes default

# Show usage if help requested
if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
    echo "Usage: $0 [--generate-only|-g] [--upload-id ID] [--part-number NUM] [METHOD] [BUCKET] [OBJECT] [EXPIRES]"
    echo ""
    echo "Flags:"
    echo "  --generate-only, -g  - Only generate URL, don't test it"
    echo "  --upload-id ID       - Multipart upload ID (for MPU part uploads)"
    echo "  --part-number NUM    - Part number (for MPU part uploads, 1-10000)"
    echo ""
    echo "Arguments:"
    echo "  METHOD   - HTTP method (GET or PUT), default: GET"
    echo "  BUCKET   - S3 bucket name, default: test-bucket"
    echo "  OBJECT   - S3 object key, default: test-object.txt"
    echo "  EXPIRES  - Expiration time in seconds, default: 300"
    echo ""
    echo "Environment variables:"
    echo "  AWS_ACCESS_KEY_ID     - AWS access key"
    echo "  AWS_SECRET_ACCESS_KEY - AWS secret key"
    echo "  S3_ENDPOINT           - S3 endpoint URL, default: https://localhost:8080"
    echo "  AWS_REGION            - AWS region, default: us-east-1"
    echo ""
    echo "Examples:"
    echo "  $0 GET my-bucket my-file.txt 600"
    echo "  $0 PUT test-bucket upload.txt 300"
    echo "  $0 --generate-only GET my-bucket my-file.txt 600"
    echo "  $0 -g PUT test-bucket upload.txt 300"
    echo "  $0 --upload-id abc123 --part-number 1 PUT bucket file.bin 3600"
    echo "  $0 -g --upload-id abc123 --part-number 2 PUT bucket file.bin 3600"
    exit 0
fi

# Generate timestamp
TIMESTAMP=$(date -u +"%Y%m%dT%H%M%SZ")
DATE_STAMP=$(echo "$TIMESTAMP" | cut -c1-8)

echo "Building presigned URL with timestamp: $TIMESTAMP"
echo "Method: $METHOD"
echo "Bucket: $BUCKET"
echo "Object: $OBJECT"
echo "Expires: $EXPIRES seconds"

# Build components
CREDENTIAL="${AWS_ACCESS_KEY_ID}/${DATE_STAMP}/${AWS_REGION}/s3/aws4_request"
SIGNED_HEADERS="host"
HOST=$(echo "$S3_ENDPOINT" | sed 's|^https://||' | sed 's|^http://||' | sed 's|/.*$||')

echo "Credential: $CREDENTIAL"
echo "Host: $HOST"

# URL encoding function that matches JavaScript's encodeURIComponent
# This is critical - must encode exactly like boto3 does
urlencode() {
    local string="${1}"
    local strlen=${#string}
    local encoded=""
    local pos c o

    for (( pos=0 ; pos<strlen ; pos++ )); do
        c=${string:$pos:1}
        case "$c" in
            [-_.~a-zA-Z0-9] ) o="${c}" ;;
            * ) printf -v o '%%%02X' "'$c" ;;  # Use uppercase hex like boto3
        esac
        encoded+="${o}"
    done
    echo "${encoded}"
}

# Build canonical URI
CANONICAL_URI="/${BUCKET}/${OBJECT}"

# Build canonical query string with proper URL encoding
# boto3 always sorts query parameters alphabetically - this is CRITICAL
ENCODED_CREDENTIAL=$(urlencode "$CREDENTIAL")
ALGORITHM="AWS4-HMAC-SHA256"
ENCODED_ALGORITHM=$(urlencode "$ALGORITHM")

# Build query parameters in the order Mahi expects
# Mahi expects X-Amz parameters first, then other parameters alphabetically
declare -a X_AMZ_PARAMS=(
    "X-Amz-Algorithm=${ENCODED_ALGORITHM}"
    "X-Amz-Credential=${ENCODED_CREDENTIAL}" 
    "X-Amz-Date=${TIMESTAMP}"
    "X-Amz-Expires=${EXPIRES}"
    "X-Amz-SignedHeaders=${SIGNED_HEADERS}"
)

# Add MPU parameters (these come after X-Amz parameters in Mahi's ordering)
declare -a MPU_PARAMS=()
if [ -n "$PART_NUMBER" ]; then
    MPU_PARAMS+=("partNumber=${PART_NUMBER}")
fi

if [ -n "$UPLOAD_ID" ]; then
    MPU_PARAMS+=("uploadId=${UPLOAD_ID}")
fi

# Sort X-Amz parameters alphabetically
IFS=$'\n' SORTED_X_AMZ=($(sort <<<"${X_AMZ_PARAMS[*]}"))
unset IFS

# Sort MPU parameters alphabetically
IFS=$'\n' SORTED_MPU=($(sort <<<"${MPU_PARAMS[*]}"))
unset IFS

# Combine: X-Amz parameters first, then MPU parameters
SORTED_PARAMS=("${SORTED_X_AMZ[@]}" "${SORTED_MPU[@]}")

# Join sorted parameters
CANONICAL_QUERYSTRING=""
for param in "${SORTED_PARAMS[@]}"; do
    if [ -n "$CANONICAL_QUERYSTRING" ]; then
        CANONICAL_QUERYSTRING+="&"
    fi
    CANONICAL_QUERYSTRING+="$param"
done

echo "Canonical query string: $CANONICAL_QUERYSTRING"

# Build canonical headers exactly like boto3
# Must have trailing newline after headers and empty line before signed headers
CANONICAL_HEADERS="host:${HOST}"

# Build canonical request with exact format boto3 uses
# This format is critical - must match boto3's implementation exactly
CANONICAL_REQUEST="${METHOD}
${CANONICAL_URI}
${CANONICAL_QUERYSTRING}
${CANONICAL_HEADERS}

${SIGNED_HEADERS}
UNSIGNED-PAYLOAD"

echo "=== CANONICAL REQUEST ==="
echo "$CANONICAL_REQUEST"
echo "========================="

# Create string to sign
ALGORITHM="AWS4-HMAC-SHA256"
CREDENTIAL_SCOPE="${DATE_STAMP}/${AWS_REGION}/s3/aws4_request"
CANONICAL_REQUEST_HASH=$(printf '%s' "$CANONICAL_REQUEST" | openssl dgst -sha256 -hex | cut -d' ' -f2)

STRING_TO_SIGN="${ALGORITHM}
${TIMESTAMP}
${CREDENTIAL_SCOPE}
${CANONICAL_REQUEST_HASH}"

echo "=== STRING TO SIGN ==="
echo "$STRING_TO_SIGN"
echo "======================"

echo "Canonical request hash: $CANONICAL_REQUEST_HASH"

# HMAC helper functions - use printf instead of echo to avoid newlines
hmac_sha256() {
    local key="$1"
    local data="$2"
    printf '%s' "$data" | openssl dgst -sha256 -mac HMAC -macopt hexkey:"$key" -binary | xxd -p -c 256
}

hmac_sha256_string() {
    local key="$1"
    local data="$2"
    printf '%s' "$data" | openssl dgst -sha256 -mac HMAC -macopt key:"$key" -binary | xxd -p -c 256
}

# Calculate signature using AWS SigV4 chain
kDate=$(hmac_sha256_string "AWS4${AWS_SECRET_ACCESS_KEY}" "$DATE_STAMP")
kRegion=$(hmac_sha256 "$kDate" "$AWS_REGION")
kService=$(hmac_sha256 "$kRegion" "s3")
kSigning=$(hmac_sha256 "$kService" "aws4_request")
SIGNATURE=$(printf '%s' "$STRING_TO_SIGN" | openssl dgst -sha256 -mac HMAC -macopt hexkey:"$kSigning" -hex | cut -d' ' -f2)

echo "=== HMAC CHAIN ==="
echo "kDate: $kDate"
echo "kRegion: $kRegion"
echo "kService: $kService"
echo "kSigning: $kSigning"
echo "Signature: $SIGNATURE"
echo "=================="

# Build final URL - don't re-encode parameters that are already encoded
FINAL_URL="${S3_ENDPOINT}${CANONICAL_URI}?${CANONICAL_QUERYSTRING}&X-Amz-Signature=${SIGNATURE}"

echo "=== FINAL URL ==="
echo "$FINAL_URL"
echo "================="

# Test the URL only if not in generate-only mode
if [ "$GENERATE_ONLY" = false ]; then
    echo "Testing the $METHOD URL..."
    if [ "$METHOD" = "GET" ]; then
        HTTP_CODE=$(curl -s -w "%{http_code}" -o /dev/null --insecure "$FINAL_URL")
    elif [ "$METHOD" = "PUT" ]; then
        TEST_CONTENT="Hello from bash presigned PUT test!"
        HTTP_CODE=$(curl -s -w "%{http_code}" -o /dev/null --insecure -X PUT --data "$TEST_CONTENT" "$FINAL_URL")
    fi

    echo "HTTP response code: $HTTP_CODE"

    if [ "$HTTP_CODE" = "200" ]; then
        echo "✅ SUCCESS: Presigned $METHOD URL works!"
    else
        echo "❌ FAILED: Presigned $METHOD URL failed with code $HTTP_CODE"
    fi
else
    echo "URL generation complete (testing skipped with --generate-only flag)"
fi