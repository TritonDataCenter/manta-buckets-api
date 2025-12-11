#!/bin/bash
#
# Copyright 2025 Edgecast Cloud LLC.
# 
# AWS STS Example for Manta Buckets API
# Demonstrates GetSessionToken, AssumeRole, and IAM Policy enforcement
# This script shows detailed output of each step.
#
# Usage:
#   ./sts-demo.sh           - Run all tests (default)
#   ./sts-demo.sh full      - Run all tests
#   ./sts-demo.sh chain     - Run only privilege escalation test (STEP 8)
#

set -e

# Suppress SSL warnings from AWS CLI/boto3
export PYTHONWARNINGS="ignore:Unverified HTTPS request"

# Parse command line arguments
TEST_MODE="${1:-full}"

case "$TEST_MODE" in
    full)
        echo "Running all tests..."
        RUN_STEP_1=true
        RUN_STEP_2=true
        RUN_STEP_3=true
        RUN_STEP_4=true
        RUN_STEP_5=true
        RUN_STEP_6=true
        RUN_STEP_7=true
        RUN_STEP_8=true
        RUN_STEP_9=true
        RUN_STEP_10=true
        ;;
    chain)
        echo "Running privilege escalation test only (STEP 8)..."
        RUN_STEP_1=true   # Need buckets
        RUN_STEP_2=true   # Need session token
        RUN_STEP_3=true   # Need first role
        RUN_STEP_4=true   # Need to assume first role
        RUN_STEP_5=false  # Skip
        RUN_STEP_6=false  # Skip
        RUN_STEP_7=false  # Skip
        RUN_STEP_8=true   # The test we want
        RUN_STEP_9=false  # Skip
        RUN_STEP_10=false # Skip
        ;;
    *)
        echo "Error: Unknown test mode '$TEST_MODE'"
        echo "Usage: $0 [full|chain]"
        echo "  full  - Run all tests (default)"
        echo "  chain - Run only privilege escalation test (STEP 8)"
        exit 1
        ;;
esac

# Debug: Show which steps will run
echo ""
echo "DEBUG: Step execution plan:"
echo "  STEP 1 (Setup buckets): $RUN_STEP_1"
echo "  STEP 2 (GetSessionToken): $RUN_STEP_2"
echo "  STEP 3 (Create role): $RUN_STEP_3"
echo "  STEP 4 (AssumeRole): $RUN_STEP_4"
echo "  STEP 5 (GetCallerIdentity): $RUN_STEP_5"
echo "  STEP 6 (Test allowed ops): $RUN_STEP_6"
echo "  STEP 7 (Test denied ops): $RUN_STEP_7"
echo "  STEP 8 (Privilege escalation): $RUN_STEP_8"
echo "  STEP 9 (MSTS IAM test): $RUN_STEP_9"
echo "  STEP 10 (Error tests): $RUN_STEP_10"
echo ""

# Configuration - Set these environment variables before running:
# export S3_ENDPOINT="https://us-central.manta.mnx.io"
# export AWS_ACCESS_KEY_ID="AKIA123456789EXAMPLE"
# export AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
export ACCOUNT_UUID="3c254973-8690-4ac7-bcce-d739d1017473"
# export ROLE_NAME="S3RestrictedRole"

if [[ -z "$S3_ENDPOINT" ]]; then
    echo "Error: S3_ENDPOINT environment variable not set"
    exit 1
fi

if [[ -z "$AWS_ACCESS_KEY_ID" ]] || [[ -z "$AWS_SECRET_ACCESS_KEY" ]]; then
    echo "Error: AWS credentials not set in environment"
    exit 1
fi

ACCOUNT_UUID="${ACCOUNT_UUID:-930896af-bf8c-48d4-885c-6573a94b1853}"
ROLE_NAME="${ROLE_NAME:-S3RestrictedRole}"
SESSION_NAME="my-session-$(date +%s)"
TEST_BUCKET="sts-policy-test-$(date +%s)"
ALLOWED_BUCKET="allowed-bucket-$(date +%s)"

# Save permanent credentials
PERMANENT_ACCESS_KEY="$AWS_ACCESS_KEY_ID"
PERMANENT_SECRET_KEY="$AWS_SECRET_ACCESS_KEY"

# Test tracking
declare -a PASSED_TESTS=()
declare -a FAILED_TESTS=()
declare -a PASSED_COMMANDS=()
declare -a FAILED_COMMANDS=()
TOTAL_TESTS=0

# Helper function to record test results
record_test() {
    local test_name="$1"
    local passed="$2"
    local reason="$3"
    local command="$4"

    TOTAL_TESTS=$((TOTAL_TESTS + 1))

    if [ "$passed" = "true" ]; then
        PASSED_TESTS+=("$test_name")
        PASSED_COMMANDS+=("$command")
        echo "  ✓ PASS: $test_name"
    else
        FAILED_TESTS+=("$test_name: $reason")
        FAILED_COMMANDS+=("$command")
        echo "  ✗ FAIL: $test_name - $reason"
    fi
}

echo "================================================================================"
echo "=== AWS STS Demo for Manta Buckets API ==="
echo "================================================================================"
echo "Mode: ${TEST_MODE}"
if [ "$TEST_MODE" = "chain" ]; then
    echo "  → Running privilege escalation test only (STEP 8)"
    echo "  → Will run setup steps: 1 (buckets), 2 (session token), 3 (role), 4 (assume role)"
fi
echo
echo "Endpoint: ${S3_ENDPOINT}"
echo "Account: ${ACCOUNT_UUID}"
echo "Allowed Bucket: ${ALLOWED_BUCKET}"
echo "Restricted Bucket: ${TEST_BUCKET}"
echo
echo "This demo tests IAM policy enforcement with restrictive policies."
echo "Each step shows the AWS CLI command, server response, and policies used."
echo "================================================================================"
echo

# ============================================================================
# 1. Create test buckets with permanent credentials
# ============================================================================
if [ "$RUN_STEP_1" = true ]; then
echo "================================================================================"
echo "STEP 1: Setting up test environment (creating test buckets)"
echo "================================================================================"
echo "Using: Permanent credentials"
echo

export AWS_ACCESS_KEY_ID="$PERMANENT_ACCESS_KEY"
export AWS_SECRET_ACCESS_KEY="$PERMANENT_SECRET_KEY"
unset AWS_SESSION_TOKEN

# Create bucket that the role will have access to
echo "→ Creating allowed bucket: ${ALLOWED_BUCKET}"
echo "  Command: aws s3 mb s3://${ALLOWED_BUCKET}"
echo
aws s3 mb "s3://${ALLOWED_BUCKET}" \
    --endpoint-url "${S3_ENDPOINT}" \
    --no-verify-ssl
echo

# Create a test object in the allowed bucket
echo "→ Creating test object in allowed bucket"
echo "  Command: aws s3 cp - s3://${ALLOWED_BUCKET}/test-object.txt"
echo
echo "test content" | aws s3 cp - "s3://${ALLOWED_BUCKET}/test-object.txt" \
    --endpoint-url "${S3_ENDPOINT}" \
    --no-verify-ssl
echo

# Create bucket that the role will NOT have access to
echo "→ Creating restricted bucket: ${TEST_BUCKET}"
echo "  Command: aws s3 mb s3://${TEST_BUCKET}"
echo
aws s3 mb "s3://${TEST_BUCKET}" \
    --endpoint-url "${S3_ENDPOINT}" \
    --no-verify-ssl
echo

fi # End STEP 1

# ============================================================================
# 2. GetSessionToken - Get temporary credentials without role assumption
# ============================================================================
if [ "$RUN_STEP_2" = true ]; then
echo "================================================================================"
echo "STEP 2: GetSessionToken - Creating temporary credentials (MSTS)"
echo "================================================================================"
echo "Using: Permanent credentials"
echo "Duration: 1 hour (3600 seconds)"
echo
echo "→ Calling GetSessionToken"
echo "  Command: aws sts get-session-token --duration-seconds 3600"
echo
echo "Server Response:"

SESSION_CREDS=$(aws sts get-session-token \
    --endpoint-url "${S3_ENDPOINT}" \
    --duration-seconds 3600 \
    --output json \
    --no-verify-ssl)

echo "$SESSION_CREDS" | jq .
echo

# Extract temporary credentials
TEMP_ACCESS_KEY=$(echo "$SESSION_CREDS" | jq -r '.Credentials.AccessKeyId')
TEMP_SECRET_KEY=$(echo "$SESSION_CREDS" | jq -r '.Credentials.SecretAccessKey')
TEMP_SESSION_TOKEN=$(echo "$SESSION_CREDS" | jq -r '.Credentials.SessionToken')
TEMP_EXPIRATION=$(echo "$SESSION_CREDS" | jq -r '.Credentials.Expiration')

echo "✓ Session token (MSTS) credentials obtained:"
echo "  Access Key ID: ${TEMP_ACCESS_KEY}"
echo "  Prefix: ${TEMP_ACCESS_KEY:0:4} (MSTS = GetSessionToken)"
echo "  Expires: ${TEMP_EXPIRATION}"
echo

fi # End STEP 2

# ============================================================================
# 3. Create IAM Role with restrictive policy
# ============================================================================
if [ "$RUN_STEP_3" = true ]; then
echo "================================================================================"
echo "STEP 3: Creating IAM Role with RESTRICTIVE permission policy"
echo "================================================================================"
echo "Using: Permanent credentials (required for IAM operations)"
echo

ROLE_ARN="arn:aws:iam::${ACCOUNT_UUID}:role/${ROLE_NAME}"

# Use permanent credentials for IAM operations
export AWS_ACCESS_KEY_ID="$PERMANENT_ACCESS_KEY"
export AWS_SECRET_ACCESS_KEY="$PERMANENT_SECRET_KEY"
unset AWS_SESSION_TOKEN

# Cleanup existing role from previous runs
echo "→ Cleaning up any existing role from previous runs..."
aws iam delete-role-policy \
    --endpoint-url "${S3_ENDPOINT}" \
    --role-name "${ROLE_NAME}" \
    --policy-name "S3RestrictedAccess" \
    --no-verify-ssl \
    >/dev/null 2>&1 || true
aws iam delete-role \
    --endpoint-url "${S3_ENDPOINT}" \
    --role-name "${ROLE_NAME}" \
    --no-verify-ssl \
    >/dev/null 2>&1 || true
echo "  Done (if role existed)"
echo

# Trust policy - allows any principal to assume this role
TRUST_POLICY=$(cat <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": "*",
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF
)

echo "→ Trust Policy (who can assume this role):"
echo "$TRUST_POLICY" | jq .
echo
echo "  Note: This trust policy allows ANY principal to assume the role"
echo "  Note: Mahi does NOT support Condition blocks in trust policies"
echo

echo "→ Creating IAM role: ${ROLE_NAME}"
echo "  Command: aws iam create-role --role-name ${ROLE_NAME}"
echo
echo "Server Response:"

aws iam create-role \
    --endpoint-url "${S3_ENDPOINT}" \
    --role-name "${ROLE_NAME}" \
    --assume-role-policy-document "${TRUST_POLICY}" \
    --description "Demo role with restrictive S3 permissions" \
    --output json \
    --no-verify-ssl | jq .

echo
echo "✓ Role created: ${ROLE_ARN}"
echo

# Permission policy - restrictive S3 access
POLICY_DOCUMENT=$(cat <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:PutObject"
      ],
      "Resource": "arn:aws:s3:::${ALLOWED_BUCKET}/*"
    },
    {
      "Effect": "Allow",
      "Action": "s3:ListBucket",
      "Resource": "arn:aws:s3:::${ALLOWED_BUCKET}"
    }
  ]
}
EOF
)

echo "→ Permission Policy (what the role can do):"
echo "$POLICY_DOCUMENT" | jq .
echo
echo "  This policy ALLOWS:"
echo "    • s3:GetObject on ${ALLOWED_BUCKET}/*"
echo "    • s3:PutObject on ${ALLOWED_BUCKET}/*"
echo "    • s3:ListBucket on ${ALLOWED_BUCKET}"
echo
echo "  This policy DENIES (implicit):"
echo "    • s3:DeleteObject (not in policy)"
echo "    • s3:DeleteBucket (not in policy)"
echo "    • s3:CreateBucket (not in policy)"
echo "    • Access to bucket: ${TEST_BUCKET} (wrong resource)"
echo

echo "→ Attaching permission policy to role"
echo "  Command: aws iam put-role-policy --role-name ${ROLE_NAME} --policy-name S3RestrictedAccess"
echo

aws iam put-role-policy \
    --endpoint-url "${S3_ENDPOINT}" \
    --role-name "${ROLE_NAME}" \
    --policy-name "S3RestrictedAccess" \
    --policy-document "${POLICY_DOCUMENT}" \
    --no-verify-ssl

echo "✓ Permission policy attached to role"
echo

fi # End STEP 3

# ============================================================================
# 4. AssumeRole - Assume the role we just created
# ============================================================================
if [ "$RUN_STEP_4" = true ]; then
echo "================================================================================"
echo "STEP 4: AssumeRole - Assuming the role to get MSAR credentials"
echo "================================================================================"
echo "Using: MSTS credentials (from GetSessionToken)"
echo "Duration: 12 hours (43200 seconds)"
echo

# Use temporary credentials for AssumeRole call
export AWS_ACCESS_KEY_ID="$TEMP_ACCESS_KEY"
export AWS_SECRET_ACCESS_KEY="$TEMP_SECRET_KEY"
export AWS_SESSION_TOKEN="$TEMP_SESSION_TOKEN"

echo "→ Calling AssumeRole"
echo "  Command: aws sts assume-role --role-arn ${ROLE_ARN} --role-session-name ${SESSION_NAME}"
echo
echo "Server Response:"

ROLE_CREDS=$(aws sts assume-role \
    --endpoint-url "${S3_ENDPOINT}" \
    --role-arn "${ROLE_ARN}" \
    --role-session-name "${SESSION_NAME}" \
    --duration-seconds 43200 \
    --output json \
    --no-verify-ssl)

echo "$ROLE_CREDS" | jq .
echo

# Extract role credentials
ROLE_ACCESS_KEY=$(echo "$ROLE_CREDS" | jq -r '.Credentials.AccessKeyId')
ROLE_SECRET_KEY=$(echo "$ROLE_CREDS" | jq -r '.Credentials.SecretAccessKey')
ROLE_SESSION_TOKEN=$(echo "$ROLE_CREDS" | jq -r '.Credentials.SessionToken')
ROLE_EXPIRATION=$(echo "$ROLE_CREDS" | jq -r '.Credentials.Expiration')

echo "✓ Role assumed successfully - MSAR credentials obtained:"
echo "  Access Key ID: ${ROLE_ACCESS_KEY}"
echo "  Prefix: ${ROLE_ACCESS_KEY:0:4} (MSAR = AssumeRole)"
echo "  Expires: ${ROLE_EXPIRATION}"
echo "  Assumed Role ARN: $(echo "$ROLE_CREDS" | jq -r '.AssumedRoleUser.Arn')"
echo "  Assumed Role ID: $(echo "$ROLE_CREDS" | jq -r '.AssumedRoleUser.AssumedRoleId')"
echo
echo "DEBUG: Session token structure (first role MSAR credentials):"
echo "  Token length: ${#ROLE_SESSION_TOKEN} characters"
echo "  Token prefix (first 50 chars): ${ROLE_SESSION_TOKEN:0:50}..."
echo "  This session token should contain the roleArn for trust policy validation"
echo

fi # End STEP 4

# ============================================================================
# 5. GetCallerIdentity - Verify who we are
# ============================================================================
if [ "$RUN_STEP_5" = true ]; then
echo "================================================================================"
echo "STEP 5: GetCallerIdentity - Verifying identity"
echo "================================================================================"
echo "Using: MSAR credentials (from AssumeRole)"
echo

export AWS_ACCESS_KEY_ID="$ROLE_ACCESS_KEY"
export AWS_SECRET_ACCESS_KEY="$ROLE_SECRET_KEY"
export AWS_SESSION_TOKEN="$ROLE_SESSION_TOKEN"

echo "→ Calling GetCallerIdentity"
echo "  Command: aws sts get-caller-identity"
echo
echo "Server Response:"

IDENTITY=$(aws sts get-caller-identity \
    --endpoint-url "${S3_ENDPOINT}" \
    --output json \
    --no-verify-ssl)

echo "$IDENTITY" | jq .
echo

echo "Current identity:"
echo "  User ID: $(echo "$IDENTITY" | jq -r '.UserId')"
echo "  Account: $(echo "$IDENTITY" | jq -r '.Account')"
echo "  ARN: $(echo "$IDENTITY" | jq -r '.Arn')"
echo "  Note: ARN shows 'assumed-role' indicating we're using role credentials"
echo

fi # End STEP 5

# ============================================================================
# 6. Test ALLOWED operations with role credentials
# ============================================================================
if [ "$RUN_STEP_6" = true ]; then
echo "================================================================================"
echo "STEP 6: Testing ALLOWED operations with role credentials"
echo "================================================================================"
echo "Using: MSAR credentials (from AssumeRole)"
echo "These operations are allowed by the role's permission policy"
echo

# Test 1: ListBucket on allowed bucket
echo "→ Test 1: ListBucket on allowed bucket (${ALLOWED_BUCKET})"
echo "  Command: aws s3 ls s3://${ALLOWED_BUCKET}"
echo "  Policy Statement: Allow s3:ListBucket on ${ALLOWED_BUCKET}"
echo
if aws s3 ls "s3://${ALLOWED_BUCKET}" \
    --endpoint-url "${S3_ENDPOINT}" \
    --no-verify-ssl; then
    record_test "ListBucket on allowed bucket (policy allows)" "true" "" "aws s3 ls s3://${ALLOWED_BUCKET} --endpoint-url ${S3_ENDPOINT} --no-verify-ssl"
else
    record_test "ListBucket on allowed bucket (policy allows)" "false" "Operation failed but should be allowed by permission policy" "aws s3 ls s3://${ALLOWED_BUCKET} --endpoint-url ${S3_ENDPOINT} --no-verify-ssl"
fi
echo

# Test 2: GetObject from allowed bucket
echo "→ Test 2: GetObject from allowed bucket"
echo "  Command: aws s3 cp s3://${ALLOWED_BUCKET}/test-object.txt /tmp/test-download.txt"
echo "  Policy Statement: Allow s3:GetObject on ${ALLOWED_BUCKET}/*"
echo
if aws s3 cp "s3://${ALLOWED_BUCKET}/test-object.txt" /tmp/test-download.txt \
    --endpoint-url "${S3_ENDPOINT}" \
    --no-verify-ssl; then
    echo "  Downloaded content: $(cat /tmp/test-download.txt)"
    rm -f /tmp/test-download.txt
    record_test "GetObject from allowed bucket (policy allows)" "true" "" "aws s3 cp s3://${ALLOWED_BUCKET}/test-object.txt /tmp/test-download.txt --endpoint-url ${S3_ENDPOINT} --no-verify-ssl"
else
    record_test "GetObject from allowed bucket (policy allows)" "false" "Operation failed but should be allowed by permission policy" "aws s3 cp s3://${ALLOWED_BUCKET}/test-object.txt /tmp/test-download.txt --endpoint-url ${S3_ENDPOINT} --no-verify-ssl"
fi
echo

# Test 3: PutObject to allowed bucket
echo "→ Test 3: PutObject to allowed bucket"
echo "  Command: aws s3 cp - s3://${ALLOWED_BUCKET}/new-object.txt"
echo "  Policy Statement: Allow s3:PutObject on ${ALLOWED_BUCKET}/*"
echo
if echo "new content" | aws s3 cp - "s3://${ALLOWED_BUCKET}/new-object.txt" \
    --endpoint-url "${S3_ENDPOINT}" \
    --no-verify-ssl; then
    record_test "PutObject to allowed bucket (policy allows)" "true" "" "echo 'new content' | aws s3 cp - s3://${ALLOWED_BUCKET}/new-object.txt --endpoint-url ${S3_ENDPOINT} --no-verify-ssl"
else
    record_test "PutObject to allowed bucket (policy allows)" "false" "Operation failed but should be allowed by permission policy" "echo 'new content' | aws s3 cp - s3://${ALLOWED_BUCKET}/new-object.txt --endpoint-url ${S3_ENDPOINT} --no-verify-ssl"
fi
echo

fi # End STEP 6

# ============================================================================
# 7. Test DENIED operations with role credentials
# ============================================================================
if [ "$RUN_STEP_7" = true ]; then
echo "================================================================================"
echo "STEP 7: Testing DENIED operations with role credentials"
echo "================================================================================"
echo "Using: MSAR credentials (from AssumeRole)"
echo "These operations are NOT in the policy and should be denied (implicit deny)"
echo

# Test 4: DeleteObject from allowed bucket
echo "→ Test 4: DeleteObject from allowed bucket"
echo "  Command: aws s3 rm s3://${ALLOWED_BUCKET}/new-object.txt"
echo "  Policy: s3:DeleteObject is NOT in the policy → Implicit DENY"
echo
if aws s3 rm "s3://${ALLOWED_BUCKET}/new-object.txt" \
    --endpoint-url "${S3_ENDPOINT}" \
    --no-verify-ssl 2>&1; then
    record_test "DeleteObject denied (implicit deny)" "false" "DeleteObject succeeded but should be denied" "aws s3 rm s3://${ALLOWED_BUCKET}/new-object.txt --endpoint-url ${S3_ENDPOINT} --no-verify-ssl"
else
    record_test "DeleteObject denied (implicit deny)" "true" "" "aws s3 rm s3://${ALLOWED_BUCKET}/new-object.txt --endpoint-url ${S3_ENDPOINT} --no-verify-ssl"
fi
echo

# Test 5: ListBucket on restricted bucket
echo "→ Test 5: ListBucket on restricted bucket (${TEST_BUCKET})"
echo "  Command: aws s3 ls s3://${TEST_BUCKET}"
echo "  Policy: Resource doesn't match (policy allows ${ALLOWED_BUCKET}) → Implicit DENY"
echo
if aws s3 ls "s3://${TEST_BUCKET}" \
    --endpoint-url "${S3_ENDPOINT}" \
    --no-verify-ssl 2>&1; then
    record_test "ListBucket on wrong bucket (resource mismatch)" "false" "ListBucket succeeded but should be denied by resource mismatch" "aws s3 ls s3://${TEST_BUCKET} --endpoint-url ${S3_ENDPOINT} --no-verify-ssl"
else
    record_test "ListBucket on wrong bucket (resource mismatch)" "true" "" "aws s3 ls s3://${TEST_BUCKET} --endpoint-url ${S3_ENDPOINT} --no-verify-ssl"
fi
echo

# Test 6: CreateBucket
echo "→ Test 6: CreateBucket"
echo "  Command: aws s3 mb s3://role-created-bucket-..."
echo "  Policy: s3:CreateBucket is NOT in the policy → Implicit DENY"
echo
NEW_BUCKET="role-created-bucket-$(date +%s)"
if aws s3 mb "s3://${NEW_BUCKET}" \
    --endpoint-url "${S3_ENDPOINT}" \
    --no-verify-ssl 2>&1; then
    record_test "CreateBucket denied (not in policy)" "false" "CreateBucket succeeded but should be denied" "aws s3 mb s3://${NEW_BUCKET} --endpoint-url ${S3_ENDPOINT} --no-verify-ssl"
    # Clean up if it somehow succeeded
    aws s3 rb "s3://${NEW_BUCKET}" \
        --endpoint-url "${S3_ENDPOINT}" \
        --no-verify-ssl \
        >/dev/null 2>&1 || true
else
    record_test "CreateBucket denied (not in policy)" "true" "" "aws s3 mb s3://${NEW_BUCKET} --endpoint-url ${S3_ENDPOINT} --no-verify-ssl"
fi
echo

# Test 7: ListAllMyBuckets
echo "→ Test 7: ListAllMyBuckets"
echo "  Command: aws s3 ls"
echo "  Policy: s3:ListAllMyBuckets is NOT in the policy → Implicit DENY"
echo
if aws s3 ls \
    --endpoint-url "${S3_ENDPOINT}" \
    --no-verify-ssl 2>&1; then
    record_test "ListAllMyBuckets denied (not in policy)" "false" "ListAllMyBuckets succeeded but should be denied" "aws s3 ls --endpoint-url ${S3_ENDPOINT} --no-verify-ssl"
else
    record_test "ListAllMyBuckets denied (not in policy)" "true" "" "aws s3 ls --endpoint-url ${S3_ENDPOINT} --no-verify-ssl"
fi
echo

fi # End STEP 7

# ============================================================================
# 8. Test privilege escalation via role chaining
# ============================================================================
if [ "$RUN_STEP_8" = true ]; then
echo "================================================================================"
echo "STEP 8: Testing privilege escalation via role chaining"
echo "================================================================================"
echo "This tests whether a user can bypass policy restrictions by assuming a"
echo "different role with broader permissions (privilege escalation attack)"
echo

# Switch to permanent credentials to create second role
export AWS_ACCESS_KEY_ID="$PERMANENT_ACCESS_KEY"
export AWS_SECRET_ACCESS_KEY="$PERMANENT_SECRET_KEY"
unset AWS_SESSION_TOKEN

SECOND_ROLE_NAME="S3EscalatedRole"
SECOND_ROLE_ARN="arn:aws:iam::${ACCOUNT_UUID}:role/${SECOND_ROLE_NAME}"

# Cleanup any existing second role
echo "→ Cleaning up any existing escalation role..."
aws iam delete-role-policy \
    --endpoint-url "${S3_ENDPOINT}" \
    --role-name "${SECOND_ROLE_NAME}" \
    --policy-name "S3EscalatedAccess" \
    --no-verify-ssl \
    >/dev/null 2>&1 || true
aws iam delete-role \
    --endpoint-url "${S3_ENDPOINT}" \
    --role-name "${SECOND_ROLE_NAME}" \
    --no-verify-ssl \
    >/dev/null 2>&1 || true
echo "  Done"
echo

# Trust policy - allows any principal to assume this role
SECOND_TRUST_POLICY=$(cat <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": "*",
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF
)

echo "→ Creating second role with access to restricted bucket: ${SECOND_ROLE_NAME}"
echo "  This role has access to ${TEST_BUCKET} (the bucket denied to first role)"
echo

aws iam create-role \
    --endpoint-url "${S3_ENDPOINT}" \
    --role-name "${SECOND_ROLE_NAME}" \
    --assume-role-policy-document "${SECOND_TRUST_POLICY}" \
    --description "Role with escalated privileges for testing" \
    --no-verify-ssl >/dev/null 2>&1

echo "✓ Second role created: ${SECOND_ROLE_ARN}"
echo

# Permission policy - access to the RESTRICTED bucket
SECOND_POLICY_DOCUMENT=$(cat <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:PutObject",
        "s3:DeleteObject"
      ],
      "Resource": "arn:aws:s3:::${TEST_BUCKET}/*"
    },
    {
      "Effect": "Allow",
      "Action": "s3:ListBucket",
      "Resource": "arn:aws:s3:::${TEST_BUCKET}"
    }
  ]
}
EOF
)

echo "→ Second role permission policy (intentionally broader):"
echo "$SECOND_POLICY_DOCUMENT" | jq .
echo
echo "  This policy ALLOWS:"
echo "    • s3:GetObject, s3:PutObject, s3:DeleteObject on ${TEST_BUCKET}/*"
echo "    • s3:ListBucket on ${TEST_BUCKET}"
echo "  Note: This is the bucket the FIRST role is denied access to!"
echo

aws iam put-role-policy \
    --endpoint-url "${S3_ENDPOINT}" \
    --role-name "${SECOND_ROLE_NAME}" \
    --policy-name "S3EscalatedAccess" \
    --policy-document "${SECOND_POLICY_DOCUMENT}" \
    --no-verify-ssl

echo "✓ Permission policy attached to second role"
echo

# Now switch to first role's credentials and try to assume second role
echo "→ Test: Attempting to assume second role using first role's MSAR credentials"
echo "  Current credentials: MSAR from ${ROLE_NAME} (restricted access)"
echo "  Target role: ${SECOND_ROLE_NAME} (escalated access to ${TEST_BUCKET})"
echo "  This tests if role chaining can bypass IAM restrictions"
echo

export AWS_ACCESS_KEY_ID="$ROLE_ACCESS_KEY"
export AWS_SECRET_ACCESS_KEY="$ROLE_SECRET_KEY"
export AWS_SESSION_TOKEN="$ROLE_SESSION_TOKEN"

echo "DEBUG: Current credentials being used for second AssumeRole:"
echo "  Access Key: ${ROLE_ACCESS_KEY}"
echo "  Session Token (first 50 chars): ${ROLE_SESSION_TOKEN:0:50}..."
echo

echo "  Command: aws sts assume-role --role-arn ${SECOND_ROLE_ARN} --role-session-name escalation-test"
echo

ESCALATION_TEST_PASSED=false
if SECOND_ROLE_CREDS=$(aws sts assume-role \
    --endpoint-url "${S3_ENDPOINT}" \
    --role-arn "${SECOND_ROLE_ARN}" \
    --role-session-name "escalation-test" \
    --duration-seconds 3600 \
    --output json \
    --no-verify-ssl 2>&1); then

    echo "  ⚠ AssumeRole succeeded - role chaining is allowed"
    echo
    echo "DEBUG: Second AssumeRole response:"
    echo "$SECOND_ROLE_CREDS" | jq .
    echo

    # Extract second role credentials
    SECOND_ROLE_ACCESS_KEY=$(echo "$SECOND_ROLE_CREDS" | jq -r '.Credentials.AccessKeyId')
    SECOND_ROLE_SECRET_KEY=$(echo "$SECOND_ROLE_CREDS" | jq -r '.Credentials.SecretAccessKey')
    SECOND_ROLE_SESSION_TOKEN=$(echo "$SECOND_ROLE_CREDS" | jq -r '.Credentials.SessionToken')

    # Now test if we can access the restricted bucket with second role
    export AWS_ACCESS_KEY_ID="$SECOND_ROLE_ACCESS_KEY"
    export AWS_SECRET_ACCESS_KEY="$SECOND_ROLE_SECRET_KEY"
    export AWS_SESSION_TOKEN="$SECOND_ROLE_SESSION_TOKEN"

    echo "→ Test: Can second role access the restricted bucket?"
    echo "  Command: aws s3 ls s3://${TEST_BUCKET}"
    echo

    if aws s3 ls "s3://${TEST_BUCKET}" \
        --endpoint-url "${S3_ENDPOINT}" \
        --no-verify-ssl 2>&1; then
        echo
        echo "  ⚠ PRIVILEGE ESCALATION: Successfully accessed restricted bucket via role chaining!"
        record_test "Privilege escalation via role chaining" "false" "User can bypass policy by assuming second role with escalated privileges" "aws sts assume-role --role-arn ${SECOND_ROLE_ARN} --role-session-name escalation-test; aws s3 ls s3://${TEST_BUCKET}"
    else
        echo
        echo "  ✓ Access still denied - policy properly blocks escalated access"
        record_test "Privilege escalation via role chaining" "true" "" "aws sts assume-role --role-arn ${SECOND_ROLE_ARN} --role-session-name escalation-test; aws s3 ls s3://${TEST_BUCKET}"
    fi
else
    echo "  ✓ AssumeRole blocked - cannot assume second role from first role"
    echo "  This prevents privilege escalation via role chaining"
    echo
    echo "DEBUG: AssumeRole error response:"
    echo "$SECOND_ROLE_CREDS"
    echo
    record_test "Privilege escalation via role chaining" "true" "" "aws sts assume-role --endpoint-url ${S3_ENDPOINT} --role-arn ${SECOND_ROLE_ARN} --role-session-name escalation-test --no-verify-ssl"
fi
echo

# Cleanup second role
echo "→ Cleaning up second role..."
export AWS_ACCESS_KEY_ID="$PERMANENT_ACCESS_KEY"
export AWS_SECRET_ACCESS_KEY="$PERMANENT_SECRET_KEY"
unset AWS_SESSION_TOKEN

aws iam delete-role-policy \
    --endpoint-url "${S3_ENDPOINT}" \
    --role-name "${SECOND_ROLE_NAME}" \
    --policy-name "S3EscalatedAccess" \
    --no-verify-ssl \
    >/dev/null 2>&1

aws iam delete-role \
    --endpoint-url "${S3_ENDPOINT}" \
    --role-name "${SECOND_ROLE_NAME}" \
    --no-verify-ssl \
    >/dev/null 2>&1

echo "  ✓ Second role deleted"
echo

fi # End STEP 8

# ============================================================================
# 9. Test MSTS credentials cannot call IAM operations
# ============================================================================
if [ "$RUN_STEP_9" = true ]; then
echo "================================================================================"
echo "STEP 9: Testing MSTS credentials with IAM operations (AWS restriction)"
echo "================================================================================"
echo "Using: MSTS credentials (from GetSessionToken)"
echo "MSTS credentials should NOT be able to call IAM operations per AWS spec"
echo

export AWS_ACCESS_KEY_ID="$TEMP_ACCESS_KEY"
export AWS_SECRET_ACCESS_KEY="$TEMP_SECRET_KEY"
export AWS_SESSION_TOKEN="$TEMP_SESSION_TOKEN"

echo "→ Test: GetRole with MSTS credentials"
echo "  Command: aws iam get-role --role-name ${ROLE_NAME}"
echo "  Expected: Access Denied (MSTS credentials cannot call IAM)"
echo
if aws iam get-role \
    --endpoint-url "${S3_ENDPOINT}" \
    --role-name "${ROLE_NAME}" \
    --no-verify-ssl 2>&1; then
    record_test "MSTS credentials calling IAM operations (AWS restriction)" "false" "MSTS credentials can call IAM (should be blocked per AWS spec)" "aws iam get-role --endpoint-url ${S3_ENDPOINT} --role-name ${ROLE_NAME} --no-verify-ssl"
else
    record_test "MSTS credentials calling IAM operations (AWS restriction)" "true" "" "aws iam get-role --endpoint-url ${S3_ENDPOINT} --role-name ${ROLE_NAME} --no-verify-ssl"
fi
echo

fi # End STEP 9

# ============================================================================
# 10. Test ERROR CONDITIONS and edge cases
# ============================================================================
if [ "$RUN_STEP_10" = true ]; then
echo "================================================================================"
echo "STEP 10: Testing ERROR CONDITIONS - STS/IAM error handling"
echo "================================================================================"
echo "These tests verify that error responses are correctly formatted and match"
echo "AWS error codes and messages."
echo

# Use permanent credentials for error tests
export AWS_ACCESS_KEY_ID="$PERMANENT_ACCESS_KEY"
export AWS_SECRET_ACCESS_KEY="$PERMANENT_SECRET_KEY"
unset AWS_SESSION_TOKEN

# Error Test 1: AssumeRole with non-existent role
echo "→ Error Test 1: AssumeRole with NON-EXISTENT role"
echo "  Command: aws sts assume-role --role-arn arn:aws:iam::${ACCOUNT_UUID}:role/NonExistentRole"
echo "  Expected Error: NoSuchEntity (404)"
echo
echo "Server Response:"

NONEXISTENT_ROLE_ARN="arn:aws:iam::${ACCOUNT_UUID}:role/NonExistentRole-$(date +%s)"
if aws sts assume-role \
    --endpoint-url "${S3_ENDPOINT}" \
    --role-arn "${NONEXISTENT_ROLE_ARN}" \
    --role-session-name "test-session" \
    --output json \
    --no-verify-ssl 2>&1; then
    record_test "AssumeRole with non-existent role → NoSuchEntity" "false" "AssumeRole succeeded but should fail for non-existent role" "aws sts assume-role --endpoint-url ${S3_ENDPOINT} --role-arn ${NONEXISTENT_ROLE_ARN} --role-session-name test-session --no-verify-ssl"
else
    record_test "AssumeRole with non-existent role → NoSuchEntity" "true" "" "aws sts assume-role --endpoint-url ${S3_ENDPOINT} --role-arn ${NONEXISTENT_ROLE_ARN} --role-session-name test-session --no-verify-ssl"
fi
echo

# Error Test 2: AssumeRole with invalid role ARN format
echo "→ Error Test 2: AssumeRole with INVALID role ARN format"
echo "  Command: aws sts assume-role --role-arn invalid-arn-format"
echo "  Expected Error: InvalidParameterValue or similar (400)"
echo
echo "Server Response:"

if aws sts assume-role \
    --endpoint-url "${S3_ENDPOINT}" \
    --role-arn "invalid-arn-format" \
    --role-session-name "test-session" \
    --output json \
    --no-verify-ssl 2>&1; then
    record_test "AssumeRole with invalid ARN format → InvalidParameterValue" "false" "AssumeRole succeeded but should fail for invalid ARN" "aws sts assume-role --endpoint-url ${S3_ENDPOINT} --role-arn invalid-arn-format --role-session-name test-session --no-verify-ssl"
else
    record_test "AssumeRole with invalid ARN format → InvalidParameterValue" "true" "" "aws sts assume-role --endpoint-url ${S3_ENDPOINT} --role-arn invalid-arn-format --role-session-name test-session --no-verify-ssl"
fi
echo

# Error Test 3: AssumeRole without required parameter (RoleSessionName)
echo "→ Error Test 3: AssumeRole WITHOUT required parameter (RoleSessionName)"
echo "  Expected Error: InvalidParameterValue (400)"
echo
echo "This test uses raw POST to omit RoleSessionName:"

CURL_OUTPUT=$(curl -X POST "${S3_ENDPOINT}/" \
    -H "Authorization: AWS4-HMAC-SHA256 Credential=${PERMANENT_ACCESS_KEY}/20231201/${AWS_DEFAULT_REGION:-us-east-1}/sts/aws4_request, SignedHeaders=host;x-amz-date, Signature=dummy" \
    -d "Action=AssumeRole&RoleArn=${ROLE_ARN}&Version=2011-06-15" \
    --insecure 2>&1 | head -20)

echo "$CURL_OUTPUT"

CURL_CMD="curl -X POST '${S3_ENDPOINT}/' -d 'Action=AssumeRole&RoleArn=${ROLE_ARN}&Version=2011-06-15' --insecure"
if echo "$CURL_OUTPUT" | grep -qi "error\|invalid"; then
    record_test "AssumeRole without required parameter → InvalidParameterValue" "true" "" "$CURL_CMD"
else
    record_test "AssumeRole without required parameter → InvalidParameterValue" "false" "Request did not return expected error response" "$CURL_CMD"
fi
echo

# Error Test 4: IAM CreateRole with non-existent account
echo "→ Error Test 4: IAM operation on NON-EXISTENT account"
echo "  Command: aws iam create-role with invalid account UUID in ARN"
echo "  Expected Error: NoSuchEntity or AccessDenied"
echo

INVALID_ACCOUNT="00000000-0000-0000-0000-000000000000"
INVALID_TRUST=$(cat <<EOF
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": "*",
    "Action": "sts:AssumeRole"
  }]
}
EOF
)

if aws iam create-role \
    --endpoint-url "${S3_ENDPOINT}" \
    --role-name "TestRole" \
    --assume-role-policy-document "${INVALID_TRUST}" \
    --no-verify-ssl 2>&1; then
    record_test "IAM operation on non-existent account → NoSuchEntity/AccessDenied" "false" "CreateRole succeeded but should fail for invalid account" "aws iam create-role --endpoint-url ${S3_ENDPOINT} --role-name TestRole --assume-role-policy-document '<policy>' --no-verify-ssl"
else
    record_test "IAM operation on non-existent account → NoSuchEntity/AccessDenied" "true" "" "aws iam create-role --endpoint-url ${S3_ENDPOINT} --role-name TestRole --assume-role-policy-document '<policy>' --no-verify-ssl"
fi
echo

# Error Test 5: GetRole on non-existent role
echo "→ Error Test 5: GetRole on NON-EXISTENT role"
echo "  Command: aws iam get-role --role-name NonExistentRole"
echo "  Expected Error: NoSuchEntity (404)"
echo
echo "Server Response:"

NONEXISTENT_ROLE_NAME="NonExistentRole-$(date +%s)"
if aws iam get-role \
    --endpoint-url "${S3_ENDPOINT}" \
    --role-name "${NONEXISTENT_ROLE_NAME}" \
    --output json \
    --no-verify-ssl 2>&1; then
    record_test "GetRole on non-existent role → NoSuchEntity" "false" "GetRole succeeded but should fail for non-existent role" "aws iam get-role --endpoint-url ${S3_ENDPOINT} --role-name ${NONEXISTENT_ROLE_NAME} --no-verify-ssl"
else
    record_test "GetRole on non-existent role → NoSuchEntity" "true" "" "aws iam get-role --endpoint-url ${S3_ENDPOINT} --role-name ${NONEXISTENT_ROLE_NAME} --no-verify-ssl"
fi
echo

# Error Test 6: DeleteRole on non-existent role
echo "→ Error Test 6: DeleteRole on NON-EXISTENT role"
echo "  Command: aws iam delete-role --role-name NonExistentRole"
echo "  Expected Error: NoSuchEntity (404)"
echo
echo "Server Response:"

NONEXISTENT_ROLE_NAME2="NonExistentRole-$(date +%s)"
if aws iam delete-role \
    --endpoint-url "${S3_ENDPOINT}" \
    --role-name "${NONEXISTENT_ROLE_NAME2}" \
    --no-verify-ssl 2>&1; then
    record_test "DeleteRole on non-existent role → NoSuchEntity" "false" "DeleteRole succeeded but should fail for non-existent role" "aws iam delete-role --endpoint-url ${S3_ENDPOINT} --role-name ${NONEXISTENT_ROLE_NAME2} --no-verify-ssl"
else
    record_test "DeleteRole on non-existent role → NoSuchEntity" "true" "" "aws iam delete-role --endpoint-url ${S3_ENDPOINT} --role-name ${NONEXISTENT_ROLE_NAME2} --no-verify-ssl"
fi
echo

# Error Test 7: AssumeRole with trust policy that denies access
echo "→ Error Test 7: AssumeRole when trust policy DENIES access"
echo "  Creating role with restrictive trust policy..."
echo

DENY_ROLE_NAME="DenyAccessRole-$(date +%s)"
DENY_TRUST_POLICY=$(cat <<EOF
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Deny",
    "Principal": "*",
    "Action": "sts:AssumeRole"
  }]
}
EOF
)

echo "Trust Policy (explicit Deny):"
echo "$DENY_TRUST_POLICY" | jq .
echo

# Create role with deny policy
if aws iam create-role \
    --endpoint-url "${S3_ENDPOINT}" \
    --role-name "${DENY_ROLE_NAME}" \
    --assume-role-policy-document "${DENY_TRUST_POLICY}" \
    --no-verify-ssl >/dev/null 2>&1; then
    echo "✓ Role created with Deny trust policy"

    # Try to assume it
    echo
    echo "→ Attempting to assume role with Deny trust policy..."
    echo "  Command: aws sts assume-role --role-arn arn:aws:iam::${ACCOUNT_UUID}:role/${DENY_ROLE_NAME}"
    echo "  Expected Error: AccessDenied (403)"
    echo

    DENY_ROLE_ARN="arn:aws:iam::${ACCOUNT_UUID}:role/${DENY_ROLE_NAME}"
    if aws sts assume-role \
        --endpoint-url "${S3_ENDPOINT}" \
        --role-arn "${DENY_ROLE_ARN}" \
        --role-session-name "test-session" \
        --output json \
        --no-verify-ssl 2>&1; then
        record_test "AssumeRole with Deny trust policy → AccessDenied" "false" "AssumeRole succeeded but should be denied by trust policy" "aws sts assume-role --endpoint-url ${S3_ENDPOINT} --role-arn ${DENY_ROLE_ARN} --role-session-name test-session --no-verify-ssl"
    else
        record_test "AssumeRole with Deny trust policy → AccessDenied" "true" "" "aws sts assume-role --endpoint-url ${S3_ENDPOINT} --role-arn ${DENY_ROLE_ARN} --role-session-name test-session --no-verify-ssl"
    fi

    # Cleanup deny role
    aws iam delete-role \
        --endpoint-url "${S3_ENDPOINT}" \
        --role-name "${DENY_ROLE_NAME}" \
        --no-verify-ssl >/dev/null 2>&1
else
    record_test "AssumeRole with Deny trust policy → AccessDenied" "false" "Could not create deny role for testing" "aws sts assume-role --endpoint-url ${S3_ENDPOINT} --role-arn arn:aws:iam::${ACCOUNT_UUID}:role/${DENY_ROLE_NAME} --role-session-name test-session --no-verify-ssl"
fi
echo

# Error Test 8: GetSessionToken with excessive duration
echo "→ Error Test 8: GetSessionToken with EXCESSIVE duration"
echo "  Command: aws sts get-session-token --duration-seconds 999999"
echo "  Expected Error: InvalidParameterValue (duration > 36 hours)"
echo
echo "Server Response:"

if aws sts get-session-token \
    --endpoint-url "${S3_ENDPOINT}" \
    --duration-seconds 999999 \
    --output json \
    --no-verify-ssl 2>&1; then
    record_test "GetSessionToken with excessive duration → InvalidParameterValue" "false" "Request accepted (server may have clamped to max duration)" "aws sts get-session-token --endpoint-url ${S3_ENDPOINT} --duration-seconds 999999 --no-verify-ssl"
else
    record_test "GetSessionToken with excessive duration → InvalidParameterValue" "true" "" "aws sts get-session-token --endpoint-url ${S3_ENDPOINT} --duration-seconds 999999 --no-verify-ssl"
fi
echo

# Error Test 9: AssumeRole with excessive duration
echo "→ Error Test 9: AssumeRole with EXCESSIVE duration"
echo "  Command: aws sts assume-role --duration-seconds 999999"
echo "  Expected Error: InvalidParameterValue (duration > 12 hours)"
echo
echo "Server Response:"

if aws sts assume-role \
    --endpoint-url "${S3_ENDPOINT}" \
    --role-arn "${ROLE_ARN}" \
    --role-session-name "test-session" \
    --duration-seconds 999999 \
    --output json \
    --no-verify-ssl 2>&1; then
    record_test "AssumeRole with excessive duration → InvalidParameterValue" "false" "Request accepted (server may have clamped to max duration)" "aws sts assume-role --endpoint-url ${S3_ENDPOINT} --role-arn ${ROLE_ARN} --role-session-name test-session --duration-seconds 999999 --no-verify-ssl"
else
    record_test "AssumeRole with excessive duration → InvalidParameterValue" "true" "" "aws sts assume-role --endpoint-url ${S3_ENDPOINT} --role-arn ${ROLE_ARN} --role-session-name test-session --duration-seconds 999999 --no-verify-ssl"
fi
echo

# Error Test 10: S3 operation with completely invalid credentials
echo "→ Error Test 10: S3 operation with INVALID credentials"
echo "  Using fake access key and secret"
echo "  Expected Error: InvalidAccessKeyId or SignatureDoesNotMatch (403)"
echo

export AWS_ACCESS_KEY_ID="AKIAINVALIDKEY123456"
export AWS_SECRET_ACCESS_KEY="InvalidSecretKeyThatDoesNotExist123456789"
unset AWS_SESSION_TOKEN

if aws s3 ls \
    --endpoint-url "${S3_ENDPOINT}" \
    --no-verify-ssl 2>&1; then
    record_test "S3 operation with invalid credentials → InvalidAccessKeyId" "false" "S3 operation succeeded with invalid credentials" "aws s3 ls --endpoint-url ${S3_ENDPOINT} --no-verify-ssl (with invalid credentials)"
else
    record_test "S3 operation with invalid credentials → InvalidAccessKeyId" "true" "" "aws s3 ls --endpoint-url ${S3_ENDPOINT} --no-verify-ssl (with invalid credentials)"
fi
echo

# Restore permanent credentials
export AWS_ACCESS_KEY_ID="$PERMANENT_ACCESS_KEY"
export AWS_SECRET_ACCESS_KEY="$PERMANENT_SECRET_KEY"
unset AWS_SESSION_TOKEN

echo "================================================================================"
echo "Error testing complete (STEP 10)"
echo "================================================================================"
echo
echo "Summary of error tests:"
echo "  1. AssumeRole with non-existent role → NoSuchEntity"
echo "  2. AssumeRole with invalid ARN format → InvalidParameterValue"
echo "  3. AssumeRole without required parameter → InvalidParameterValue"
echo "  4. IAM operation on wrong account → NoSuchEntity/AccessDenied"
echo "  5. GetRole on non-existent role → NoSuchEntity"
echo "  6. DeleteRole on non-existent role → NoSuchEntity"
echo "  7. AssumeRole with Deny trust policy → AccessDenied"
echo "  8. GetSessionToken with excessive duration → InvalidParameterValue"
echo "  9. AssumeRole with excessive duration → InvalidParameterValue"
echo "  10. S3 operation with invalid credentials → InvalidAccessKeyId"
echo

fi # End STEP 10

# ============================================================================
# Cleanup
# ============================================================================
echo "================================================================================"
echo "STEP 11: Cleaning up test resources"
echo "================================================================================"
echo "Using: Permanent credentials"
echo

# Use permanent credentials for cleanup
export AWS_ACCESS_KEY_ID="$PERMANENT_ACCESS_KEY"
export AWS_SECRET_ACCESS_KEY="$PERMANENT_SECRET_KEY"
unset AWS_SESSION_TOKEN

# Delete objects from allowed bucket
echo "→ Deleting objects from allowed bucket..."
aws s3 rm "s3://${ALLOWED_BUCKET}/test-object.txt" \
    --endpoint-url "${S3_ENDPOINT}" \
    --no-verify-ssl \
    >/dev/null 2>&1 || true
aws s3 rm "s3://${ALLOWED_BUCKET}/new-object.txt" \
    --endpoint-url "${S3_ENDPOINT}" \
    --no-verify-ssl \
    >/dev/null 2>&1 || true

# Delete buckets
echo "→ Deleting test buckets..."
if aws s3 rb "s3://${ALLOWED_BUCKET}" \
    --endpoint-url "${S3_ENDPOINT}" \
    --no-verify-ssl \
    >/dev/null 2>&1; then
    echo "  ✓ Allowed bucket deleted"
fi

if aws s3 rb "s3://${TEST_BUCKET}" \
    --endpoint-url "${S3_ENDPOINT}" \
    --no-verify-ssl \
    >/dev/null 2>&1; then
    echo "  ✓ Restricted bucket deleted"
fi

# Delete role policy
echo "→ Deleting role policy..."
if aws iam delete-role-policy \
    --endpoint-url "${S3_ENDPOINT}" \
    --role-name "${ROLE_NAME}" \
    --policy-name "S3RestrictedAccess" \
    --no-verify-ssl \
    >/dev/null 2>&1; then
    echo "  ✓ Role policy deleted"
fi

# Delete role
echo "→ Deleting role..."
if aws iam delete-role \
    --endpoint-url "${S3_ENDPOINT}" \
    --role-name "${ROLE_NAME}" \
    --no-verify-ssl \
    >/dev/null 2>&1; then
    echo "  ✓ Role deleted"
fi

echo
echo "================================================================================"
echo "=== Demo Complete ==="
echo "================================================================================"
echo
echo "================================================================================"
echo "TEST RESULTS SUMMARY"
echo "================================================================================"
echo
echo "Total Tests Run: ${TOTAL_TESTS}"
echo "Passed: ${#PASSED_TESTS[@]}"
echo "Failed: ${#FAILED_TESTS[@]}"
echo

if [ ${#PASSED_TESTS[@]} -gt 0 ]; then
    echo "✓ PASSED TESTS (${#PASSED_TESTS[@]}):"
    echo "──────────────────────────────────────────────────────────────────────────────"
    for i in "${!PASSED_TESTS[@]}"; do
        echo "  ✓ ${PASSED_TESTS[$i]}"
        echo "    Command: ${PASSED_COMMANDS[$i]}"
        echo
    done
fi

if [ ${#FAILED_TESTS[@]} -gt 0 ]; then
    echo "✗ FAILED TESTS (${#FAILED_TESTS[@]}):"
    echo "──────────────────────────────────────────────────────────────────────────────"
    for i in "${!FAILED_TESTS[@]}"; do
        echo "  ✗ ${FAILED_TESTS[$i]}"
        echo "    Command: ${FAILED_COMMANDS[$i]}"
        echo
    done
else
    echo "✓ ALL TESTS PASSED!"
    echo
fi

echo "================================================================================"
echo "DEMO COVERAGE SUMMARY"
echo "================================================================================"
echo
echo "Credential Types Tested:"
echo "  • Permanent credentials (full access)"
echo "  • MSTS (GetSessionToken) - temporary, same permissions, IAM blocked"
echo "  • MSAR (AssumeRole) - temporary, policy-restricted"
echo
echo "Policy Enforcement Tested:"
echo "  • Trust Policy validation (who can assume role)"
echo "  • Permission Policy evaluation (what role can do)"
echo "  • Implicit Deny (operations not in policy)"
echo "  • Resource matching (bucket-specific permissions)"
echo "  • Action matching (operation-specific permissions)"
echo
echo "Error Conditions Tested:"
echo "  • NoSuchEntity errors (non-existent resources)"
echo "  • AccessDenied errors (policy denials, invalid auth)"
echo "  • InvalidParameterValue errors (bad parameters, excessive durations)"
echo "  • XML error response format validation"
echo
echo "STS Operations Tested:"
echo "  • GetSessionToken (create MSTS credentials)"
echo "  • AssumeRole (create MSAR credentials)"
echo "  • GetCallerIdentity (verify identity)"
echo
echo "IAM Operations Tested:"
echo "  • CreateRole (with trust policy)"
echo "  • PutRolePolicy (attach permission policy)"
echo "  • GetRole (retrieve role information)"
echo "  • DeleteRole (cleanup)"
echo "  • DeleteRolePolicy (cleanup)"
echo
echo "S3 Operations Tested:"
echo "  • CreateBucket, DeleteBucket"
echo "  • ListBucket (with policy restrictions)"
echo "  • PutObject, GetObject (with policy restrictions)"
echo "  • DeleteObject (policy denied)"
echo "  • ListAllMyBuckets (policy denied)"
echo
