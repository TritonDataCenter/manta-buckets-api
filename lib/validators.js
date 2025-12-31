/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright 2025 Edgecast Cloud LLC.
 */

/*
 * File:     validators.js
 * Purpose:  Account identifier validation using sdc-ufds canonical patterns
 *
 * Description:
 * This module provides centralized validation for account identifiers
 * (logins and UUIDs) using the canonical regex patterns from
 * sdc-ufds/schema/sdcperson.js.
 *
 * Security:
 * Account identifiers extracted from URL paths MUST be validated before use in
 * security contexts (authorization, Mahi lookups, resource access). This module
 * provides defense-in-depth by validating format before external service calls.
 *
 * Invariants:
 * - LOGIN_RE and UUID_RE patterns MUST match sdc-ufds schema exactly
 * - All account identifiers in security contexts MUST pass validation
 * - Validation MUST occur before Mahi lookups (fail fast)
 */

///--- Globals

/**
 * Login name regex from sdc-ufds/schema/sdcperson.js
 *
 * Valid login format:
 * - Must start with letter (a-zA-Z)
 * - May contain: letters, digits, underscore, period, at-sign
 * - Character set: [a-zA-Z0-9_\.@]
 * - Length: 3-32 characters (enforced separately)
 *
 * Examples:
 *   Valid:   testuser, user.name, user_123, user@example
 *   Invalid: 123user (starts with digit), user-name (hyphen not allowed)
 */
var LOGIN_RE = /^[a-zA-Z][a-zA-Z0-9_\.@]+$/;

/**
 * UUID regex from sdc-ufds/schema/sdcperson.js
 *
 * RFC 4122 UUID format (lowercase only):
 * - 8 hex digits
 * - hyphen
 * - 4 hex digits
 * - hyphen
 * - 4 hex digits
 * - hyphen
 * - 4 hex digits
 * - hyphen
 * - 12 hex digits
 *
 * Examples:
 *   Valid:   550e8400-e29b-41d4-a716-446655440000
 *   Invalid: 550E8400-E29B-41D4-A716-446655440000 (uppercase not allowed)
 */
var UUID_RE = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;

///--- API

/**
 * Validate account login format
 *
 * Validates that a string conforms to the sdc-ufds login format. Used to
 * validate account names extracted from URL paths before using them in
 * security-critical operations.
 *
 * Validation rules (from sdc-ufds/schema/sdcperson.js):
 * - Type: must be non-empty string
 * - Length: 3-32 characters (inclusive)
 * - Pattern: must match LOGIN_RE
 * - First character: must be letter (a-zA-Z)
 * - Subsequent characters: letters, digits, underscore, period, at-sign
 *
 * Security:
 * - Rejects path traversal patterns (not alphanumeric start)
 * - Rejects overly long inputs (DoS prevention)
 * - Rejects special characters that could enable injection
 *
 * @param {string} login - The login name to validate
 * @returns {boolean} - True if valid login format, false otherwise
 *
 * Examples:
 *   isValidLogin('testuser')       => true
 *   isValidLogin('user.name')      => true
 *   isValidLogin('user@example')   => true
 *   isValidLogin('ab')             => false (too short)
 *   isValidLogin('123user')        => false (starts with digit)
 *   isValidLogin('../admin')       => false (path traversal)
 */
function isValidLogin(login) {
    // Type and existence check
    if (!login || typeof (login) !== 'string') {
        return (false);
    }

    // Length constraints from sdc-ufds
    if (login.length < 3 || login.length > 32) {
        return (false);
    }

    // Pattern validation
    return (LOGIN_RE.test(login));
}

/**
 * Validate UUID format
 *
 * Validates that a string conforms to RFC 4122 UUID format (lowercase only).
 * Used to validate account UUIDs before using them in resource lookups or
 * authorization checks.
 *
 * Validation rules:
 * - Type: must be non-empty string
 * - Pattern: must match UUID_RE (8-4-4-4-12 hex digits with hyphens)
 * - Case: lowercase only (a-f, not A-F)
 * - Length: exactly 36 characters
 *
 * Security:
 * - Rejects malformed UUIDs that could cause parsing errors
 * - Rejects non-UUID strings that could enable injection
 * - Validates format before database lookups
 *
 * @param {string} uuid - The UUID string to validate
 * @returns {boolean} - True if valid UUID format, false otherwise
 *
 * Examples:
 *   isValidUuid('550e8400-e29b-41d4-a716-446655440000')  => true
 *   isValidUuid('not-a-uuid')                            => false
 *   isValidUuid('550E8400-E29B-41D4-A716-446655440000')  => false (uppercase)
 */
function isValidUuid(uuid) {
    // Type and existence check
    if (!uuid || typeof (uuid) !== 'string') {
        return (false);
    }

    // Pattern validation
    return (UUID_RE.test(uuid));
}

/**
 * Validate account identifier (login or UUID)
 *
 * Validates that a string is either a valid login name OR a valid UUID.
 * This is the primary validation function for account identifiers extracted
 * from URL paths, as Manta supports both login names and UUIDs for account
 * identification.
 *
 * Security:
 * - Validates before Mahi lookups (fail fast)
 * - Rejects invalid formats early in request processing
 * - Defense-in-depth: validates format even if Mahi would reject
 *
 * Used in:
 * - lib/anonymous-auth.js: validate account from anonymous access paths
 * - lib/auth/authorization-handler.js: validate account from request paths
 *
 * @param {string} identifier - The account identifier (login or UUID)
 * @returns {boolean} - True if valid login OR valid UUID format
 *
 * Examples:
 *   isValidAccountIdentifier('testuser')                           => true
 *   isValidAccountIdentifier('550e8400-e29b-41d4-a716-446655440000') => true
 *   isValidAccountIdentifier('../admin')                           => false
 *   isValidAccountIdentifier('a')                                  => false
 */
function isValidAccountIdentifier(identifier) {
    return (isValidLogin(identifier) || isValidUuid(identifier));
}

///--- Exports

module.exports = {
    LOGIN_RE: LOGIN_RE,
    UUID_RE: UUID_RE,
    isValidLogin: isValidLogin,
    isValidUuid: isValidUuid,
    isValidAccountIdentifier: isValidAccountIdentifier
};
