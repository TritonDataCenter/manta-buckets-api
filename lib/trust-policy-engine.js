/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright 2025 Edgecast Cloud LLC.
 */

/*
 * AWS STS Trust Policy Evaluation Engine for Manta Buckets API
 *
 * Implements AWS-compatible trust policy validation for role assumption.
 * Trust policies (AssumeRolePolicyDocument) control which principals
 * can assume a role under what conditions.
 */

var assert = require('assert-plus');
var crypto = require('crypto');
var sprintf = require('util').format;

/**
 * @brief Evaluates AWS STS trust policies for role assumption
 *
 * This engine implements AWS IAM trust policy evaluation logic to determine
 * whether a given principal is authorized to assume a role based on the
 * role's AssumeRolePolicyDocument and current request context.
 *
 * @param {Object} opts Configuration options
 * @param {Object} opts.log Bunyan logger instance
 * @param {Boolean} opts.strictMode Enable strict AWS
 * compatibility (default: true)
 *
 * @example
 * var engine = new TrustPolicyEngine({ log: logger });
 *
 * var policy = {
 *   "Version": "2012-10-17",
 *   "Statement": [{
 *     "Effect": "Allow",
 *     "Principal": { "AWS": "arn:aws:iam::account:user/alice" },
 *     "Action": "sts:AssumeRole"
 *   }]
 * };
 *
 * var result = engine.evaluate(policy, principal, context);
 * if (result.decision === 'Allow') {
 *   // Grant role assumption
 * }
 */
function TrustPolicyEngine(opts) {
    assert.object(opts, 'options');
    assert.object(opts.log, 'options.log');
    assert.optionalBool(opts.strictMode, 'options.strictMode');

    this.log = opts.log.child({component: 'TrustPolicyEngine'});
    this.strictMode = opts.strictMode !== false;

    // Supported trust policy versions
    this.SUPPORTED_VERSIONS = ['2012-10-17', '2008-10-17'];

    // Supported principal types
    this.PRINCIPAL_TYPES = ['AWS', 'Service', 'Federated'];

    // Supported actions for trust policies
    this.TRUST_ACTIONS = ['sts:AssumeRole', 'sts:AssumeRoleWithWebIdentity',
                          'sts:AssumeRoleWithSAML'];
}

/**
 * @brief Primary policy evaluation method
 *
 * Evaluates whether a principal can assume a role based on trust policy.
 * Implements AWS policy evaluation logic with explicit deny precedence.
 *
 * @param {Object} policy Trust policy document (AssumeRolePolicyDocument)
 * @param {Object} principal Requesting principal information
 * @param {Object} context Request context for condition evaluation
 * @return {Object} Evaluation result with decision and details
 */
TrustPolicyEngine.prototype.evaluate = function evaluate(policy, principal,
                                                         context) {
    assert.object(policy, 'policy');
    assert.object(principal, 'principal');
    assert.object(context, 'context');

    var self = this;
    var log = self.log;

    log.debug({
        policy: policy,
        principal: principal.arn,
        context: context
    }, 'Starting trust policy evaluation');

    try {
        // Step 1: Validate policy structure
        var validationResult = self._validatePolicyStructure(policy);
        if (!validationResult.valid) {
            return ({
                decision: 'Deny',
                reason: 'InvalidPolicyDocument',
                details: validationResult.errors
            });
        }

        // Step 2: Process each statement
        var allowStatements = [];
        var denyStatements = [];

        for (var i = 0; i < policy.Statement.length; i++) {
            var statement = policy.Statement[i];
            var evaluation = self._evaluateStatement(statement, principal,
                                                     context);

            if (evaluation.matches) {
                if (statement.Effect === 'Allow') {
                    allowStatements.push({
                        statement: statement,
                        evaluation: evaluation
                    });
                } else if (statement.Effect === 'Deny') {
                    denyStatements.push({
                        statement: statement,
                        evaluation: evaluation
                    });
                }
            }
        }

        // Step 3: Apply AWS evaluation logic (explicit deny wins)
        if (denyStatements.length > 0) {
            log.debug({
                principal: principal.arn,
                denyCount: denyStatements.length
            }, 'Trust policy evaluation: Explicit deny found');

            return ({
                decision: 'Deny',
                reason: 'ExplicitDeny',
                details: {
                    denyStatements: denyStatements.length,
                    firstDenyReason: denyStatements[0].evaluation.reason
                }
            });
        }

        if (allowStatements.length > 0) {
            log.debug({
                principal: principal.arn,
                allowCount: allowStatements.length
            }, 'Trust policy evaluation: Access granted');

            return ({
                decision: 'Allow',
                reason: 'ExplicitAllow',
                details: {
                    allowStatements: allowStatements.length,
                    grantedBy: allowStatements[0].evaluation.reason
                }
            });
        }

        // Step 4: Default deny (no matching statements)
        log.debug({
            principal: principal.arn,
            statementCount: policy.Statement.length
        }, 'Trust policy evaluation: Implicit deny (no matching statements)');

        return ({
            decision: 'Deny',
            reason: 'ImplicitDeny',
            details: 'No statements matched the request'
        });

    } catch (err) {
        log.debug({
            err: err,
            principal: principal.arn
        }, 'Trust policy evaluation failed with error');

        return ({
            decision: 'Deny',
            reason: 'EvaluationError',
            details: err.message
        });
    }
};

/**
 * @brief Validates trust policy document structure
 * @private
 */
TrustPolicyEngine.prototype._validatePolicyStructure =
function _validatePolicyStructure(policy) {
    var errors = [];

    // Check required fields
    if (!policy.Version) {
        errors.push('Missing required field: Version');
    } else if (this.SUPPORTED_VERSIONS.indexOf(policy.Version) === -1) {
        errors.push(sprintf('Unsupported policy version: %s',
                           policy.Version));
    }

    if (!policy.Statement) {
        errors.push('Missing required field: Statement');
    } else if (!Array.isArray(policy.Statement)) {
        errors.push('Statement must be an array');
    } else if (policy.Statement.length === 0) {
        errors.push('Statement array cannot be empty');
    }

    // Validate each statement structure
    if (policy.Statement && Array.isArray(policy.Statement)) {
        for (var i = 0; i < policy.Statement.length; i++) {
            var stmt = policy.Statement[i];
            var stmtErrors = this._validateStatement(stmt, i);
            errors = errors.concat(stmtErrors);
        }
    }

    return ({
        valid: errors.length === 0,
        errors: errors
    });
};

/**
 * @brief Validates individual statement structure
 * @private
 */
TrustPolicyEngine.prototype._validateStatement =
function _validateStatement(statement, index) {
    var errors = [];
    var prefix = sprintf('Statement[%d]: ', index);

    // Effect is required
    if (!statement.Effect) {
        errors.push(prefix + 'Missing required field: Effect');
    } else if (statement.Effect !== 'Allow' && statement.Effect !== 'Deny') {
        errors.push(prefix +
                    sprintf('Invalid Effect: %s (must be Allow or Deny)',
                            statement.Effect));
    }

    // Principal is required for trust policies
    if (!statement.Principal) {
        errors.push(prefix + 'Missing required field: Principal');
    }

    // Action is required
    if (!statement.Action) {
        errors.push(prefix + 'Missing required field: Action');
    }

    return (errors);
};

/**
 * @brief Evaluates a single policy statement against principal and context
 * @private
 */
TrustPolicyEngine.prototype._evaluateStatement =
function _evaluateStatement(statement, principal, context) {
    var self = this;

    // Check if action matches
    var actionMatch = self._matchAction(statement.Action, 'sts:AssumeRole');
    if (!actionMatch.matches) {
        return ({
            matches: false,
            reason: sprintf('Action mismatch: %s', actionMatch.reason)
        });
    }

    // Check if principal matches
    var principalMatch = self._matchPrincipal(statement.Principal, principal);
    if (!principalMatch.matches) {
        return ({
            matches: false,
            reason: sprintf('Principal mismatch: %s', principalMatch.reason)
        });
    }

    // Check conditions if present
    if (statement.Condition) {
        var conditionMatch = self._evaluateConditions(statement.Condition,
                                                      context);
        if (!conditionMatch.matches) {
            return ({
                matches: false,
                reason: sprintf('Condition failed: %s', conditionMatch.reason)
            });
        }
    }

    return ({
        matches: true,
        reason: sprintf('Statement matched for %s', statement.Effect)
    });
};

/**
 * @brief Matches action patterns against requested action
 * @private
 */
TrustPolicyEngine.prototype._matchAction = function _matchAction(policyAction,
                                                                requestAction) {
    // Handle string or array
    var actions = Array.isArray(policyAction) ? policyAction : [policyAction];

    for (var i = 0; i < actions.length; i++) {
        var action = actions[i];

        // Exact match
        if (action === requestAction) {
            return ({matches: true, reason: 'Exact action match'});
        }

        // Wildcard match
        if (action === '*') {
            return ({matches: true, reason: 'Wildcard action match'});
        }

        // Service wildcard (e.g., "sts:*")
        if (action.endsWith(':*')) {
            var servicePrefix = action.substring(0, action.length - 1);
            if (requestAction.startsWith(servicePrefix)) {
                return ({matches: true, reason: 'Service wildcard match'});
            }
        }
    }

    return ({
        matches: false,
        reason: sprintf('No action matched: %s not in %j',
                        requestAction, actions)
    });
};

/**
 * @brief Matches principal patterns against requesting principal
 * @private
 */
TrustPolicyEngine.prototype._matchPrincipal =
function _matchPrincipal(policyPrincipal, requestPrincipal) {
    var self = this;

    // Handle wildcard principal
    if (policyPrincipal === '*') {
        return ({matches: true, reason: 'Wildcard principal match'});
    }

    // Handle structured principal object
    if (typeof (policyPrincipal) === 'object' && policyPrincipal !== null) {
        // Check AWS principals
        if (policyPrincipal.AWS) {
            var awsMatch = self._matchAWSPrincipal(policyPrincipal.AWS,
                                                   requestPrincipal);
            if (awsMatch.matches) {
                return (awsMatch);
            }
        }

        // Check service principals
        if (policyPrincipal.Service) {
            var serviceMatch =
                self._matchServicePrincipal(policyPrincipal.Service,
                                                          requestPrincipal);
            if (serviceMatch.matches) {
                return (serviceMatch);
            }
        }

        // Check federated principals
        if (policyPrincipal.Federated) {
            var federatedMatch = self._matchFederatedPrincipal(
                policyPrincipal.Federated, requestPrincipal);
            if (federatedMatch.matches) {
                return (federatedMatch);
            }
        }
    }

    return ({
        matches: false,
        reason: sprintf('Principal %s did not match policy principal %j',
                       requestPrincipal.arn, policyPrincipal)
    });
};

/**
 * @brief Matches AWS IAM principals (users, roles, accounts)
 * @private
 */
TrustPolicyEngine.prototype._matchAWSPrincipal =
function _matchAWSPrincipal(awsPrincipals, requestPrincipal) {
    var principals = Array.isArray(awsPrincipals) ?
        awsPrincipals : [awsPrincipals];

    for (var i = 0; i < principals.length; i++) {
        var principal = principals[i];

        // Exact ARN match
        if (principal === requestPrincipal.arn) {
            return ({
                matches: true,
                reason: sprintf('Exact ARN match: %s', principal)
            });
        }

        // Account ID match (allows all users/roles in account)
        if (principal.match(/^\d{12}$/)) {
            if (requestPrincipal.account === principal) {
                return ({
                    matches: true,
                    reason: sprintf('Account match: %s', principal)
                });
            }
        }

        // Account ARN match
        var accountArnPattern = /^arn:aws:iam::(\d{12}):root$/;
        var accountMatch = principal.match(accountArnPattern);
        if (accountMatch && accountMatch[1] === requestPrincipal.account) {
            return ({
                matches: true,
                reason: sprintf('Account root match: %s', principal)
            });
        }
    }

    return ({
        matches: false,
        reason: sprintf('AWS principal %s not found in %j',
                       requestPrincipal.arn, principals)
    });
};

/**
 * @brief Matches service principals
 * @private
 */
TrustPolicyEngine.prototype._matchServicePrincipal =
function _matchServicePrincipal(servicePrincipals, requestPrincipal) {
    // Only match if request principal is a service
    if (requestPrincipal.type !== 'service') {
        return ({
            matches: false,
            reason: 'Request principal is not a service'
        });
    }

    var services = Array.isArray(servicePrincipals) ? servicePrincipals :
        [servicePrincipals];

    for (var i = 0; i < services.length; i++) {
        var service = services[i];
        if (service === requestPrincipal.service) {
            return ({
                matches: true,
                reason: sprintf('Service match: %s', service)
            });
        }
    }

    return ({
        matches: false,
        reason: sprintf('Service %s not found in %j',
                       requestPrincipal.service, services)
    });
};

/**
 * @brief Matches federated principals (SAML, OIDC)
 * @private
 */
TrustPolicyEngine.prototype._matchFederatedPrincipal =
function _matchFederatedPrincipal(federatedPrincipals, requestPrincipal) {
    // Only match if request principal is federated
    if (requestPrincipal.type !== 'federated') {
        return ({
            matches: false,
            reason: 'Request principal is not federated'
        });
    }

    var providers = Array.isArray(federatedPrincipals) ? federatedPrincipals :
        [federatedPrincipals];

    for (var i = 0; i < providers.length; i++) {
        var provider = providers[i];
        if (provider === requestPrincipal.provider) {
            return ({
                matches: true,
                reason: sprintf('Federated provider match: %s', provider)
            });
        }
    }

    return ({
        matches: false,
        reason: sprintf('Federated provider %s not found in %j',
                       requestPrincipal.provider, providers)
    });
};

/**
 * @brief Evaluates policy conditions against request context
 * @private
 */
TrustPolicyEngine.prototype._evaluateConditions =
function _evaluateConditions(conditions, context) {
    var self = this;
    var log = self.log;

    // All condition blocks must evaluate to true (logical AND)
    for (var conditionType in conditions) {
        var conditionBlock = conditions[conditionType];
        var blockResult = self._evaluateConditionBlock(conditionType,
                                                       conditionBlock, context);

        if (!blockResult.matches) {
            log.debug({
                conditionType: conditionType,
                reason: blockResult.reason
            }, 'Condition block failed');

            return (blockResult);
        }
    }

    return ({matches: true, reason: 'All conditions passed'});
};

/**
 * @brief Evaluates a single condition block
 * @private
 */
TrustPolicyEngine.prototype._evaluateConditionBlock =
function _evaluateConditionBlock(conditionType, conditionBlock, context) {
    var self = this;

    // All conditions in block must be true (logical AND)
    for (var key in conditionBlock) {
        var expectedValues = conditionBlock[key];
        var actualValue = self._getContextValue(key, context);

        var comparison = self._compareValues(conditionType, expectedValues,
                                           actualValue);
        if (!comparison.matches) {
            return ({
                matches: false,
                reason: sprintf('Condition %s failed: %s', key,
                                comparison.reason)
            });
        }
    }

    return ({matches: true, reason: sprintf('Condition block %s passed',
                                           conditionType)});
};

/**
 * @brief Gets context value for condition evaluation
 * @private
 */
TrustPolicyEngine.prototype._getContextValue =
function _getContextValue(key, context) {
    var normalizedKey = key.toLowerCase();

    // Map common AWS context keys to local context
    var keyMappings = {
        'aws:sourceip': context.sourceIp,
        'aws:userid': context.userId,
        'aws:username': context.username,
        'aws:requesttime': context.requestTime,
        'sts:externalid': context.externalId,
        'aws:multifactorauthage': context.mfaAge,
        'aws:multifactorauthpresent': context.mfa ? 'true' : 'false'
    };

    return (keyMappings[normalizedKey] || context[key]);
};

/**
 * @brief Compares expected and actual values based on condition type
 * @private
 */
TrustPolicyEngine.prototype._compareValues =
function _compareValues(conditionType, expectedValues, actualValue) {
    var expected = Array.isArray(expectedValues) ? expectedValues :
        [expectedValues];

    switch (conditionType) {
        case 'StringEquals':
            return (this._stringEquals(expected, actualValue));
        case 'StringNotEquals':
            return (this._stringNotEquals(expected, actualValue));
        case 'StringLike':
            return (this._stringLike(expected, actualValue));
        case 'StringNotLike':
            return (this._stringNotLike(expected, actualValue));
        case 'IpAddress':
            return (this._ipAddressMatch(expected, actualValue));
        case 'NotIpAddress':
            return (this._notIpAddressMatch(expected, actualValue));
        case 'Bool':
            return (this._boolMatch(expected, actualValue));
        case 'DateGreaterThan':
            return (this._dateGreaterThan(expected, actualValue));
        case 'DateLessThan':
            return (this._dateLessThan(expected, actualValue));
        default:
            return ({
                matches: false,
                reason: sprintf('Unsupported condition type: %s', conditionType)
            });
    }
};

/**
 * @brief String equality comparison
 * @private
 */
TrustPolicyEngine.prototype._stringEquals =
function _stringEquals(expected, actual) {
    if (actual === undefined || actual === null) {
        return ({matches: false, reason: 'Actual value is null/undefined'});
    }

    var actualStr = String(actual);
    for (var i = 0; i < expected.length; i++) {
        if (String(expected[i]) === actualStr) {
            return ({matches: true, reason: 'String equality match'});
        }
    }

    return ({
        matches: false,
        reason: sprintf('String %s not equal to any of %j', actual, expected)
    });
};

/**
 * @brief String inequality comparison
 * @private
 */
TrustPolicyEngine.prototype._stringNotEquals =
function _stringNotEquals(expected, actual) {
    var equalityResult = this._stringEquals(expected, actual);
    return ({
        matches: !equalityResult.matches,
        reason: equalityResult.matches ?
            'String equality found (not expected)' :
            'String inequality confirmed'
    });
};

/**
 * @brief Wildcard string matching
 * @private
 */
TrustPolicyEngine.prototype._stringLike =
    function _stringLike(expected, actual) {
    if (actual === undefined || actual === null) {
        return ({matches: false, reason: 'Actual value is null/undefined'});
    }

    var actualStr = String(actual);
    for (var i = 0; i < expected.length; i++) {
        var pattern = String(expected[i]);
        // Convert shell-style wildcards to regex
        // JSSTYLED
        var regex = new RegExp('^' + pattern.replace(/\*/g, '.*')
                                          .replace(/\?/g, '.') + '$');
        if (regex.test(actualStr)) {
            return ({matches: true, reason: 'Wildcard pattern match'});
        }
    }

    return ({
        matches: false,
        reason: sprintf('String %s does not match patterns %j', actual,
                        expected)
    });
};

/**
 * @brief Negative wildcard string matching
 * @private
 */
TrustPolicyEngine.prototype._stringNotLike =
function _stringNotLike(expected, actual) {
    var likeResult = this._stringLike(expected, actual);
    return ({
        matches: !likeResult.matches,
        reason: likeResult.matches ? 'Pattern match found (not expected)' :
                                   'Pattern mismatch confirmed'
    });
};

/**
 * @brief IP address/CIDR matching
 * @private
 */
TrustPolicyEngine.prototype._ipAddressMatch =
function _ipAddressMatch(expected, actual) {
    if (!actual) {
        return ({matches: false, reason: 'No IP address provided'});
    }

    // Simple IP matching - production would need proper CIDR evaluation
    for (var i = 0; i < expected.length; i++) {
        var expectedIp = String(expected[i]);
        if (expectedIp === String(actual)) {
            return ({matches: true, reason: 'IP address match'});
        }

        // Basic CIDR support for /32
        if (expectedIp.endsWith('/32')) {
            var baseIp = expectedIp.substring(0, expectedIp.length - 3);
            if (baseIp === String(actual)) {
                return ({matches: true, reason: 'CIDR /32 match'});
            }
        }
    }

    return ({
        matches: false,
        reason: sprintf('IP %s does not match %j', actual, expected)
    });
};

/**
 * @brief Negative IP address matching
 * @private
 */
TrustPolicyEngine.prototype._notIpAddressMatch =
function _notIpAddressMatch(expected, actual) {
    var ipResult = this._ipAddressMatch(expected, actual);
    return ({
        matches: !ipResult.matches,
        reason: ipResult.matches ? 'IP match found (not expected)' :
                                 'IP mismatch confirmed'
    });
};

/**
 * @brief Boolean value matching
 * @private
 */
TrustPolicyEngine.prototype._boolMatch = function _boolMatch(expected, actual) {
    for (var i = 0; i < expected.length; i++) {
        var expectedBool = String(expected[i]).toLowerCase() === 'true';
        var actualBool = Boolean(actual);

        if (expectedBool === actualBool) {
            return ({matches: true, reason: 'Boolean match'});
        }
    }

    return ({
        matches: false,
        reason: sprintf('Boolean %s does not match %j', actual, expected)
    });
};

/**
 * @brief Date greater than comparison
 * @private
 */
TrustPolicyEngine.prototype._dateGreaterThan =
function _dateGreaterThan(expected, actual) {
    var actualDate = new Date(actual);

    for (var i = 0; i < expected.length; i++) {
        var expectedDate = new Date(expected[i]);
        if (actualDate > expectedDate) {
            return ({matches: true, reason: 'Date greater than match'});
        }
    }

    return ({
        matches: false,
        reason: sprintf('Date %s not greater than %j', actual, expected)
    });
};

/**
 * @brief Date less than comparison
 * @private
 */
TrustPolicyEngine.prototype._dateLessThan =
function _dateLessThan(expected, actual) {
    var actualDate = new Date(actual);

    for (var i = 0; i < expected.length; i++) {
        var expectedDate = new Date(expected[i]);
        if (actualDate < expectedDate) {
            return ({matches: true, reason: 'Date less than match'});
        }
    }

    return ({
        matches: false,
        reason: sprintf('Date %s not less than %j', actual, expected)
    });
};

module.exports = {
    TrustPolicyEngine: TrustPolicyEngine
};
