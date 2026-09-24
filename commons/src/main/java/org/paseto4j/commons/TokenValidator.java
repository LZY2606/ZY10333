/*
 * SPDX-FileCopyrightText: Copyright © 2026 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.commons;

/**
 * Applies the pre-cryptographic stages of a {@link ValidationPolicy} to a PASETO token. All
 * checks run before any cryptographic operation so malformed or policy-violating tokens are
 * rejected cheaply and uniformly for v1-v4. Failure messages are safe summaries: they never
 * include key material, plaintext payloads or token contents.
 */
public final class TokenValidator {

  private TokenValidator() {}

  /**
   * Parses and validates a token against the policy.
   *
   * @param token the serialized token
   * @param version the version required by the entry point
   * @param purpose the purpose required by the entry point
   * @param policy the validation policy
   * @param implicitAssertion the implicit assertion supplied by the caller, may be empty
   * @return the validated token with decoded payload and footer
   * @throws PolicyViolationException when the token does not satisfy the policy
   */
  public static ValidatedToken parse(
      String token, Version version, Purpose purpose, ValidationPolicy policy, String implicitAssertion) {
    Conditions.verify(token != null, "token must not be null");
    Conditions.verify(policy != null, "policy must not be null");

    requireImplicitAssertionSatisfied(policy, implicitAssertion);

    String[] parts = token.split("\\.", -1);
    if (parts.length < 3 || parts.length > 4) {
      throw malformed();
    }
    for (int i = 0; i < 3; i++) {
      if (parts[i].isEmpty()) {
        throw malformed();
      }
    }
    // An empty footer segment is non-canonical: an empty footer is encoded as no segment at all
    if (parts.length == 4 && parts[3].isEmpty()) {
      throw malformed();
    }

    requireVersion(parts[0], version, policy);
    requirePurpose(parts[1], purpose, policy);
    requireLengthWithinLimits(
        token.length(), parts[2].length(), parts.length == 4 ? parts[3].length() : 0, policy);

    byte[] payload = decodeSegment(parts[2]);
    byte[] footer = parts.length == 4 ? decodeSegment(parts[3]) : new byte[0];

    policy.footerExpectation().validate(footer);

    return new ValidatedToken(new TokenAlgorithm(version, purpose), payload, footer);
  }

  /**
   * Checks that the given version is allowed by the policy. Shared with PASERK decoding.
   *
   * @throws PolicyViolationException when the version is not allowed
   */
  public static void requireVersionAllowed(Version version, ValidationPolicy policy) {
    if (!policy.allowedVersions().isEmpty() && !policy.allowedVersions().contains(version)) {
      throw new PolicyViolationException(
          "POLICY_VERSION_NOT_ALLOWED",
          PolicyStage.VERSION,
          "the token version is not allowed by the validation policy");
    }
  }

  /**
   * Checks total and per-segment lengths against the policy. Shared with PASERK decoding.
   *
   * @throws PolicyViolationException when a limit is exceeded
   */
  public static void requireLengthWithinLimits(
      int tokenLength, int payloadSegmentLength, int footerSegmentLength, ValidationPolicy policy) {
    if (policy.maxTokenLength() != null && tokenLength > policy.maxTokenLength()) {
      throw new PolicyViolationException(
          "POLICY_TOKEN_TOO_LONG",
          PolicyStage.LENGTH,
          "the token exceeds the maximum length allowed by the validation policy");
    }
    if (policy.maxPayloadLength() != null && payloadSegmentLength > policy.maxPayloadLength()) {
      throw new PolicyViolationException(
          "POLICY_PAYLOAD_TOO_LONG",
          PolicyStage.LENGTH,
          "the payload segment exceeds the maximum length allowed by the validation policy");
    }
    if (policy.maxFooterLength() != null && footerSegmentLength > policy.maxFooterLength()) {
      throw new PolicyViolationException(
          "POLICY_FOOTER_TOO_LONG",
          PolicyStage.LENGTH,
          "the footer segment exceeds the maximum length allowed by the validation policy");
    }
  }

  private static void requireImplicitAssertionSatisfied(
      ValidationPolicy policy, String implicitAssertion) {
    if (policy.implicitAssertionRequired() && Conditions.isNullOrEmpty(implicitAssertion)) {
      throw new PolicyViolationException(
          "POLICY_IMPLICIT_ASSERTION_REQUIRED",
          PolicyStage.IMPLICIT_ASSERTION,
          "the validation policy requires a non-empty implicit assertion");
    }
  }

  private static void requireVersion(String tokenVersion, Version expected, ValidationPolicy policy) {
    Version parsed = null;
    for (Version candidate : Version.values()) {
      if (candidate.toString().equals(tokenVersion)) {
        parsed = candidate;
        break;
      }
    }
    if (parsed == null) {
      throw malformed();
    }
    if (parsed != expected) {
      throw new PolicyViolationException(
          "TOKEN_WRONG_VERSION",
          PolicyStage.VERSION,
          "the token version does not match the expected version");
    }
    requireVersionAllowed(parsed, policy);
  }

  private static void requirePurpose(String tokenPurpose, Purpose expected, ValidationPolicy policy) {
    Purpose parsed = null;
    for (Purpose candidate : Purpose.values()) {
      if (candidate.toString().equals(tokenPurpose)) {
        parsed = candidate;
        break;
      }
    }
    if (parsed == null) {
      throw malformed();
    }
    if (parsed != expected) {
      throw new PolicyViolationException(
          "TOKEN_WRONG_PURPOSE",
          PolicyStage.PURPOSE,
          "the token purpose does not match the expected purpose");
    }
    if (!policy.allowedPurposes().isEmpty() && !policy.allowedPurposes().contains(parsed)) {
      throw new PolicyViolationException(
          "POLICY_PURPOSE_NOT_ALLOWED",
          PolicyStage.PURPOSE,
          "the token purpose is not allowed by the validation policy");
    }
  }

  private static byte[] decodeSegment(String segment) {
    if (!Base64Url.isCanonical(segment)) {
      throw new PolicyViolationException(
          "TOKEN_NON_CANONICAL_ENCODING",
          PolicyStage.ENCODING,
          "a token segment is not canonical base64url");
    }
    return Base64Url.decode(segment);
  }

  private static PolicyViolationException malformed() {
    return new PolicyViolationException(
        "TOKEN_MALFORMED", PolicyStage.STRUCTURE, "the token does not have a valid PASETO structure");
  }

  /** Validates the claims of an authenticated payload against the policy. */
  public static void validateClaims(String payload, ValidationPolicy policy) {
    ClaimValidator.validate(payload, policy);
  }
}
