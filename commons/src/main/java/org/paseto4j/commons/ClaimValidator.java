/*
 * SPDX-FileCopyrightText: Copyright © 2026 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.commons;

import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.DateTimeException;
import java.time.format.DateTimeParseException;
import java.time.temporal.ChronoUnit;
import java.util.Map;

/**
 * Validates payload claims against a {@link ValidationPolicy}. Runs only after the token has been
 * authenticated, so claim failures can never leak information about unauthenticated ciphertext.
 * Failure messages never echo claim values.
 */
final class ClaimValidator {

  private ClaimValidator() {}

  static void validate(String payload, ValidationPolicy policy) {
    boolean claimRulesActive =
        policy.validateTimestamps()
            || !policy.requiredClaims().isEmpty()
            || !policy.expectedClaims().isEmpty();
    if (!claimRulesActive) {
      return;
    }

    Map<String, JsonClaims.Value> claims = parse(payload);

    for (String required : policy.requiredClaims()) {
      if (!claims.containsKey(required)) {
        throw new PolicyViolationException(
            "POLICY_CLAIM_MISSING",
            PolicyStage.CLAIMS,
            "a claim required by the validation policy is missing");
      }
    }

    for (Map.Entry<String, String> expectation : policy.expectedClaims().entrySet()) {
      JsonClaims.Value claim = claims.get(expectation.getKey());
      if (!(claim instanceof JsonClaims.Text text)
          || !expectation.getValue().equals(text.value())) {
        throw new PolicyViolationException(
            "POLICY_CLAIM_MISMATCH",
            PolicyStage.CLAIMS,
            "a claim does not have the value required by the validation policy");
      }
    }

    if (policy.validateTimestamps()) {
      Instant now = Instant.now(policy.clock());
      long skewSeconds = policy.allowedClockSkew().getSeconds();
      validateExpiry(claims, now, skewSeconds);
      validateNotBefore(claims, now, skewSeconds);
      validateIssuedAt(claims, now, skewSeconds);
    }
  }

  private static Map<String, JsonClaims.Value> parse(String payload) {
    try {
      return JsonClaims.parseObject(payload);
    } catch (PasetoException e) {
      throw unreadable();
    }
  }

  private static void validateExpiry(
      Map<String, JsonClaims.Value> claims, Instant now, long skewSeconds) {
    JsonClaims.Value exp = claims.get("exp");
    if (exp != null && !(exp instanceof JsonClaims.Other)) {
      Instant expiry = timestamp(exp);
      if (now.isAfter(expiry.plus(skewSeconds, ChronoUnit.SECONDS))) {
        throw new PolicyViolationException(
            "POLICY_TOKEN_EXPIRED", PolicyStage.CLAIMS, "the token has expired");
      }
    }
  }

  private static void validateNotBefore(
      Map<String, JsonClaims.Value> claims, Instant now, long skewSeconds) {
    JsonClaims.Value nbf = claims.get("nbf");
    if (nbf != null && !(nbf instanceof JsonClaims.Other)) {
      Instant notBefore = timestamp(nbf);
      if (now.isBefore(notBefore.minus(skewSeconds, ChronoUnit.SECONDS))) {
        throw new PolicyViolationException(
            "POLICY_TOKEN_NOT_YET_VALID", PolicyStage.CLAIMS, "the token is not yet valid");
      }
    }
  }

  private static void validateIssuedAt(
      Map<String, JsonClaims.Value> claims, Instant now, long skewSeconds) {
    JsonClaims.Value iat = claims.get("iat");
    if (iat != null && !(iat instanceof JsonClaims.Other)) {
      Instant issuedAt = timestamp(iat);
      if (issuedAt.isAfter(now.plus(skewSeconds, ChronoUnit.SECONDS))) {
        throw new PolicyViolationException(
            "POLICY_TOKEN_ISSUED_IN_FUTURE",
            PolicyStage.CLAIMS,
            "the token was issued in the future");
      }
    }
  }

  private static Instant timestamp(JsonClaims.Value claim) {
    if (claim instanceof JsonClaims.Number number) {
      try {
        return Instant.ofEpochSecond(number.value().longValueExact());
      } catch (ArithmeticException | DateTimeException e) {
        throw malformedTimestamp();
      }
    }
    if (claim instanceof JsonClaims.Text text) {
      String value = text.value();
      try {
        return OffsetDateTime.parse(value).toInstant();
      } catch (DateTimeParseException ignored) {
        try {
          return Instant.parse(value);
        } catch (DateTimeParseException ignoredAgain) {
          throw malformedTimestamp();
        }
      }
    }
    throw malformedTimestamp();
  }

  private static PolicyViolationException unreadable() {
    return new PolicyViolationException(
        "POLICY_CLAIMS_UNREADABLE",
        PolicyStage.CLAIMS,
        "the payload does not contain a JSON object with claims");
  }

  private static PolicyViolationException malformedTimestamp() {
    return new PolicyViolationException(
        "POLICY_CLAIM_MALFORMED",
        PolicyStage.CLAIMS,
        "a timestamp claim cannot be parsed");
  }
}
