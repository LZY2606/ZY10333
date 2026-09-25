/*
 * SPDX-FileCopyrightText: Copyright © 2026 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.commons;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.format.DateTimeParseException;
import java.util.Locale;

/**
 * Validates the claims of an authenticated payload against a {@link ValidationPolicy}. Runs only
 * after decryption or signature verification succeeded, and only when the policy defines claim
 * rules; payloads that are not JSON are left untouched unless claim rules apply.
 */
public final class ClaimValidator {

  private static final ObjectMapper MAPPER = new ObjectMapper();

  private ClaimValidator() {}

  /**
   * Validates {@code payload} against the claim rules of {@code policy}.
   *
   * @throws ValidationException when a claim rule is violated or the payload is not a JSON claims
   *     object while claim rules apply
   */
  public static void validate(String payload, ValidationPolicy policy) {
    if (!policy.hasClaimRules()) {
      return;
    }
    JsonNode claims = parse(payload);
    for (String required : policy.requiredClaims()) {
      if (!claims.has(required) || claims.get(required).isNull()) {
        throw new ValidationException(
            FailureCode.MISSING_CLAIM,
            String.format(Locale.ROOT, "required claim '%s' is missing", required));
      }
    }
    if (policy.expectedIssuer() != null
        && !policy.expectedIssuer().equals(text(claims, "iss"))) {
      throw new ValidationException(
          FailureCode.UNEXPECTED_ISSUER, "issuer claim does not match the policy");
    }
    if (policy.expectedAudience() != null
        && !policy.expectedAudience().equals(text(claims, "aud"))) {
      throw new ValidationException(
          FailureCode.UNEXPECTED_AUDIENCE, "audience claim does not match the policy");
    }
    if (policy.temporalValidation()) {
      validateTemporal(claims, policy);
    }
  }

  private static void validateTemporal(JsonNode claims, ValidationPolicy policy) {
    Instant now = policy.clock().instant();
    Instant notBeforeLimit = now.plus(policy.maxClockSkew());
    if (claims.has("exp") && !claims.get("exp").isNull()) {
      Instant expires = temporal(claims, "exp");
      if (now.isAfter(expires.plus(policy.maxClockSkew()))) {
        throw new ValidationException(FailureCode.TOKEN_EXPIRED, "token is expired");
      }
    }
    if (claims.has("nbf") && !claims.get("nbf").isNull()) {
      if (notBeforeLimit.isBefore(temporal(claims, "nbf"))) {
        throw new ValidationException(FailureCode.TOKEN_NOT_YET_VALID, "token is not yet valid");
      }
    }
    if (claims.has("iat") && !claims.get("iat").isNull()) {
      if (notBeforeLimit.isBefore(temporal(claims, "iat"))) {
        throw new ValidationException(
            FailureCode.ISSUED_IN_FUTURE, "token was issued in the future");
      }
    }
  }

  private static JsonNode parse(String payload) {
    final JsonNode claims;
    try {
      claims = MAPPER.readTree(payload);
    } catch (Exception e) {
      throw new ValidationException(
          FailureCode.MALFORMED_CLAIMS, "payload is not a JSON claims object", e);
    }
    if (claims == null || !claims.isObject()) {
      throw new ValidationException(
          FailureCode.MALFORMED_CLAIMS, "payload is not a JSON claims object");
    }
    return claims;
  }

  private static String text(JsonNode claims, String name) {
    JsonNode node = claims.get(name);
    return node != null && node.isTextual() ? node.asText() : null;
  }

  private static Instant temporal(JsonNode claims, String name) {
    JsonNode node = claims.get(name);
    if (node == null || !node.isTextual()) {
      throw new ValidationException(
          FailureCode.MALFORMED_CLAIMS,
          String.format(Locale.ROOT, "claim '%s' is not an ISO-8601 timestamp", name));
    }
    String value = node.asText();
    try {
      return OffsetDateTime.parse(value).toInstant();
    } catch (DateTimeParseException ignored) {
      // fall through to Instant form below
    }
    try {
      return Instant.parse(value);
    } catch (DateTimeParseException e) {
      throw new ValidationException(
          FailureCode.MALFORMED_CLAIMS,
          String.format(Locale.ROOT, "claim '%s' is not an ISO-8601 timestamp", name),
          e);
    }
  }
}
