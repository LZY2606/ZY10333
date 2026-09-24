/*
 * SPDX-FileCopyrightText: Copyright © 2026 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.commons;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.paseto4j.commons.PolicyAssertions.assertSafeMessage;
import static org.paseto4j.commons.PolicyAssertions.assertViolation;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import org.junit.jupiter.api.Test;

class ClaimValidatorTest {

  private static final Instant NOW = Instant.parse("2026-01-01T00:00:00Z");
  private static final Clock CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);
  private static final Duration SKEW = Duration.ofMinutes(1);

  private static ValidationPolicy clockPolicy() {
    return ValidationPolicy.builder().clock(CLOCK, SKEW).build();
  }

  @Test
  void noClaimRulesMeansNoJsonParsing() {
    assertDoesNotThrow(
        () -> TokenValidator.validateClaims("not json at all", ValidationPolicy.permissive()));
  }

  @Test
  void nonJsonPayloadIsRejectedWhenClaimRulesAreActive() {
    PolicyViolationException exception =
        assertViolation(
            () -> TokenValidator.validateClaims("not json at all", clockPolicy()),
            "POLICY_CLAIMS_UNREADABLE",
            PolicyStage.CLAIMS);
    assertSafeMessage(exception, "not json at all");
  }

  @Test
  void expiredTokenIsRejected() {
    assertViolation(
        () -> TokenValidator.validateClaims("{\"exp\":\"2025-12-31T23:58:00+00:00\"}", clockPolicy()),
        "POLICY_TOKEN_EXPIRED",
        PolicyStage.CLAIMS);
  }

  @Test
  void tokenWithinSkewOfExpiryIsAccepted() {
    // exp + skew == now, still valid
    assertDoesNotThrow(
        () ->
            TokenValidator.validateClaims(
                "{\"exp\":\"2025-12-31T23:59:00+00:00\"}", clockPolicy()));
  }

  @Test
  void notYetValidTokenIsRejected() {
    assertViolation(
        () -> TokenValidator.validateClaims("{\"nbf\":\"2026-01-01T00:01:30+00:00\"}", clockPolicy()),
        "POLICY_TOKEN_NOT_YET_VALID",
        PolicyStage.CLAIMS);
  }

  @Test
  void tokenWithinSkewOfNotBeforeIsAccepted() {
    // nbf - skew == now, valid
    assertDoesNotThrow(
        () ->
            TokenValidator.validateClaims(
                "{\"nbf\":\"2026-01-01T00:01:00+00:00\"}", clockPolicy()));
  }

  @Test
  void tokenIssuedInTheFutureIsRejected() {
    assertViolation(
        () -> TokenValidator.validateClaims("{\"iat\":\"2026-01-01T00:02:00+00:00\"}", clockPolicy()),
        "POLICY_TOKEN_ISSUED_IN_FUTURE",
        PolicyStage.CLAIMS);
  }

  @Test
  void numericTimestampsAreSupported() {
    long expired = NOW.getEpochSecond() - 61;
    long valid = NOW.getEpochSecond() + 3600;
    assertViolation(
        () -> TokenValidator.validateClaims("{\"exp\":" + expired + "}", clockPolicy()),
        "POLICY_TOKEN_EXPIRED",
        PolicyStage.CLAIMS);
    assertDoesNotThrow(
        () -> TokenValidator.validateClaims("{\"exp\":" + valid + "}", clockPolicy()));
  }

  @Test
  void unparseableTimestampIsRejected() {
    assertViolation(
        () -> TokenValidator.validateClaims("{\"exp\":\"not-a-date\"}", clockPolicy()),
        "POLICY_CLAIM_MALFORMED",
        PolicyStage.CLAIMS);
  }

  @Test
  void requiredClaimsAreEnforced() {
    ValidationPolicy policy = ValidationPolicy.builder().requireClaims("iss", "sub").build();
    assertDoesNotThrow(
        () -> TokenValidator.validateClaims("{\"iss\":\"a\",\"sub\":\"b\"}", policy));
    assertViolation(
        () -> TokenValidator.validateClaims("{\"iss\":\"a\"}", policy),
        "POLICY_CLAIM_MISSING",
        PolicyStage.CLAIMS);
  }

  @Test
  void expectedClaimValuesAreEnforced() {
    ValidationPolicy policy =
        ValidationPolicy.builder().expectClaim("iss", "s3ns1t1ve-issuer").build();
    assertDoesNotThrow(
        () -> TokenValidator.validateClaims("{\"iss\":\"s3ns1t1ve-issuer\"}", policy));
    PolicyViolationException exception =
        assertViolation(
            () -> TokenValidator.validateClaims("{\"iss\":\"attacker\"}", policy),
            "POLICY_CLAIM_MISMATCH",
            PolicyStage.CLAIMS);
    assertSafeMessage(exception, "s3ns1t1ve-issuer", "attacker");
  }
}
