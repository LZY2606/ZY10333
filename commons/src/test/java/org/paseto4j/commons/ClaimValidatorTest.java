/*
 * SPDX-FileCopyrightText: Copyright © 2026 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.commons;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import org.junit.jupiter.api.Test;

class ClaimValidatorTest {

  private static final Instant NOW = Instant.parse("2024-06-01T00:00:00Z");
  private static final Clock FIXED_CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);

  private static ValidationPolicy.Builder temporalPolicy() {
    return ValidationPolicy.builder().clock(FIXED_CLOCK).validateTemporalClaims();
  }

  @Test
  void ignoresPayloadWhenNoClaimRulesApply() {
    assertDoesNotThrow(() -> ClaimValidator.validate("not json at all", ValidationPolicy.permissive()));
  }

  @Test
  void rejectsNonJsonPayloadWhenClaimRulesApply() {
    ValidationPolicy policy = ValidationPolicy.builder().requireClaims("exp").build();

    ValidationException notJson =
        assertThrows(ValidationException.class, () -> ClaimValidator.validate("not json", policy));
    assertEquals(FailureCode.MALFORMED_CLAIMS, notJson.code());
    assertEquals(ValidationPhase.CLAIMS, notJson.phase());

    ValidationException notObject =
        assertThrows(ValidationException.class, () -> ClaimValidator.validate("[1,2]", policy));
    assertEquals(FailureCode.MALFORMED_CLAIMS, notObject.code());
  }

  @Test
  void enforcesRequiredClaims() {
    ValidationPolicy policy = ValidationPolicy.builder().requireClaims("sub", "exp").build();

    assertDoesNotThrow(
        () -> ClaimValidator.validate("{\"sub\":\"alice\",\"exp\":\"2030-01-01T00:00:00Z\"}", policy));

    ValidationException e =
        assertThrows(
            ValidationException.class,
            () -> ClaimValidator.validate("{\"sub\":\"alice\"}", policy));
    assertEquals(FailureCode.MISSING_CLAIM, e.code());
    assertEquals(ValidationPhase.CLAIMS, e.phase());
  }

  @Test
  void enforcesIssuer() {
    ValidationPolicy policy = ValidationPolicy.builder().expectIssuer("paseto4j").build();

    assertDoesNotThrow(() -> ClaimValidator.validate("{\"iss\":\"paseto4j\"}", policy));

    ValidationException wrong =
        assertThrows(
            ValidationException.class, () -> ClaimValidator.validate("{\"iss\":\"other\"}", policy));
    assertEquals(FailureCode.UNEXPECTED_ISSUER, wrong.code());

    ValidationException missing =
        assertThrows(ValidationException.class, () -> ClaimValidator.validate("{}", policy));
    assertEquals(FailureCode.UNEXPECTED_ISSUER, missing.code());
  }

  @Test
  void enforcesAudience() {
    ValidationPolicy policy = ValidationPolicy.builder().expectAudience("api").build();

    assertDoesNotThrow(() -> ClaimValidator.validate("{\"aud\":\"api\"}", policy));

    ValidationException e =
        assertThrows(
            ValidationException.class, () -> ClaimValidator.validate("{\"aud\":\"web\"}", policy));
    assertEquals(FailureCode.UNEXPECTED_AUDIENCE, e.code());
  }

  @Test
  void rejectsExpiredToken() {
    ValidationPolicy policy = temporalPolicy().build();

    ValidationException e =
        assertThrows(
            ValidationException.class,
            () -> ClaimValidator.validate("{\"exp\":\"2024-05-31T23:59:59+00:00\"}", policy));
    assertEquals(FailureCode.TOKEN_EXPIRED, e.code());
    assertEquals(ValidationPhase.CLAIMS, e.phase());
  }

  @Test
  void acceptsTokenExpiringInTheFuture() {
    ValidationPolicy policy = temporalPolicy().build();

    assertDoesNotThrow(
        () -> ClaimValidator.validate("{\"exp\":\"2024-06-01T00:00:01+00:00\"}", policy));
    // exp equal to now is still valid
    assertDoesNotThrow(
        () -> ClaimValidator.validate("{\"exp\":\"2024-06-01T00:00:00+00:00\"}", policy));
    // 'Z' instant form is accepted as well
    assertDoesNotThrow(() -> ClaimValidator.validate("{\"exp\":\"2030-01-01T00:00:00Z\"}", policy));
  }

  @Test
  void clockSkewCoversBoundaryOnBothEnds() {
    ValidationPolicy lenient = temporalPolicy().maxClockSkew(Duration.ofSeconds(2)).build();

    // expired 1 second ago: inside the skew window
    assertDoesNotThrow(
        () -> ClaimValidator.validate("{\"exp\":\"2024-05-31T23:59:59+00:00\"}", lenient));
    // becomes valid in 1 second: inside the skew window
    assertDoesNotThrow(
        () -> ClaimValidator.validate("{\"nbf\":\"2024-06-01T00:00:01+00:00\"}", lenient));

    ValidationPolicy strict = temporalPolicy().build();
    ValidationException expired =
        assertThrows(
            ValidationException.class,
            () -> ClaimValidator.validate("{\"exp\":\"2024-05-31T23:59:59+00:00\"}", strict));
    assertEquals(FailureCode.TOKEN_EXPIRED, expired.code());

    ValidationException notYetValid =
        assertThrows(
            ValidationException.class,
            () -> ClaimValidator.validate("{\"nbf\":\"2024-06-01T00:00:01+00:00\"}", strict));
    assertEquals(FailureCode.TOKEN_NOT_YET_VALID, notYetValid.code());
    assertEquals(ValidationPhase.CLAIMS, notYetValid.phase());
  }

  @Test
  void rejectsTokenIssuedInTheFuture() {
    ValidationPolicy policy = temporalPolicy().build();

    ValidationException e =
        assertThrows(
            ValidationException.class,
            () -> ClaimValidator.validate("{\"iat\":\"2024-06-01T00:00:01+00:00\"}", policy));
    assertEquals(FailureCode.ISSUED_IN_FUTURE, e.code());
    assertEquals(ValidationPhase.CLAIMS, e.phase());

    assertDoesNotThrow(
        () -> ClaimValidator.validate("{\"iat\":\"2024-05-31T23:59:59+00:00\"}", policy));
  }

  @Test
  void rejectsUnparseableTemporalClaim() {
    ValidationPolicy policy = temporalPolicy().build();

    ValidationException e =
        assertThrows(
            ValidationException.class,
            () -> ClaimValidator.validate("{\"exp\":\"tomorrow\"}", policy));
    assertEquals(FailureCode.MALFORMED_CLAIMS, e.code());

    ValidationException nonTextual =
        assertThrows(
            ValidationException.class,
            () -> ClaimValidator.validate("{\"exp\":12345}", policy));
    assertEquals(FailureCode.MALFORMED_CLAIMS, nonTextual.code());
  }
}
