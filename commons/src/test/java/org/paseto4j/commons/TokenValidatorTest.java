/*
 * SPDX-FileCopyrightText: Copyright © 2026 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.commons;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.paseto4j.commons.PolicyAssertions.assertSafeMessage;
import static org.paseto4j.commons.PolicyAssertions.assertViolation;
import static org.paseto4j.commons.Purpose.PURPOSE_LOCAL;
import static org.paseto4j.commons.Purpose.PURPOSE_PUBLIC;
import static org.paseto4j.commons.Version.V1;
import static org.paseto4j.commons.Version.V2;
import static org.paseto4j.commons.Version.V3;
import static org.paseto4j.commons.Version.V4;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.Executors;
import org.junit.jupiter.api.Test;

class TokenValidatorTest {

  private static final String TOKEN = "v1.local.AQID"; // payload bytes 01 02 03
  private static final String TOKEN_WITH_FOOTER = "v1.local.AQID.czNjcjN0"; // footer "s3cr3t"

  private static ValidatedToken parse(String token, ValidationPolicy policy) {
    return TokenValidator.parse(token, V1, PURPOSE_LOCAL, policy, "");
  }

  @Test
  void permissivePolicyParsesToken() {
    ValidatedToken token = parse(TOKEN, ValidationPolicy.permissive());
    assertArrayEquals(new byte[] {1, 2, 3}, token.payload());
    assertArrayEquals(new byte[0], token.footer());
    assertEquals(V1, token.version());
    assertEquals(PURPOSE_LOCAL, token.purpose());
  }

  @Test
  void malformedStructuresAreRejectedAtStructureStage() {
    assertViolation(
        () -> parse("v1.local", ValidationPolicy.permissive()),
        "TOKEN_MALFORMED",
        PolicyStage.STRUCTURE);
    assertViolation(
        () -> parse("v1.local.AQID.Zm9v.extra", ValidationPolicy.permissive()),
        "TOKEN_MALFORMED",
        PolicyStage.STRUCTURE);
    assertViolation(
        () -> parse("v1..AQID", ValidationPolicy.permissive()),
        "TOKEN_MALFORMED",
        PolicyStage.STRUCTURE);
    assertViolation(
        () -> parse("v1.local.", ValidationPolicy.permissive()),
        "TOKEN_MALFORMED",
        PolicyStage.STRUCTURE);
    assertViolation(
        () -> parse("v9.local.AQID", ValidationPolicy.permissive()),
        "TOKEN_MALFORMED",
        PolicyStage.STRUCTURE);
  }

  @Test
  void emptyFooterSegmentIsNonCanonical() {
    // An empty footer has the same byte semantics as a missing footer and is therefore
    // encoded as no segment at all; a trailing dot is rejected
    assertViolation(
        () -> parse("v1.local.AQID.", ValidationPolicy.permissive()),
        "TOKEN_MALFORMED",
        PolicyStage.STRUCTURE);
  }

  @Test
  void wrongVersionIsRejected() {
    assertViolation(
        () -> parse("v2.local.AQID", ValidationPolicy.permissive()),
        "TOKEN_WRONG_VERSION",
        PolicyStage.VERSION);
  }

  @Test
  void versionOutsideAllowedSetIsRejected() {
    ValidationPolicy policy = ValidationPolicy.builder().allowVersions(V2, V3, V4).build();
    PolicyViolationException exception =
        assertViolation(() -> parse(TOKEN, policy), "POLICY_VERSION_NOT_ALLOWED", PolicyStage.VERSION);
    assertSafeMessage(exception, "AQID");
  }

  @Test
  void allowedVersionIsAccepted() {
    ValidationPolicy policy = ValidationPolicy.builder().allowVersions(V1, V2).build();
    assertDoesNotThrow(() -> parse(TOKEN, policy));
  }

  @Test
  void wrongPurposeIsRejected() {
    assertViolation(
        () -> parse("v1.public.AQID", ValidationPolicy.permissive()),
        "TOKEN_WRONG_PURPOSE",
        PolicyStage.PURPOSE);
  }

  @Test
  void purposeOutsideAllowedSetIsRejected() {
    ValidationPolicy policy =
        ValidationPolicy.builder().allowPurposes(PURPOSE_PUBLIC).build();
    assertViolation(() -> parse(TOKEN, policy), "POLICY_PURPOSE_NOT_ALLOWED", PolicyStage.PURPOSE);
  }

  @Test
  void tokenLengthLimitIsEnforcedAtBoundary() {
    assertDoesNotThrow(
        () -> parse(TOKEN, ValidationPolicy.builder().maxTokenLength(TOKEN.length()).build()));
    assertViolation(
        () -> parse(TOKEN, ValidationPolicy.builder().maxTokenLength(TOKEN.length() - 1).build()),
        "POLICY_TOKEN_TOO_LONG",
        PolicyStage.LENGTH);
  }

  @Test
  void payloadLengthLimitIsEnforcedAtBoundary() {
    assertDoesNotThrow(() -> parse(TOKEN, ValidationPolicy.builder().maxPayloadLength(4).build()));
    assertViolation(
        () -> parse(TOKEN, ValidationPolicy.builder().maxPayloadLength(3).build()),
        "POLICY_PAYLOAD_TOO_LONG",
        PolicyStage.LENGTH);
  }

  @Test
  void footerLengthLimitIsEnforcedAtBoundary() {
    int footerSegmentLength = "czNjcjN0".length();
    assertDoesNotThrow(
        () ->
            parse(
                TOKEN_WITH_FOOTER,
                ValidationPolicy.builder().maxFooterLength(footerSegmentLength).build()));
    assertViolation(
        () ->
            parse(
                TOKEN_WITH_FOOTER,
                ValidationPolicy.builder().maxFooterLength(footerSegmentLength - 1).build()),
        "POLICY_FOOTER_TOO_LONG",
        PolicyStage.LENGTH);
  }

  @Test
  void nonCanonicalPayloadSegmentIsRejectedBeforeDecoding() {
    assertViolation(
        () -> parse("v1.local.AR", ValidationPolicy.permissive()),
        "TOKEN_NON_CANONICAL_ENCODING",
        PolicyStage.ENCODING);
    assertViolation(
        () -> parse("v1.local.AQID=", ValidationPolicy.permissive()),
        "TOKEN_NON_CANONICAL_ENCODING",
        PolicyStage.ENCODING);
    assertViolation(
        () -> parse("v1.local.AQ+D", ValidationPolicy.permissive()),
        "TOKEN_NON_CANONICAL_ENCODING",
        PolicyStage.ENCODING);
  }

  @Test
  void nonCanonicalFooterSegmentIsRejected() {
    assertViolation(
        () -> parse("v1.local.AQID.Zm9v=", ValidationPolicy.permissive()),
        "TOKEN_NON_CANONICAL_ENCODING",
        PolicyStage.ENCODING);
  }

  @Test
  void exactFooterIsEnforced() {
    assertDoesNotThrow(
        () -> parse(TOKEN_WITH_FOOTER, ValidationPolicy.builder().expectFooter("s3cr3t").build()));
    PolicyViolationException exception =
        assertViolation(
            () -> parse(TOKEN_WITH_FOOTER, ValidationPolicy.builder().expectFooter("wrong").build()),
            "POLICY_FOOTER_MISMATCH",
            PolicyStage.FOOTER);
    assertSafeMessage(exception, "s3cr3t", "wrong", "czNjcjN0");
  }

  @Test
  void missingFooterDoesNotMatchExactExpectation() {
    assertViolation(
        () -> parse(TOKEN, ValidationPolicy.builder().expectFooter("s3cr3t").build()),
        "POLICY_FOOTER_MISMATCH",
        PolicyStage.FOOTER);
  }

  @Test
  void absentFooterExpectationIsEnforced() {
    assertDoesNotThrow(
        () -> parse(TOKEN, ValidationPolicy.builder().requireNoFooter().build()));
    assertViolation(
        () -> parse(TOKEN_WITH_FOOTER, ValidationPolicy.builder().requireNoFooter().build()),
        "POLICY_FOOTER_NOT_ALLOWED",
        PolicyStage.FOOTER);
  }

  @Test
  void footerPredicateIsEnforced() {
    assertDoesNotThrow(
        () ->
            parse(
                TOKEN_WITH_FOOTER,
                ValidationPolicy.builder().footerMatching(f -> f.startsWith("s3")).build()));
    assertViolation(
        () ->
            parse(
                TOKEN_WITH_FOOTER,
                ValidationPolicy.builder().footerMatching(f -> f.startsWith("zz")).build()),
        "POLICY_FOOTER_REJECTED",
        PolicyStage.FOOTER);
  }

  @Test
  void implicitAssertionRequirementIsEnforced() {
    ValidationPolicy policy = ValidationPolicy.builder().requireImplicitAssertion().build();
    assertViolation(
        () -> TokenValidator.parse(TOKEN, V1, PURPOSE_LOCAL, policy, ""),
        "POLICY_IMPLICIT_ASSERTION_REQUIRED",
        PolicyStage.IMPLICIT_ASSERTION);
    assertDoesNotThrow(
        () -> TokenValidator.parse(TOKEN, V1, PURPOSE_LOCAL, policy, "an-assertion"));
  }

  @Test
  void legacyPolicyMatchesLegacyFooterSemantics() {
    assertDoesNotThrow(() -> parse(TOKEN, ValidationPolicy.legacy("")));
    assertDoesNotThrow(() -> parse(TOKEN, ValidationPolicy.legacy(null)));
    assertDoesNotThrow(() -> parse(TOKEN_WITH_FOOTER, ValidationPolicy.legacy("s3cr3t")));
    assertThrows(
        PolicyViolationException.class, () -> parse(TOKEN_WITH_FOOTER, ValidationPolicy.legacy("")));
    assertThrows(
        PolicyViolationException.class,
        () -> parse(TOKEN_WITH_FOOTER, ValidationPolicy.legacy("wrong")));
    assertThrows(
        PolicyViolationException.class, () -> parse(TOKEN, ValidationPolicy.legacy("s3cr3t")));
  }

  @Test
  void policyIsImmutable() {
    ValidationPolicy policy =
        ValidationPolicy.builder().allowVersions(V1).requireClaims("iss").build();
    assertThrows(UnsupportedOperationException.class, () -> policy.allowedVersions().add(V2));
    assertThrows(UnsupportedOperationException.class, () -> policy.requiredClaims().clear());
    assertThrows(
        UnsupportedOperationException.class, () -> policy.expectedClaims().put("iss", "x"));
  }

  @Test
  void policyIsSafeToShareBetweenThreads() throws Exception {
    ValidationPolicy policy =
        ValidationPolicy.builder().allowVersions(V1).maxTokenLength(64).build();
    Callable<ValidatedToken> task = () -> parse(TOKEN, policy);
    try (var executor = Executors.newFixedThreadPool(8)) {
      List<Callable<ValidatedToken>> tasks = new ArrayList<>();
      for (int i = 0; i < 64; i++) {
        tasks.add(task);
      }
      var results = executor.invokeAll(tasks);
      for (var result : results) {
        assertArrayEquals(new byte[] {1, 2, 3}, result.get().payload());
      }
    }
  }
}
