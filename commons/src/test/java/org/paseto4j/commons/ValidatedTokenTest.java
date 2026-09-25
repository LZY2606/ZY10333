/*
 * SPDX-FileCopyrightText: Copyright © 2026 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.commons;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

class ValidatedTokenTest {

  // "payload" and "footer" in canonical unpadded base64url
  private static final String TOKEN = "v2.local.cGF5bG9hZA";
  private static final String TOKEN_WITH_FOOTER = TOKEN + ".Zm9vdGVy";

  @Test
  void parsesValidToken() {
    ValidatedToken token = ValidatedToken.parse(TOKEN, ValidationPolicy.permissive());

    assertEquals(Version.V2, token.version());
    assertEquals(Purpose.PURPOSE_LOCAL, token.purpose());
    assertArrayEquals("payload".getBytes(), token.payload());
    assertArrayEquals(new byte[0], token.footer());
    assertArrayEquals("v2.local.".getBytes(), token.header());
  }

  @Test
  void parsesFooter() {
    ValidatedToken token = ValidatedToken.parse(TOKEN_WITH_FOOTER, ValidationPolicy.permissive());

    assertArrayEquals("footer".getBytes(), token.footer());
    assertDoesNotThrow(() -> token.verifyFooter("footer"));
  }

  @Test
  void emptyFooterSegmentHasSameByteSemanticsAsMissingFooter() {
    ValidatedToken withEmptySegment = ValidatedToken.parse(TOKEN + ".", ValidationPolicy.permissive());
    ValidatedToken withoutSegment = ValidatedToken.parse(TOKEN, ValidationPolicy.permissive());

    assertArrayEquals(new byte[0], withEmptySegment.footer());
    assertArrayEquals(withoutSegment.footer(), withEmptySegment.footer());
    assertDoesNotThrow(() -> withEmptySegment.verifyFooter(""));
    assertDoesNotThrow(() -> withEmptySegment.verifyFooter(null));

    ValidationPolicy expectEmpty = ValidationPolicy.builder().expectFooter("").build();
    assertDoesNotThrow(() -> ValidatedToken.parse(TOKEN, expectEmpty));
    assertDoesNotThrow(() -> ValidatedToken.parse(TOKEN + ".", expectEmpty));
  }

  @Test
  void rejectsNullAndEmptyToken() {
    ValidationException nullToken =
        assertThrows(
            ValidationException.class, () -> ValidatedToken.parse(null, ValidationPolicy.permissive()));
    assertEquals(FailureCode.MALFORMED_TOKEN, nullToken.code());
    assertEquals(ValidationPhase.STRUCTURE, nullToken.phase());

    ValidationException empty =
        assertThrows(
            ValidationException.class, () -> ValidatedToken.parse("", ValidationPolicy.permissive()));
    assertEquals(FailureCode.MALFORMED_TOKEN, empty.code());
  }

  @Test
  void rejectsWrongSegmentCount() {
    ValidationException twoParts =
        assertThrows(
            ValidationException.class,
            () -> ValidatedToken.parse("v2.local", ValidationPolicy.permissive()));
    assertEquals(FailureCode.MALFORMED_TOKEN, twoParts.code());

    ValidationException fiveParts =
        assertThrows(
            ValidationException.class,
            () -> ValidatedToken.parse("v2.local.a.b.c", ValidationPolicy.permissive()));
    assertEquals(FailureCode.MALFORMED_TOKEN, fiveParts.code());
  }

  @Test
  void rejectsUnknownVersionAndPurpose() {
    ValidationException version =
        assertThrows(
            ValidationException.class,
            () -> ValidatedToken.parse("v9.local.cGF5bG9hZA", ValidationPolicy.permissive()));
    assertEquals(FailureCode.MALFORMED_TOKEN, version.code());

    ValidationException purpose =
        assertThrows(
            ValidationException.class,
            () -> ValidatedToken.parse("v2.secret.cGF5bG9hZA", ValidationPolicy.permissive()));
    assertEquals(FailureCode.MALFORMED_TOKEN, purpose.code());
  }

  @Test
  void enforcesAllowedVersions() {
    ValidationPolicy policy = ValidationPolicy.builder().allowVersions(Version.V4).build();

    ValidationException e =
        assertThrows(ValidationException.class, () -> ValidatedToken.parse(TOKEN, policy));
    assertEquals(FailureCode.VERSION_NOT_ALLOWED, e.code());
    assertEquals(ValidationPhase.STRUCTURE, e.phase());

    ValidationPolicy allowed =
        ValidationPolicy.builder().allowVersions(Version.V2, Version.V4).build();
    assertDoesNotThrow(() -> ValidatedToken.parse(TOKEN, allowed));
  }

  @Test
  void enforcesAllowedPurposes() {
    ValidationPolicy policy =
        ValidationPolicy.builder().allowPurposes(Purpose.PURPOSE_PUBLIC).build();

    ValidationException e =
        assertThrows(ValidationException.class, () -> ValidatedToken.parse(TOKEN, policy));
    assertEquals(FailureCode.PURPOSE_NOT_ALLOWED, e.code());
    assertEquals(ValidationPhase.STRUCTURE, e.phase());
  }

  @Test
  void enforcesMaxTokenLengthAtBoundary() {
    assertDoesNotThrow(
        () ->
            ValidatedToken.parse(
                TOKEN, ValidationPolicy.builder().maxTokenLength(TOKEN.length()).build()));

    ValidationException e =
        assertThrows(
            ValidationException.class,
            () ->
                ValidatedToken.parse(
                    TOKEN, ValidationPolicy.builder().maxTokenLength(TOKEN.length() - 1).build()));
    assertEquals(FailureCode.TOKEN_TOO_LONG, e.code());
    assertEquals(ValidationPhase.STRUCTURE, e.phase());
  }

  @Test
  void enforcesMaxPayloadLengthAtBoundary() {
    String payloadSegment = "cGF5bG9hZA";
    assertDoesNotThrow(
        () ->
            ValidatedToken.parse(
                TOKEN, ValidationPolicy.builder().maxPayloadLength(payloadSegment.length()).build()));

    ValidationException e =
        assertThrows(
            ValidationException.class,
            () ->
                ValidatedToken.parse(
                    TOKEN,
                    ValidationPolicy.builder().maxPayloadLength(payloadSegment.length() - 1).build()));
    assertEquals(FailureCode.SEGMENT_TOO_LONG, e.code());
    assertEquals(ValidationPhase.STRUCTURE, e.phase());
  }

  @Test
  void enforcesMaxFooterLengthAtBoundary() {
    String footerSegment = "Zm9vdGVy";
    assertDoesNotThrow(
        () ->
            ValidatedToken.parse(
                TOKEN_WITH_FOOTER,
                ValidationPolicy.builder().maxFooterLength(footerSegment.length()).build()));

    ValidationException e =
        assertThrows(
            ValidationException.class,
            () ->
                ValidatedToken.parse(
                    TOKEN_WITH_FOOTER,
                    ValidationPolicy.builder().maxFooterLength(footerSegment.length() - 1).build()));
    assertEquals(FailureCode.SEGMENT_TOO_LONG, e.code());
  }

  @Test
  void rejectsNonCanonicalPayload() {
    // "QR" decodes to the same byte as canonical "QQ": a lenient decoder would accept it
    ValidationException nonCanonical =
        assertThrows(
            ValidationException.class,
            () -> ValidatedToken.parse("v2.local.QR", ValidationPolicy.permissive()));
    assertEquals(FailureCode.NON_CANONICAL_ENCODING, nonCanonical.code());
    assertEquals(ValidationPhase.STRUCTURE, nonCanonical.phase());

    ValidationException padded =
        assertThrows(
            ValidationException.class,
            () -> ValidatedToken.parse("v2.local.cGF5bG9hZA==", ValidationPolicy.permissive()));
    assertEquals(FailureCode.NON_CANONICAL_ENCODING, padded.code());
  }

  @Test
  void rejectsNonCanonicalFooter() {
    ValidationException e =
        assertThrows(
            ValidationException.class,
            () -> ValidatedToken.parse(TOKEN + ".Zm9vdGVy==", ValidationPolicy.permissive()));
    assertEquals(FailureCode.NON_CANONICAL_ENCODING, e.code());
  }

  @Test
  void enforcesPolicyFooter() {
    ValidationPolicy matching = ValidationPolicy.builder().expectFooter("footer").build();
    assertDoesNotThrow(() -> ValidatedToken.parse(TOKEN_WITH_FOOTER, matching));

    ValidationPolicy mismatching = ValidationPolicy.builder().expectFooter("other").build();
    ValidationException e =
        assertThrows(
            ValidationException.class, () -> ValidatedToken.parse(TOKEN_WITH_FOOTER, mismatching));
    assertEquals(FailureCode.FOOTER_MISMATCH, e.code());
    assertEquals(ValidationPhase.FOOTER, e.phase());
  }

  @Test
  void enforcesFooterPredicate() {
    ValidationPolicy accepting =
        ValidationPolicy.builder().footerPredicate(f -> f.startsWith("foot")).build();
    assertDoesNotThrow(() -> ValidatedToken.parse(TOKEN_WITH_FOOTER, accepting));

    ValidationPolicy rejecting =
        ValidationPolicy.builder().footerPredicate(f -> f.startsWith("head")).build();
    ValidationException e =
        assertThrows(
            ValidationException.class, () -> ValidatedToken.parse(TOKEN_WITH_FOOTER, rejecting));
    assertEquals(FailureCode.FOOTER_REJECTED, e.code());
    assertEquals(ValidationPhase.FOOTER, e.phase());
  }

  @Test
  void verifyFooterMatchesCallerSuppliedFooter() {
    ValidatedToken token = ValidatedToken.parse(TOKEN_WITH_FOOTER, ValidationPolicy.permissive());

    ValidationException e =
        assertThrows(ValidationException.class, () -> token.verifyFooter("wrong"));
    assertEquals(FailureCode.FOOTER_MISMATCH, e.code());
    assertEquals(ValidationPhase.FOOTER, e.phase());
  }

  @Test
  void enforcesImplicitAssertionRules() {
    ValidationPolicy required = ValidationPolicy.builder().requireImplicitAssertion().build();
    ValidationException unsupported =
        assertThrows(
            ValidationException.class, () -> required.verifyImplicitAssertion("assertion", false));
    assertEquals(FailureCode.IMPLICIT_ASSERTION_REQUIRED, unsupported.code());
    assertEquals(ValidationPhase.IMPLICIT_ASSERTION, unsupported.phase());

    ValidationException missing =
        assertThrows(ValidationException.class, () -> required.verifyImplicitAssertion("", true));
    assertEquals(FailureCode.IMPLICIT_ASSERTION_REQUIRED, missing.code());

    assertDoesNotThrow(() -> required.verifyImplicitAssertion("assertion", true));

    ValidationPolicy exact = ValidationPolicy.builder().expectImplicitAssertion("expected").build();
    ValidationException mismatch =
        assertThrows(ValidationException.class, () -> exact.verifyImplicitAssertion("other", true));
    assertEquals(FailureCode.IMPLICIT_ASSERTION_MISMATCH, mismatch.code());
    assertEquals(ValidationPhase.IMPLICIT_ASSERTION, mismatch.phase());
    assertDoesNotThrow(() -> exact.verifyImplicitAssertion("expected", true));
  }

  @Test
  void failureMessagesDoNotContainSecrets() {
    String secretToken = "v2.local.c2VjcmV0LXBheWxvYWQ=";
    ValidationException e =
        assertThrows(
            ValidationException.class,
            () -> ValidatedToken.parse(secretToken, ValidationPolicy.permissive()));
    assertFalse(e.getMessage().contains(secretToken));
    assertFalse(e.getMessage().contains("c2VjcmV0"));
  }

  @Test
  void policyIsImmutable() {
    ValidationPolicy.Builder builder =
        ValidationPolicy.builder().allowVersions(Version.V2).requireClaims("exp");
    ValidationPolicy policy = builder.build();

    assertThrows(UnsupportedOperationException.class, () -> policy.allowedVersions().add(Version.V4));
    assertThrows(UnsupportedOperationException.class, () -> policy.requiredClaims().add("sub"));

    // later builder mutations must not leak into the built policy
    builder.allowVersions(Version.V4).requireClaims("sub");
    assertFalse(policy.allowedVersions().contains(Version.V4));
    assertFalse(policy.requiredClaims().contains("sub"));
  }

  @Test
  void policyIsSafeForConcurrentUse() throws InterruptedException {
    ValidationPolicy policy =
        ValidationPolicy.builder()
            .allowVersions(Version.V2)
            .expectFooter("footer")
            .maxTokenLength(TOKEN_WITH_FOOTER.length())
            .build();
    int threads = 8;
    CountDownLatch ready = new CountDownLatch(threads);
    CountDownLatch start = new CountDownLatch(1);
    AtomicInteger failures = new AtomicInteger();
    Thread[] workers = new Thread[threads];

    for (int i = 0; i < threads; i++) {
      workers[i] =
          new Thread(
              () -> {
                ready.countDown();
                try {
                  start.await();
                  for (int j = 0; j < 50; j++) {
                    ValidatedToken.parse(TOKEN_WITH_FOOTER, policy).verifyFooter("footer");
                  }
                } catch (Exception e) {
                  failures.incrementAndGet();
                }
              });
      workers[i].start();
    }
    assertEquals(true, ready.await(30, TimeUnit.SECONDS));
    start.countDown();
    for (Thread worker : workers) {
      worker.join(30000);
      assertFalse(worker.isAlive());
    }
    assertEquals(0, failures.get());
  }
}
