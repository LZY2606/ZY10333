/*
 * SPDX-FileCopyrightText: Copyright © 2026 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.version1;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.paseto4j.commons.HexToBytes.hexToBytes;
import static org.paseto4j.commons.PolicyAssertions.assertSafeMessage;
import static org.paseto4j.commons.PolicyAssertions.assertViolation;
import static org.paseto4j.commons.Purpose.PURPOSE_LOCAL;
import static org.paseto4j.commons.Purpose.PURPOSE_PUBLIC;
import static org.paseto4j.commons.Version.V1;
import static org.paseto4j.commons.Version.V2;

import java.security.KeyPairGenerator;
import java.security.SignatureException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import org.junit.jupiter.api.Test;
import org.paseto4j.commons.PasetoException;
import org.paseto4j.commons.PolicyStage;
import org.paseto4j.commons.PolicyViolationException;
import org.paseto4j.commons.SecretKey;
import org.paseto4j.commons.ValidationPolicy;

class PasetoPolicyTest {

  private static final String KEY =
      "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f";
  private static final String WRONG_KEY =
      "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8e";
  private static final String NONCE = "26f7553354482a1d91d4784627854b8da6b8042a7966523c2b404e8dbbe7f7f2";
  private static final String PAYLOAD =
      "{\"data\":\"this is a signed message\",\"exp\":\"2019-01-01T00:00:00+00:00\"}";
  private static final String FOOTER = "{\"kid\":\"UbkK8Y6iv4GZhFp6Tx3IWLWLfNXSEvJcdT3zdR65YZxo\"}";
  // Official v1 test vector (4-E-3)
  private static final String TOKEN =
      "v1.local.4VyfcVcFAOAbB8yEM1j1Ob7Iez5VZJy5kHNsQxmlrAwKUbOtq9cv39T2fC0MDWafX0nQJ4grFZzTdroMvU772RW-X1oTtoFBjsl_3YYHWnwgqzs0aFc3ejjORmKP4KUM339W3szA28OabR192eRqiyspQ6xPM35NMR-04-FhRJZEWiF0W5oWjPVtGPjeVjm2DI4YtJg.eyJraWQiOiJVYmtLOFk2aXY0R1poRnA2VHgzSVdMV0xmTlhTRXZKY2RUM3pkUjY1WVp4byJ9";

  private static SecretKey key() {
    return SecretKey.fromHexString(KEY);
  }

  @Test
  void legacyApiRemainsCompatible() {
    assertEquals(PAYLOAD, Paseto.decrypt(key(), TOKEN, FOOTER));
    assertEquals(PAYLOAD, Paseto.decrypt(key(), TOKEN, ValidationPolicy.permissive()));
    assertEquals(PAYLOAD, Paseto.decrypt(key(), TOKEN, ValidationPolicy.legacy(FOOTER)));
  }

  @Test
  void versionMustBeAllowed() {
    ValidationPolicy policy = ValidationPolicy.builder().allowVersions(V2).build();
    PolicyViolationException exception =
        assertViolation(
            () -> Paseto.decrypt(key(), TOKEN, policy),
            "POLICY_VERSION_NOT_ALLOWED",
            PolicyStage.VERSION);
    assertSafeMessage(exception, TOKEN, PAYLOAD, KEY);
    assertDoesNotThrow(
        () -> Paseto.decrypt(key(), TOKEN, ValidationPolicy.builder().allowVersions(V1).build()));
  }

  @Test
  void purposeMustBeAllowed() {
    ValidationPolicy policy = ValidationPolicy.builder().allowPurposes(PURPOSE_PUBLIC).build();
    assertViolation(
        () -> Paseto.decrypt(key(), TOKEN, policy),
        "POLICY_PURPOSE_NOT_ALLOWED",
        PolicyStage.PURPOSE);
    assertDoesNotThrow(
        () ->
            Paseto.decrypt(
                key(), TOKEN, ValidationPolicy.builder().allowPurposes(PURPOSE_LOCAL).build()));
  }

  @Test
  void tokenLengthBoundaryIsEnforced() {
    assertDoesNotThrow(
        () ->
            Paseto.decrypt(
                key(),
                TOKEN,
                ValidationPolicy.builder().maxTokenLength(TOKEN.length()).build()));
    assertViolation(
        () ->
            Paseto.decrypt(
                key(),
                TOKEN,
                ValidationPolicy.builder().maxTokenLength(TOKEN.length() - 1).build()),
        "POLICY_TOKEN_TOO_LONG",
        PolicyStage.LENGTH);
  }

  @Test
  void segmentLengthBoundariesAreEnforced() {
    String payloadSegment = TOKEN.split("\\.")[2];
    String footerSegment = TOKEN.split("\\.")[3];
    assertDoesNotThrow(
        () ->
            Paseto.decrypt(
                key(),
                TOKEN,
                ValidationPolicy.builder()
                    .maxPayloadLength(payloadSegment.length())
                    .maxFooterLength(footerSegment.length())
                    .build()));
    assertViolation(
        () ->
            Paseto.decrypt(
                key(),
                TOKEN,
                ValidationPolicy.builder().maxPayloadLength(payloadSegment.length() - 1).build()),
        "POLICY_PAYLOAD_TOO_LONG",
        PolicyStage.LENGTH);
    assertViolation(
        () ->
            Paseto.decrypt(
                key(),
                TOKEN,
                ValidationPolicy.builder().maxFooterLength(footerSegment.length() - 1).build()),
        "POLICY_FOOTER_TOO_LONG",
        PolicyStage.LENGTH);
  }

  @Test
  void footerExpectationsAreEnforced() {
    assertDoesNotThrow(
        () -> Paseto.decrypt(key(), TOKEN, ValidationPolicy.builder().expectFooter(FOOTER).build()));
    assertDoesNotThrow(
        () ->
            Paseto.decrypt(
                key(),
                TOKEN,
                ValidationPolicy.builder().footerMatching(f -> f.contains("kid")).build()));
    assertViolation(
        () -> Paseto.decrypt(key(), TOKEN, ValidationPolicy.builder().expectFooter("nope").build()),
        "POLICY_FOOTER_MISMATCH",
        PolicyStage.FOOTER);
    assertViolation(
        () -> Paseto.decrypt(key(), TOKEN, ValidationPolicy.builder().requireNoFooter().build()),
        "POLICY_FOOTER_NOT_ALLOWED",
        PolicyStage.FOOTER);
    assertViolation(
        () ->
            Paseto.decrypt(
                key(),
                TOKEN,
                ValidationPolicy.builder().footerMatching(f -> f.contains("secret")).build()),
        "POLICY_FOOTER_REJECTED",
        PolicyStage.FOOTER);
  }

  @Test
  void nonCanonicalEncodingIsRejectedBeforeCrypto() {
    String tampered = TOKEN + "=";
    PolicyViolationException exception =
        assertViolation(
            () -> Paseto.decrypt(key(), tampered, ValidationPolicy.permissive()),
            "TOKEN_NON_CANONICAL_ENCODING",
            PolicyStage.ENCODING);
    assertSafeMessage(exception, tampered, PAYLOAD, KEY);
  }

  @Test
  void implicitAssertionRequirementAppliesToAllVersions() {
    ValidationPolicy policy = ValidationPolicy.builder().requireImplicitAssertion().build();
    assertViolation(
        () -> Paseto.decrypt(key(), TOKEN, policy),
        "POLICY_IMPLICIT_ASSERTION_REQUIRED",
        PolicyStage.IMPLICIT_ASSERTION);
  }

  @Test
  void wrongKeyIsAnAuthenticationFailureNotAPolicyRejection() {
    RuntimeException exception =
        assertThrows(
            RuntimeException.class,
            () -> Paseto.decrypt(SecretKey.fromHexString(WRONG_KEY), TOKEN, ValidationPolicy.permissive()));
    assertFalse(exception instanceof PolicyViolationException);
  }

  @Test
  void expiredAndFutureTokensAreRejectedByTheClock() {
    String token =
        PasetoLocal.encrypt(
            key(),
            hexToBytes(NONCE),
            "{\"data\":\"test\",\"exp\":\"2026-01-01T00:00:00+00:00\",\"nbf\":\"2025-01-01T00:00:00+00:00\"}",
            "");

    Clock valid = Clock.fixed(Instant.parse("2025-06-01T00:00:00Z"), ZoneOffset.UTC);
    assertDoesNotThrow(
        () ->
            Paseto.decrypt(
                key(),
                token,
                ValidationPolicy.builder().clock(valid, Duration.ofMinutes(1)).build()));

    Clock afterExpiry = Clock.fixed(Instant.parse("2026-01-01T00:02:00Z"), ZoneOffset.UTC);
    PolicyViolationException expired =
        assertViolation(
            () ->
                Paseto.decrypt(
                    key(),
                    token,
                    ValidationPolicy.builder().clock(afterExpiry, Duration.ofMinutes(1)).build()),
            "POLICY_TOKEN_EXPIRED",
            PolicyStage.CLAIMS);
    assertSafeMessage(expired, token, KEY);

    Clock beforeNotBefore = Clock.fixed(Instant.parse("2024-12-31T23:58:00Z"), ZoneOffset.UTC);
    assertViolation(
        () ->
            Paseto.decrypt(
                key(),
                token,
                ValidationPolicy.builder().clock(beforeNotBefore, Duration.ofMinutes(1)).build()),
        "POLICY_TOKEN_NOT_YET_VALID",
        PolicyStage.CLAIMS);
  }

  @Test
  void claimRestrictionsAreEnforced() {
    String token =
        PasetoLocal.encrypt(
            key(), hexToBytes(NONCE), "{\"iss\":\"paseto4j\",\"data\":\"test\"}", "");
    assertDoesNotThrow(
        () ->
            Paseto.decrypt(
                key(),
                token,
                ValidationPolicy.builder()
                    .requireClaims("iss")
                    .expectClaim("iss", "paseto4j")
                    .build()));
    assertViolation(
        () ->
            Paseto.decrypt(
                key(), token, ValidationPolicy.builder().requireClaims("sub").build()),
        "POLICY_CLAIM_MISSING",
        PolicyStage.CLAIMS);
    assertViolation(
        () ->
            Paseto.decrypt(
                key(), token, ValidationPolicy.builder().expectClaim("iss", "other").build()),
        "POLICY_CLAIM_MISMATCH",
        PolicyStage.CLAIMS);
  }

  @Test
  void publicTokensFollowTheSameStages() throws Exception {
    var generator = KeyPairGenerator.getInstance("RSA");
    generator.initialize(2048);
    var keyPair = generator.generateKeyPair();
    RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
    RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();

    String token = Paseto.sign(privateKey, PAYLOAD, FOOTER);

    // legacy API and permissive policy agree
    assertEquals(PAYLOAD, Paseto.parse(publicKey, token, FOOTER));
    assertEquals(PAYLOAD, Paseto.parse(publicKey, token, ValidationPolicy.permissive()));

    assertViolation(
        () -> Paseto.parse(publicKey, token, ValidationPolicy.builder().allowVersions(V2).build()),
        "POLICY_VERSION_NOT_ALLOWED",
        PolicyStage.VERSION);
    assertViolation(
        () ->
            Paseto.parse(
                publicKey, token, ValidationPolicy.builder().allowPurposes(PURPOSE_LOCAL).build()),
        "POLICY_PURPOSE_NOT_ALLOWED",
        PolicyStage.PURPOSE);
    assertViolation(
        () ->
            Paseto.parse(
                publicKey,
                token,
                ValidationPolicy.builder().maxTokenLength(token.length() - 1).build()),
        "POLICY_TOKEN_TOO_LONG",
        PolicyStage.LENGTH);
    assertViolation(
        () -> Paseto.parse(publicKey, token, ValidationPolicy.builder().expectFooter("no").build()),
        "POLICY_FOOTER_MISMATCH",
        PolicyStage.FOOTER);

    // authentication failure is not a policy rejection
    var otherGenerator = KeyPairGenerator.getInstance("RSA");
    otherGenerator.initialize(2048);
    RSAPublicKey wrongKey = (RSAPublicKey) otherGenerator.generateKeyPair().getPublic();
    assertThrows(
        SignatureException.class,
        () -> Paseto.parse(wrongKey, token, ValidationPolicy.permissive()));
  }
}
