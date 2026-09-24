/*
 * SPDX-FileCopyrightText: Copyright © 2026 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.version2;

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

import java.security.SignatureException;
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
  private static final String NONCE = "45742c976d684ff84ebdc0de59809a97cda2f64c84fda19b";
  private static final String PAYLOAD =
      "{\"data\":\"this is a signed message\",\"exp\":\"2019-01-01T00:00:00+00:00\"}";
  // Official v2 test vector (2-E-4)
  private static final String TOKEN =
      "v2.local.5K4SCXNhItIhyNuVIZcwrdtaDKiyF81-eWHScuE0idiVqCo72bbjo07W05mqQkhLZdVbxEa5I_u5sgVk1QLkcWEcOSlLHwNpCkvmGGlbCdNExn6Qclw3qTKIIl5-O5xRBN076fSDPo5xUCPpBA";

  private static SecretKey key() {
    return SecretKey.fromHexString(KEY);
  }

  @Test
  void legacyApiRemainsCompatible() {
    assertEquals(PAYLOAD, Paseto.decrypt(key(), TOKEN, ""));
    assertEquals(PAYLOAD, Paseto.decrypt(key(), TOKEN, ValidationPolicy.permissive()));
  }

  @Test
  void versionMustBeAllowed() {
    ValidationPolicy policy = ValidationPolicy.builder().allowVersions(V1).build();
    PolicyViolationException exception =
        assertViolation(
            () -> Paseto.decrypt(key(), TOKEN, policy),
            "POLICY_VERSION_NOT_ALLOWED",
            PolicyStage.VERSION);
    assertSafeMessage(exception, TOKEN, PAYLOAD, KEY);
    assertDoesNotThrow(
        () -> Paseto.decrypt(key(), TOKEN, ValidationPolicy.builder().allowVersions(V2).build()));
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
  void payloadLengthBoundaryIsEnforced() {
    String payloadSegment = TOKEN.split("\\.")[2];
    assertDoesNotThrow(
        () ->
            Paseto.decrypt(
                key(),
                TOKEN,
                ValidationPolicy.builder().maxPayloadLength(payloadSegment.length()).build()));
    assertViolation(
        () ->
            Paseto.decrypt(
                key(),
                TOKEN,
                ValidationPolicy.builder().maxPayloadLength(payloadSegment.length() - 1).build()),
        "POLICY_PAYLOAD_TOO_LONG",
        PolicyStage.LENGTH);
  }

  @Test
  void footerExpectationsAreEnforced() {
    String token = PasetoLocal.encrypt(key(), hexToBytes(NONCE), PAYLOAD, "footer-value");
    assertDoesNotThrow(
        () ->
            Paseto.decrypt(
                key(), token, ValidationPolicy.builder().expectFooter("footer-value").build()));
    assertViolation(
        () ->
            Paseto.decrypt(
                key(), token, ValidationPolicy.builder().expectFooter("other").build()),
        "POLICY_FOOTER_MISMATCH",
        PolicyStage.FOOTER);
    assertViolation(
        () -> Paseto.decrypt(key(), token, ValidationPolicy.builder().requireNoFooter().build()),
        "POLICY_FOOTER_NOT_ALLOWED",
        PolicyStage.FOOTER);
    assertDoesNotThrow(
        () -> Paseto.decrypt(key(), TOKEN, ValidationPolicy.builder().requireNoFooter().build()));
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
  void wrongKeyIsAnAuthenticationFailureNotAPolicyRejection() {
    PasetoException exception =
        assertThrows(
            PasetoException.class,
            () ->
                Paseto.decrypt(
                    SecretKey.fromHexString(WRONG_KEY), TOKEN, ValidationPolicy.permissive()));
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
  void publicTokensFollowTheSameStages() throws SignatureException {
    String signedMessage =
        "v2.public.RnJhbmsgRGVuaXMgcm9ja3O7MPuu90WKNyvBUUhAGFmi4PiPOr2bN2ytUSU-QWlj8eNefki2MubssfN1b8figynnY0WusRPwIQ-o0HSZOS0F.Q3VvbiBBbHBpbnVz";
    PublicKey publicKey =
        PublicKey.fromHexString("1eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2");

    // legacy API and permissive policy agree
    assertEquals("Frank Denis rocks", Paseto.parse(publicKey, signedMessage, "Cuon Alpinus"));
    assertEquals(
        "Frank Denis rocks", Paseto.parse(publicKey, signedMessage, ValidationPolicy.permissive()));
    assertEquals(
        "Frank Denis rocks",
        Paseto.parse(
            publicKey,
            signedMessage,
            ValidationPolicy.builder().expectFooter("Cuon Alpinus").build()));

    assertViolation(
        () ->
            Paseto.parse(
                publicKey, signedMessage, ValidationPolicy.builder().allowVersions(V1).build()),
        "POLICY_VERSION_NOT_ALLOWED",
        PolicyStage.VERSION);
    assertViolation(
        () ->
            Paseto.parse(
                publicKey,
                signedMessage,
                ValidationPolicy.builder().allowPurposes(PURPOSE_LOCAL).build()),
        "POLICY_PURPOSE_NOT_ALLOWED",
        PolicyStage.PURPOSE);
    assertViolation(
        () ->
            Paseto.parse(
                publicKey,
                signedMessage,
                ValidationPolicy.builder().maxTokenLength(signedMessage.length() - 1).build()),
        "POLICY_TOKEN_TOO_LONG",
        PolicyStage.LENGTH);
    assertViolation(
        () ->
            Paseto.parse(
                publicKey, signedMessage, ValidationPolicy.builder().expectFooter("no").build()),
        "POLICY_FOOTER_MISMATCH",
        PolicyStage.FOOTER);

    // authentication failure is not a policy rejection
    PublicKey wrongKey =
        PublicKey.fromHexString(
            "2eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2");
    assertThrows(
        SignatureException.class,
        () -> Paseto.parse(wrongKey, signedMessage, ValidationPolicy.permissive()));
  }
}
