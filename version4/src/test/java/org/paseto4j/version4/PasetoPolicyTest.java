/*
 * SPDX-FileCopyrightText: Copyright © 2026 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.version4;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.paseto4j.commons.PolicyAssertions.assertSafeMessage;
import static org.paseto4j.commons.PolicyAssertions.assertViolation;
import static org.paseto4j.commons.Purpose.PURPOSE_LOCAL;
import static org.paseto4j.commons.Purpose.PURPOSE_PUBLIC;
import static org.paseto4j.commons.Version.V3;
import static org.paseto4j.commons.Version.V4;

import java.io.IOException;
import java.io.StringReader;
import java.security.Security;
import java.security.SignatureException;
import java.security.interfaces.EdECPublicKey;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.junit.jupiter.api.Test;
import org.paseto4j.commons.HexToBytes;
import org.paseto4j.commons.PolicyStage;
import org.paseto4j.commons.PolicyViolationException;
import org.paseto4j.commons.Purpose;
import org.paseto4j.commons.SecretKey;
import org.paseto4j.commons.TestVectors;
import org.paseto4j.commons.TestVectors.TestVector;
import org.paseto4j.commons.ValidationPolicy;

class PasetoPolicyTest {

  static {
    Security.addProvider(new BouncyCastleProvider());
  }

  private static TestVector vector(String name) throws IOException {
    return TestVectors.read("test-vectors/v4.json").tests.stream()
        .filter(t -> t.name.equals(name))
        .findFirst()
        .orElseThrow();
  }

  @Test
  void legacyApiRemainsCompatible() throws IOException {
    TestVector vector = vector("4-E-7");
    SecretKey key = SecretKey.fromHexString(vector.key);
    assertEquals(
        vector.payload, Paseto.decrypt(key, vector.token, vector.footer, vector.implicitAssertion));
    assertEquals(
        vector.payload,
        Paseto.decrypt(key, vector.token, ValidationPolicy.permissive(), vector.implicitAssertion));
    assertEquals(
        vector.payload,
        Paseto.decrypt(
            key, vector.token, ValidationPolicy.legacy(vector.footer), vector.implicitAssertion));
  }

  @Test
  void versionAndPurposeMustBeAllowed() throws IOException {
    TestVector vector = vector("4-E-1");
    SecretKey key = SecretKey.fromHexString(vector.key);
    PolicyViolationException exception =
        assertViolation(
            () ->
                Paseto.decrypt(
                    key, vector.token, ValidationPolicy.builder().allowVersions(V3).build()),
            "POLICY_VERSION_NOT_ALLOWED",
            PolicyStage.VERSION);
    assertSafeMessage(exception, vector.token, vector.payload, vector.key);
    assertViolation(
        () ->
            Paseto.decrypt(
                key,
                vector.token,
                ValidationPolicy.builder().allowPurposes(PURPOSE_PUBLIC).build()),
        "POLICY_PURPOSE_NOT_ALLOWED",
        PolicyStage.PURPOSE);
    assertDoesNotThrow(
        () ->
            Paseto.decrypt(
                key,
                vector.token,
                ValidationPolicy.builder()
                    .allowVersions(V4)
                    .allowPurposes(PURPOSE_LOCAL)
                    .build()));
  }

  @Test
  void lengthBoundariesAreEnforced() throws IOException {
    TestVector vector = vector("4-E-5");
    SecretKey key = SecretKey.fromHexString(vector.key);
    String payloadSegment = vector.token.split("\\.")[2];
    String footerSegment = vector.token.split("\\.")[3];
    assertDoesNotThrow(
        () ->
            Paseto.decrypt(
                key,
                vector.token,
                ValidationPolicy.builder()
                    .maxTokenLength(vector.token.length())
                    .maxPayloadLength(payloadSegment.length())
                    .maxFooterLength(footerSegment.length())
                    .build()));
    assertViolation(
        () ->
            Paseto.decrypt(
                key,
                vector.token,
                ValidationPolicy.builder().maxTokenLength(vector.token.length() - 1).build()),
        "POLICY_TOKEN_TOO_LONG",
        PolicyStage.LENGTH);
    assertViolation(
        () ->
            Paseto.decrypt(
                key,
                vector.token,
                ValidationPolicy.builder().maxPayloadLength(payloadSegment.length() - 1).build()),
        "POLICY_PAYLOAD_TOO_LONG",
        PolicyStage.LENGTH);
    assertViolation(
        () ->
            Paseto.decrypt(
                key,
                vector.token,
                ValidationPolicy.builder().maxFooterLength(footerSegment.length() - 1).build()),
        "POLICY_FOOTER_TOO_LONG",
        PolicyStage.LENGTH);
  }

  @Test
  void footerExpectationsAreEnforced() throws IOException {
    TestVector vector = vector("4-E-5");
    SecretKey key = SecretKey.fromHexString(vector.key);
    assertDoesNotThrow(
        () ->
            Paseto.decrypt(
                key, vector.token, ValidationPolicy.builder().expectFooter(vector.footer).build()));
    assertViolation(
        () ->
            Paseto.decrypt(
                key, vector.token, ValidationPolicy.builder().expectFooter("other").build()),
        "POLICY_FOOTER_MISMATCH",
        PolicyStage.FOOTER);
    assertViolation(
        () ->
            Paseto.decrypt(
                key, vector.token, ValidationPolicy.builder().requireNoFooter().build()),
        "POLICY_FOOTER_NOT_ALLOWED",
        PolicyStage.FOOTER);
  }

  @Test
  void implicitAssertionIsEnforced() throws IOException {
    TestVector vector = vector("4-E-7");
    SecretKey key = SecretKey.fromHexString(vector.key);
    ValidationPolicy requiring = ValidationPolicy.builder().requireImplicitAssertion().build();

    // missing implicit assertion is a policy rejection
    assertViolation(
        () -> Paseto.decrypt(key, vector.token, requiring),
        "POLICY_IMPLICIT_ASSERTION_REQUIRED",
        PolicyStage.IMPLICIT_ASSERTION);

    // correct implicit assertion passes
    assertEquals(
        vector.payload, Paseto.decrypt(key, vector.token, requiring, vector.implicitAssertion));

    // wrong implicit assertion is an authentication failure, not a policy rejection
    RuntimeException exception =
        assertThrows(
            RuntimeException.class,
            () -> Paseto.decrypt(key, vector.token, requiring, "{\"test-vector\":\"wrong\"}"));
    assertFalse(exception instanceof PolicyViolationException);
  }

  @Test
  void nonCanonicalEncodingIsRejectedBeforeCrypto() throws IOException {
    TestVector vector = vector("4-E-1");
    SecretKey key = SecretKey.fromHexString(vector.key);
    String tampered = vector.token + "=";
    PolicyViolationException exception =
        assertViolation(
            () -> Paseto.decrypt(key, tampered, ValidationPolicy.permissive()),
            "TOKEN_NON_CANONICAL_ENCODING",
            PolicyStage.ENCODING);
    assertSafeMessage(exception, tampered, vector.payload, vector.key);
  }

  @Test
  void wrongKeyIsAnAuthenticationFailureNotAPolicyRejection() throws IOException {
    TestVector vector = vector("4-E-1");
    SecretKey wrongKey =
        SecretKey.fromHexString(vector.key.substring(0, vector.key.length() - 2) + "00");
    RuntimeException exception =
        assertThrows(
            RuntimeException.class,
            () -> Paseto.decrypt(wrongKey, vector.token, ValidationPolicy.permissive()));
    assertFalse(exception instanceof PolicyViolationException);
  }

  @Test
  void expiredAndFutureTokensAreRejectedByTheClock() throws IOException {
    TestVector vector = vector("4-E-1");
    SecretKey key = SecretKey.fromHexString(vector.key);
    String token =
        PasetoLocal.encrypt(
            key,
            HexToBytes.hexToBytes(vector.nonce),
            "{\"data\":\"test\",\"exp\":\"2026-01-01T00:00:00+00:00\",\"nbf\":\"2025-01-01T00:00:00+00:00\"}",
            "",
            "");

    Clock valid = Clock.fixed(Instant.parse("2025-06-01T00:00:00Z"), ZoneOffset.UTC);
    assertDoesNotThrow(
        () ->
            Paseto.decrypt(
                key, token, ValidationPolicy.builder().clock(valid, Duration.ofMinutes(1)).build()));

    Clock afterExpiry = Clock.fixed(Instant.parse("2026-01-01T00:02:00Z"), ZoneOffset.UTC);
    PolicyViolationException expired =
        assertViolation(
            () ->
                Paseto.decrypt(
                    key,
                    token,
                    ValidationPolicy.builder().clock(afterExpiry, Duration.ofMinutes(1)).build()),
            "POLICY_TOKEN_EXPIRED",
            PolicyStage.CLAIMS);
    assertSafeMessage(expired, token, vector.key);

    Clock beforeNotBefore = Clock.fixed(Instant.parse("2024-12-31T23:58:00Z"), ZoneOffset.UTC);
    assertViolation(
        () ->
            Paseto.decrypt(
                key,
                token,
                ValidationPolicy.builder().clock(beforeNotBefore, Duration.ofMinutes(1)).build()),
        "POLICY_TOKEN_NOT_YET_VALID",
        PolicyStage.CLAIMS);
  }

  @Test
  void publicTokensFollowTheSameStages() throws IOException, SignatureException {
    TestVector vector = vector("4-S-3");
    EdECPublicKey publicKey = publicKey(vector.publicKeyPem);

    // legacy API and permissive policy agree
    assertEquals(
        vector.payload, Paseto.parse(publicKey, vector.token, vector.footer, vector.implicitAssertion));
    assertEquals(
        vector.payload,
        Paseto.parse(publicKey, vector.token, ValidationPolicy.permissive(), vector.implicitAssertion));
    assertEquals(
        vector.payload,
        Paseto.parse(
            publicKey,
            vector.token,
            ValidationPolicy.builder()
                .requireImplicitAssertion()
                .expectFooter(vector.footer)
                .build(),
            vector.implicitAssertion));

    assertViolation(
        () ->
            Paseto.parse(
                publicKey,
                vector.token,
                ValidationPolicy.builder().allowVersions(V3).build(),
                vector.implicitAssertion),
        "POLICY_VERSION_NOT_ALLOWED",
        PolicyStage.VERSION);
    assertViolation(
        () ->
            Paseto.parse(
                publicKey,
                vector.token,
                ValidationPolicy.builder().allowPurposes(PURPOSE_LOCAL).build(),
                vector.implicitAssertion),
        "POLICY_PURPOSE_NOT_ALLOWED",
        PolicyStage.PURPOSE);
    assertViolation(
        () ->
            Paseto.parse(
                publicKey,
                vector.token,
                ValidationPolicy.builder().expectFooter("no").build(),
                vector.implicitAssertion),
        "POLICY_FOOTER_MISMATCH",
        PolicyStage.FOOTER);

    // authentication failure is not a policy rejection
    assertThrows(
        SignatureException.class,
        () ->
            Paseto.parse(
                publicKey,
                vector.token,
                ValidationPolicy.permissive(),
                "{\"test-vector\":\"wrong\"}"));
  }

  private static EdECPublicKey publicKey(String pem) throws IOException {
    try (var reader = new StringReader(pem)) {
      Object parsed = new PEMParser(reader).readObject();
      return (EdECPublicKey) new JcaPEMKeyConverter().getPublicKey((SubjectPublicKeyInfo) parsed);
    }
  }
}
