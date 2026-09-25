/*
 * SPDX-FileCopyrightText: Copyright © 2026 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.version4;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.io.Reader;
import java.io.StringReader;
import java.security.KeyPairGenerator;
import java.security.interfaces.EdECPrivateKey;
import java.security.interfaces.EdECPublicKey;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.junit.jupiter.api.Test;
import org.paseto4j.commons.FailureCode;
import org.paseto4j.commons.Purpose;
import org.paseto4j.commons.SecretKey;
import org.paseto4j.commons.TestVectors;
import org.paseto4j.commons.TestVectors.TestVector;
import org.paseto4j.commons.ValidationException;
import org.paseto4j.commons.ValidationPhase;
import org.paseto4j.commons.ValidationPolicy;
import org.paseto4j.commons.Version;

class PasetoPolicyTest {

  private static final String WRONG_KEY =
      "0000000000000000000000000000000000000000000000000000000000000000";

  private static TestVector vector(String name) throws IOException {
    return TestVectors.read("test-vectors/v4.json").tests.stream()
        .filter(v -> v.name.equals(name))
        .findFirst()
        .orElseThrow();
  }

  private static EdECPublicKey readPublic(String pem) throws IOException {
    Reader reader = new StringReader(pem);
    Object parsed = new PEMParser(reader).readObject();
    return (EdECPublicKey) new JcaPEMKeyConverter().getPublicKey((SubjectPublicKeyInfo) parsed);
  }

  private static EdECPrivateKey readPrivate(String pem) throws IOException {
    Reader reader = new StringReader(pem);
    Object parsed = new PEMParser(reader).readObject();
    return (EdECPrivateKey) new JcaPEMKeyConverter().getPrivateKey((PrivateKeyInfo) parsed);
  }

  @Test
  void permissivePolicyMatchesLegacyApi() throws IOException {
    TestVector v = vector("4-E-1");
    SecretKey key = SecretKey.fromHexString(v.key);

    assertEquals(
        Paseto.decrypt(key, v.token, v.footer),
        Paseto.decrypt(key, v.token, v.footer, ValidationPolicy.permissive()));
    assertEquals(
        v.payload, Paseto.decrypt(key, v.token, v.footer, "", ValidationPolicy.permissive()));
  }

  @Test
  void rejectsDisallowedVersionAndPurpose() throws IOException {
    TestVector v = vector("4-E-1");
    SecretKey key = SecretKey.fromHexString(v.key);

    ValidationException version =
        assertThrows(
            ValidationException.class,
            () ->
                Paseto.decrypt(
                    key,
                    v.token,
                    v.footer,
                    ValidationPolicy.builder().allowVersions(Version.V3).build()));
    assertEquals(FailureCode.VERSION_NOT_ALLOWED, version.code());
    assertEquals(ValidationPhase.STRUCTURE, version.phase());

    ValidationException purpose =
        assertThrows(
            ValidationException.class,
            () ->
                Paseto.decrypt(
                    key,
                    v.token,
                    v.footer,
                    ValidationPolicy.builder().allowPurposes(Purpose.PURPOSE_PUBLIC).build()));
    assertEquals(FailureCode.PURPOSE_NOT_ALLOWED, purpose.code());
    assertEquals(ValidationPhase.STRUCTURE, purpose.phase());
  }

  @Test
  void enforcesTokenAndSegmentLengths() throws IOException {
    TestVector v = vector("4-E-1");
    SecretKey key = SecretKey.fromHexString(v.key);

    assertEquals(
        v.payload,
        Paseto.decrypt(
            key,
            v.token,
            v.footer,
            ValidationPolicy.builder().maxTokenLength(v.token.length()).build()));

    ValidationException tooLong =
        assertThrows(
            ValidationException.class,
            () ->
                Paseto.decrypt(
                    key,
                    v.token,
                    v.footer,
                    ValidationPolicy.builder().maxTokenLength(v.token.length() - 1).build()));
    assertEquals(FailureCode.TOKEN_TOO_LONG, tooLong.code());
    assertEquals(ValidationPhase.STRUCTURE, tooLong.phase());

    String payloadSegment = v.token.split("\\.")[2];
    ValidationException segmentTooLong =
        assertThrows(
            ValidationException.class,
            () ->
                Paseto.decrypt(
                    key,
                    v.token,
                    v.footer,
                    ValidationPolicy.builder()
                        .maxPayloadLength(payloadSegment.length() - 1)
                        .build()));
    assertEquals(FailureCode.SEGMENT_TOO_LONG, segmentTooLong.code());
    assertEquals(ValidationPhase.STRUCTURE, segmentTooLong.phase());
  }

  @Test
  void rejectsNonCanonicalPayload() throws IOException {
    TestVector v = vector("4-E-1");
    SecretKey key = SecretKey.fromHexString(v.key);

    ValidationException e =
        assertThrows(
            ValidationException.class,
            () -> Paseto.decrypt(key, "v4.local.QR", "", ValidationPolicy.permissive()));
    assertEquals(FailureCode.NON_CANONICAL_ENCODING, e.code());
    assertEquals(ValidationPhase.STRUCTURE, e.phase());
  }

  @Test
  void enforcesFooterAndImplicitAssertion() throws IOException {
    TestVector v = vector("4-E-7");
    SecretKey key = SecretKey.fromHexString(v.key);

    ValidationPolicy matching =
        ValidationPolicy.builder()
            .expectFooter(v.footer)
            .expectImplicitAssertion(v.implicitAssertion)
            .build();
    assertEquals(
        v.payload, Paseto.decrypt(key, v.token, v.footer, v.implicitAssertion, matching));

    ValidationException footerMismatch =
        assertThrows(
            ValidationException.class,
            () ->
                Paseto.decrypt(
                    key,
                    v.token,
                    v.footer,
                    v.implicitAssertion,
                    ValidationPolicy.builder().expectFooter("other").build()));
    assertEquals(FailureCode.FOOTER_MISMATCH, footerMismatch.code());
    assertEquals(ValidationPhase.FOOTER, footerMismatch.phase());

    ValidationException callerFooter =
        assertThrows(
            ValidationException.class,
            () ->
                Paseto.decrypt(
                    key, v.token, "wrong footer", v.implicitAssertion,
                    ValidationPolicy.permissive()));
    assertEquals(FailureCode.FOOTER_MISMATCH, callerFooter.code());
    assertEquals(ValidationPhase.FOOTER, callerFooter.phase());

    ValidationException implicitRequired =
        assertThrows(
            ValidationException.class,
            () ->
                Paseto.decrypt(
                    key,
                    v.token,
                    v.footer,
                    "",
                    ValidationPolicy.builder().requireImplicitAssertion().build()));
    assertEquals(FailureCode.IMPLICIT_ASSERTION_REQUIRED, implicitRequired.code());
    assertEquals(ValidationPhase.IMPLICIT_ASSERTION, implicitRequired.phase());

    ValidationException implicitMismatch =
        assertThrows(
            ValidationException.class,
            () ->
                Paseto.decrypt(
                    key,
                    v.token,
                    v.footer,
                    "other",
                    ValidationPolicy.builder().expectImplicitAssertion("expected").build()));
    assertEquals(FailureCode.IMPLICIT_ASSERTION_MISMATCH, implicitMismatch.code());
    assertEquals(ValidationPhase.IMPLICIT_ASSERTION, implicitMismatch.phase());
  }

  @Test
  void wrongKeyYieldsAuthenticationFailureWithoutSecrets() throws IOException {
    TestVector v = vector("4-E-1");
    SecretKey wrongKey = SecretKey.fromHexString(WRONG_KEY);

    ValidationException e =
        assertThrows(
            ValidationException.class,
            () -> Paseto.decrypt(wrongKey, v.token, v.footer, ValidationPolicy.permissive()));
    assertEquals(FailureCode.AUTHENTICATION_FAILED, e.code());
    assertEquals(ValidationPhase.AUTHENTICATION, e.phase());
    assertFalse(e.getMessage().contains(v.token));
    assertFalse(e.getMessage().contains(WRONG_KEY));
    assertFalse(e.getMessage().contains(v.payload));
  }

  @Test
  void enforcesTemporalClaimsOnBothClockEnds() throws IOException {
    TestVector v = vector("4-E-1");
    SecretKey key = SecretKey.fromHexString(v.key);

    ValidationPolicy beforeExpiry =
        ValidationPolicy.builder()
            .clock(Clock.fixed(Instant.parse("2021-01-01T00:00:00Z"), ZoneOffset.UTC))
            .validateTemporalClaims()
            .build();
    assertEquals(v.payload, Paseto.decrypt(key, v.token, v.footer, beforeExpiry));

    ValidationPolicy afterExpiry =
        ValidationPolicy.builder()
            .clock(Clock.fixed(Instant.parse("2023-01-01T00:00:00Z"), ZoneOffset.UTC))
            .validateTemporalClaims()
            .build();
    ValidationException e =
        assertThrows(
            ValidationException.class, () -> Paseto.decrypt(key, v.token, v.footer, afterExpiry));
    assertEquals(FailureCode.TOKEN_EXPIRED, e.code());
    assertEquals(ValidationPhase.CLAIMS, e.phase());
  }

  @Test
  void publicPurposePolicyMatrix() throws Exception {
    TestVector v = vector("4-S-3");
    EdECPublicKey publicKey = readPublic(v.publicKeyPem);

    // legacy API still works
    assertEquals(v.payload, Paseto.parse(publicKey, v.token, v.footer, v.implicitAssertion));
    // permissive policy matches legacy
    assertEquals(
        v.payload,
        Paseto.parse(
            publicKey, v.token, v.footer, v.implicitAssertion, ValidationPolicy.permissive()));
    // restricted policy accepting the token
    assertEquals(
        v.payload,
        Paseto.parse(
            publicKey,
            v.token,
            v.footer,
            v.implicitAssertion,
            ValidationPolicy.builder()
                .allowVersions(Version.V4)
                .allowPurposes(Purpose.PURPOSE_PUBLIC)
                .expectFooter(v.footer)
                .expectImplicitAssertion(v.implicitAssertion)
                .build()));

    KeyPairGenerator generator = KeyPairGenerator.getInstance("Ed25519");
    EdECPublicKey otherPublic = (EdECPublicKey) generator.generateKeyPair().getPublic();

    ValidationException wrongKey =
        assertThrows(
            ValidationException.class,
            () ->
                Paseto.parse(
                    otherPublic, v.token, v.footer, v.implicitAssertion,
                    ValidationPolicy.permissive()));
    assertEquals(FailureCode.AUTHENTICATION_FAILED, wrongKey.code());
    assertEquals(ValidationPhase.AUTHENTICATION, wrongKey.phase());
    assertFalse(wrongKey.getMessage().contains(v.token));
    assertFalse(wrongKey.getMessage().contains(v.payload));

    ValidationException localOnly =
        assertThrows(
            ValidationException.class,
            () ->
                Paseto.parse(
                    publicKey,
                    v.token,
                    v.footer,
                    v.implicitAssertion,
                    ValidationPolicy.builder().allowPurposes(Purpose.PURPOSE_LOCAL).build()));
    assertEquals(FailureCode.PURPOSE_NOT_ALLOWED, localOnly.code());
    assertEquals(ValidationPhase.STRUCTURE, localOnly.phase());
  }

  @Test
  void signThenParseWithPolicy() throws Exception {
    TestVector v = vector("4-S-1");
    EdECPrivateKey privateKey = readPrivate(v.secretKeyPem);
    EdECPublicKey publicKey = readPublic(v.publicKeyPem);

    String signed = Paseto.sign(privateKey, v.payload, v.footer, v.implicitAssertion);
    assertEquals(
        v.payload,
        Paseto.parse(
            publicKey,
            signed,
            v.footer,
            v.implicitAssertion,
            ValidationPolicy.builder().allowVersions(Version.V4).build()));
  }
}
