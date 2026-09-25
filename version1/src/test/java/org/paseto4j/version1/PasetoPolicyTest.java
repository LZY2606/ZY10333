/*
 * SPDX-FileCopyrightText: Copyright © 2026 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.version1;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.paseto4j.commons.HexToBytes.hexToBytes;
import static org.paseto4j.version1.CryptoFunctions.convertBytesToRSAPrivateKey;
import static org.paseto4j.version1.CryptoFunctions.convertBytesToRSAPublicKey;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import org.junit.jupiter.api.Test;
import org.paseto4j.commons.FailureCode;
import org.paseto4j.commons.Purpose;
import org.paseto4j.commons.SecretKey;
import org.paseto4j.commons.ValidationException;
import org.paseto4j.commons.ValidationPhase;
import org.paseto4j.commons.ValidationPolicy;
import org.paseto4j.commons.Version;

class PasetoPolicyTest {

  // Official PASETO v1 test vectors
  private static final String KEY =
      "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f";
  private static final String WRONG_KEY =
      "0000000000000000000000000000000000000000000000000000000000000000";
  private static final SecretKey SECRET_KEY = SecretKey.fromHexString(KEY);
  private static final String PAYLOAD =
      "{\"data\":\"this is a secret message\",\"exp\":\"2019-01-01T00:00:00+00:00\"}";
  private static final String TOKEN =
      "v1.local.w_NOpjgte4bX-2i1JAiTQzHoGUVOgc2yqKqsnYGmaPaCu_KWUkRGlCRnOvZZxeH4HTykY7AE_jkzSXAYBkQ1QnwvKS16uTXNfnmp8IRknY76I2m3S5qsM8klxWQQKFDuQHl8xXV0MwAoeFh9X6vbwIqrLlof3s4PMjRDwKsxYzkMr1RvfDI8emoPoW83q4Q60_xpHaw";
  private static final String FOOTER =
      "{\"kid\":\"UbkK8Y6iv4GZhFp6Tx3IWLWLfNXSEvJcdT3zdR65YZxo\"}";
  private static final String FOOTER_TOKEN =
      "v1.local.IddlRQmpk6ojcD10z1EYdLexXvYiadtY0MrYQaRnq3dnqKIWcbbpOcgXdMIkm3_3gksirTj81bvWrWkQwcUHilt-tQo7LZK8I6HCK1V78B9YeEqGNeeWXOyWWHoJQIe0d5nTdvcT2vnER6NrJ7xIowvFba6J4qMlFhBnYSxHEq9v9NlzcKsz1zscdjcAiXnEuCHyRSc.eyJraWQiOiJVYmtLOFk2aXY0R1poRnA2VHgzSVdMV0xmTlhTRXZKY2RUM3pkUjY1WVp4byJ9";

  @Test
  void permissivePolicyMatchesLegacyApi() {
    assertEquals(
        Paseto.decrypt(SECRET_KEY, TOKEN, ""),
        Paseto.decrypt(SECRET_KEY, TOKEN, "", ValidationPolicy.permissive()));
    assertEquals(
        PAYLOAD, Paseto.decrypt(SECRET_KEY, FOOTER_TOKEN, FOOTER, ValidationPolicy.permissive()));
  }

  @Test
  void rejectsDisallowedVersion() {
    ValidationPolicy policy = ValidationPolicy.builder().allowVersions(Version.V2).build();

    ValidationException e =
        assertThrows(
            ValidationException.class, () -> Paseto.decrypt(SECRET_KEY, TOKEN, "", policy));
    assertEquals(FailureCode.VERSION_NOT_ALLOWED, e.code());
    assertEquals(ValidationPhase.STRUCTURE, e.phase());
  }

  @Test
  void rejectsDisallowedPurpose() {
    ValidationPolicy policy =
        ValidationPolicy.builder().allowPurposes(Purpose.PURPOSE_PUBLIC).build();

    ValidationException e =
        assertThrows(
            ValidationException.class, () -> Paseto.decrypt(SECRET_KEY, TOKEN, "", policy));
    assertEquals(FailureCode.PURPOSE_NOT_ALLOWED, e.code());
    assertEquals(ValidationPhase.STRUCTURE, e.phase());
  }

  @Test
  void enforcesTokenAndSegmentLengths() {
    assertEquals(
        PAYLOAD,
        Paseto.decrypt(
            SECRET_KEY,
            TOKEN,
            "",
            ValidationPolicy.builder().maxTokenLength(TOKEN.length()).build()));

    ValidationException tooLong =
        assertThrows(
            ValidationException.class,
            () ->
                Paseto.decrypt(
                    SECRET_KEY,
                    TOKEN,
                    "",
                    ValidationPolicy.builder().maxTokenLength(TOKEN.length() - 1).build()));
    assertEquals(FailureCode.TOKEN_TOO_LONG, tooLong.code());
    assertEquals(ValidationPhase.STRUCTURE, tooLong.phase());

    String payloadSegment = TOKEN.split("\\.")[2];
    ValidationException segmentTooLong =
        assertThrows(
            ValidationException.class,
            () ->
                Paseto.decrypt(
                    SECRET_KEY,
                    TOKEN,
                    "",
                    ValidationPolicy.builder()
                        .maxPayloadLength(payloadSegment.length() - 1)
                        .build()));
    assertEquals(FailureCode.SEGMENT_TOO_LONG, segmentTooLong.code());
    assertEquals(ValidationPhase.STRUCTURE, segmentTooLong.phase());
  }

  @Test
  void rejectsNonCanonicalPayload() {
    String token = "v1.local.QR";

    ValidationException e =
        assertThrows(
            ValidationException.class,
            () -> Paseto.decrypt(SECRET_KEY, token, "", ValidationPolicy.permissive()));
    assertEquals(FailureCode.NON_CANONICAL_ENCODING, e.code());
    assertEquals(ValidationPhase.STRUCTURE, e.phase());
  }

  @Test
  void enforcesPolicyFooter() {
    ValidationPolicy matching = ValidationPolicy.builder().expectFooter(FOOTER).build();
    assertEquals(PAYLOAD, Paseto.decrypt(SECRET_KEY, FOOTER_TOKEN, FOOTER, matching));

    ValidationPolicy mismatching = ValidationPolicy.builder().expectFooter("other").build();
    ValidationException e =
        assertThrows(
            ValidationException.class,
            () -> Paseto.decrypt(SECRET_KEY, FOOTER_TOKEN, FOOTER, mismatching));
    assertEquals(FailureCode.FOOTER_MISMATCH, e.code());
    assertEquals(ValidationPhase.FOOTER, e.phase());

    ValidationPolicy rejecting =
        ValidationPolicy.builder().footerPredicate(f -> f.isEmpty()).build();
    ValidationException rejected =
        assertThrows(
            ValidationException.class,
            () -> Paseto.decrypt(SECRET_KEY, FOOTER_TOKEN, FOOTER, rejecting));
    assertEquals(FailureCode.FOOTER_REJECTED, rejected.code());
    assertEquals(ValidationPhase.FOOTER, rejected.phase());
  }

  @Test
  void rejectsMismatchingCallerFooter() {
    ValidationException e =
        assertThrows(
            ValidationException.class,
            () ->
                Paseto.decrypt(
                    SECRET_KEY, FOOTER_TOKEN, "wrong footer", ValidationPolicy.permissive()));
    assertEquals(FailureCode.FOOTER_MISMATCH, e.code());
    assertEquals(ValidationPhase.FOOTER, e.phase());
  }

  @Test
  void rejectsImplicitAssertionRequirementOnV1() {
    ValidationPolicy policy = ValidationPolicy.builder().requireImplicitAssertion().build();

    ValidationException e =
        assertThrows(
            ValidationException.class, () -> Paseto.decrypt(SECRET_KEY, TOKEN, "", policy));
    assertEquals(FailureCode.IMPLICIT_ASSERTION_REQUIRED, e.code());
    assertEquals(ValidationPhase.IMPLICIT_ASSERTION, e.phase());
  }

  @Test
  void wrongKeyYieldsAuthenticationFailureWithoutSecrets() {
    ValidationException e =
        assertThrows(
            ValidationException.class,
            () ->
                Paseto.decrypt(
                    SecretKey.fromHexString(WRONG_KEY),
                    TOKEN,
                    "",
                    ValidationPolicy.permissive()));
    assertEquals(FailureCode.AUTHENTICATION_FAILED, e.code());
    assertEquals(ValidationPhase.AUTHENTICATION, e.phase());
    assertFalse(e.getMessage().contains(TOKEN));
    assertFalse(e.getMessage().contains(WRONG_KEY));
    assertFalse(e.getMessage().contains(PAYLOAD));
  }

  @Test
  void enforcesTemporalClaimsOnBothClockEnds() {
    ValidationPolicy beforeExpiry =
        ValidationPolicy.builder()
            .clock(Clock.fixed(Instant.parse("2018-01-01T00:00:00Z"), ZoneOffset.UTC))
            .validateTemporalClaims()
            .build();
    assertEquals(PAYLOAD, Paseto.decrypt(SECRET_KEY, TOKEN, "", beforeExpiry));

    ValidationPolicy afterExpiry =
        ValidationPolicy.builder()
            .clock(Clock.fixed(Instant.parse("2020-01-01T00:00:00Z"), ZoneOffset.UTC))
            .validateTemporalClaims()
            .build();
    ValidationException e =
        assertThrows(
            ValidationException.class, () -> Paseto.decrypt(SECRET_KEY, TOKEN, "", afterExpiry));
    assertEquals(FailureCode.TOKEN_EXPIRED, e.code());
    assertEquals(ValidationPhase.CLAIMS, e.phase());
  }

  @Test
  void enforcesClaimRestrictions() {
    String token =
        Paseto.encrypt(
            SECRET_KEY,
            "{\"data\":\"x\",\"iss\":\"paseto4j\",\"nbf\":\"2030-01-01T00:00:00+00:00\"}",
            "");

    ValidationPolicy issuerPolicy = ValidationPolicy.builder().expectIssuer("paseto4j").build();
    assertEquals(
        Paseto.decrypt(SECRET_KEY, token, ""), Paseto.decrypt(SECRET_KEY, token, "", issuerPolicy));

    ValidationException issuer =
        assertThrows(
            ValidationException.class,
            () ->
                Paseto.decrypt(
                    SECRET_KEY,
                    token,
                    "",
                    ValidationPolicy.builder().expectIssuer("other").build()));
    assertEquals(FailureCode.UNEXPECTED_ISSUER, issuer.code());
    assertEquals(ValidationPhase.CLAIMS, issuer.phase());

    ValidationException missingClaim =
        assertThrows(
            ValidationException.class,
            () ->
                Paseto.decrypt(
                    SECRET_KEY,
                    token,
                    "",
                    ValidationPolicy.builder().requireClaims("kid").build()));
    assertEquals(FailureCode.MISSING_CLAIM, missingClaim.code());
    assertEquals(ValidationPhase.CLAIMS, missingClaim.phase());

    ValidationException notYetValid =
        assertThrows(
            ValidationException.class,
            () ->
                Paseto.decrypt(
                    SECRET_KEY,
                    token,
                    "",
                    ValidationPolicy.builder()
                        .clock(Clock.fixed(Instant.parse("2024-01-01T00:00:00Z"), ZoneOffset.UTC))
                        .validateTemporalClaims()
                        .build()));
    assertEquals(FailureCode.TOKEN_NOT_YET_VALID, notYetValid.code());
    assertEquals(ValidationPhase.CLAIMS, notYetValid.phase());
  }

  @Test
  void publicPurposePolicyMatrix() throws Exception {
    KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
    generator.initialize(2048);
    KeyPair keyPair = generator.generateKeyPair();
    KeyPair otherKeyPair = generator.generateKeyPair();

    String signed =
        Paseto.sign((RSAPrivateKey) keyPair.getPrivate(), PAYLOAD, FOOTER);

    // legacy API still works
    assertEquals(
        PAYLOAD, Paseto.parse((RSAPublicKey) keyPair.getPublic(), signed, FOOTER));
    // permissive policy matches legacy
    assertEquals(
        PAYLOAD,
        Paseto.parse(
            (RSAPublicKey) keyPair.getPublic(), signed, FOOTER, ValidationPolicy.permissive()));
    // purpose-restricted policy accepts public tokens
    assertEquals(
        PAYLOAD,
        Paseto.parse(
            (RSAPublicKey) keyPair.getPublic(),
            signed,
            FOOTER,
            ValidationPolicy.builder()
                .allowVersions(Version.V1)
                .allowPurposes(Purpose.PURPOSE_PUBLIC)
                .expectFooter(FOOTER)
                .build()));

    ValidationException wrongKey =
        assertThrows(
            ValidationException.class,
            () ->
                Paseto.parse(
                    (RSAPublicKey) otherKeyPair.getPublic(),
                    signed,
                    FOOTER,
                    ValidationPolicy.permissive()));
    assertEquals(FailureCode.AUTHENTICATION_FAILED, wrongKey.code());
    assertEquals(ValidationPhase.AUTHENTICATION, wrongKey.phase());
    assertFalse(wrongKey.getMessage().contains(signed));
    assertFalse(wrongKey.getMessage().contains(PAYLOAD));

    ValidationException localOnly =
        assertThrows(
            ValidationException.class,
            () ->
                Paseto.parse(
                    (RSAPublicKey) keyPair.getPublic(),
                    signed,
                    FOOTER,
                    ValidationPolicy.builder().allowPurposes(Purpose.PURPOSE_LOCAL).build()));
    assertEquals(FailureCode.PURPOSE_NOT_ALLOWED, localOnly.code());
    assertEquals(ValidationPhase.STRUCTURE, localOnly.phase());
  }

  @Test
  void publicPurposeWithOfficialVectorKey() throws Exception {
    String payload = "{\"data\":\"this is a signed message\",\"exp\":\"2019-01-01T00:00:00+00:00\"}";
    String signed =
        Paseto.sign(
            convertBytesToRSAPrivateKey(hexToBytes(PasetoPublicTest.PRIVATE_KEY)), payload, "");
    String parsed =
        Paseto.parse(
            convertBytesToRSAPublicKey(hexToBytes(PUBLIC_KEY)),
            signed,
            "",
            ValidationPolicy.builder().allowVersions(Version.V1).build());
    assertEquals(payload, parsed);
  }

  // Official v1 public test vector key (from PasetoPublicTest vectors)
  private static final String PUBLIC_KEY =
      "30820122300d06092a864886f70d01010105000382010f003082010a0282010100c9a4e04ede77a61de9e461e0c28196c33e61"
          + "45f597490034f0d08ec1ed0512000b5a8b3d1828cd14277bdb79c21f106d375a9def831287fb8df3c24f21bc312a1783"
          + "a78931a3860c379b6b3da1747bd1ba063d4dd361e76a7c452d6fa098b6e060efd26587d617f33cc8b05cbb96353add19"
          + "c430c35d2f702104ed044d277b761bc606490194d4e57ab24350f17736320b9945eb205a479510b426139d7000a5546e"
          + "508d9277a2f5136be5f5b481ba66792293719119c0c08323793241ff400810b874984e6fc1d8a13826dd57a6a553284a"
          + "0b5fb5c3f156e8759ca7f246d64282f033c889d67bf016eabfd605ce401b3678b979204eb17541286efc66c73ca30203"
          + "010001";
}
