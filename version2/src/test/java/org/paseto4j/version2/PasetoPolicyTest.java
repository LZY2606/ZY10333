/*
 * SPDX-FileCopyrightText: Copyright © 2026 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.version2;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.paseto4j.commons.HexToBytes.hexToBytes;

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

  // Official PASETO v2 test vectors
  private static final String KEY =
      "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f";
  private static final String WRONG_KEY =
      "0000000000000000000000000000000000000000000000000000000000000000";
  private static final SecretKey SECRET_KEY = SecretKey.fromHexString(KEY);
  private static final String PAYLOAD =
      "{\"data\":\"this is a secret message\",\"exp\":\"2019-01-01T00:00:00+00:00\"}";
  private static final String TOKEN =
      "v2.local.pvFdDeNtXxknVPsbBCZF6MGedVhPm40SneExdClOxa9HNR8wFv7cu1cB0B4WxDdT6oUc2toyLR6jA6sc-EUM5ll1EkeY47yYk6q8m1RCpqTIzUrIu3B6h232h62DPbIxtjGvNRAwsLK7LcV8oQ";
  private static final String FOOTER =
      "{\"kid\":\"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN\"}";
  private static final String FOOTER_TOKEN =
      "v2.local.pvFdDeNtXxknVPsbBCZF6MGedVhPm40SneExdClOxa9HNR8wFv7cu1cB0B4WxDdT6oUc2toyLR6jA6sc-EUM5ll1EkeY47yYk6q8m1RCpqTIzUrIu3B6h232h62DnMXKdHn_Smp6L_NfaEnZ-A.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9";

  private static final String SIGN_SECRET =
      "b4cbfb43df4ce210727d953e4a713307fa19bb7d9f85041438d9e11b942a37741eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2";
  private static final String SIGN_PUBLIC =
      "1eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2";
  private static final String SIGNED_TOKEN =
      "v2.public.RnJhbmsgRGVuaXMgcm9ja3NBeHgns4TLYAoyD1OPHww0qfxHdTdzkKcyaE4_fBF2WuY1JNRW_yI8qRhZmNTaO19zRhki6YWRaKKlCZNCNrQM";
  private static final String SIGNED_PAYLOAD = "Frank Denis rocks";

  @Test
  void permissivePolicyMatchesLegacyApi() {
    assertEquals(
        Paseto.decrypt(SECRET_KEY, TOKEN, ""),
        Paseto.decrypt(SECRET_KEY, TOKEN, "", ValidationPolicy.permissive()));
    assertEquals(
        PAYLOAD, Paseto.decrypt(SECRET_KEY, FOOTER_TOKEN, FOOTER, ValidationPolicy.permissive()));
  }

  @Test
  void rejectsDisallowedVersionAndPurpose() {
    ValidationException version =
        assertThrows(
            ValidationException.class,
            () ->
                Paseto.decrypt(
                    SECRET_KEY,
                    TOKEN,
                    "",
                    ValidationPolicy.builder().allowVersions(Version.V4).build()));
    assertEquals(FailureCode.VERSION_NOT_ALLOWED, version.code());
    assertEquals(ValidationPhase.STRUCTURE, version.phase());

    ValidationException purpose =
        assertThrows(
            ValidationException.class,
            () ->
                Paseto.decrypt(
                    SECRET_KEY,
                    TOKEN,
                    "",
                    ValidationPolicy.builder().allowPurposes(Purpose.PURPOSE_PUBLIC).build()));
    assertEquals(FailureCode.PURPOSE_NOT_ALLOWED, purpose.code());
    assertEquals(ValidationPhase.STRUCTURE, purpose.phase());
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
    ValidationException e =
        assertThrows(
            ValidationException.class,
            () -> Paseto.decrypt(SECRET_KEY, "v2.local.QR", "", ValidationPolicy.permissive()));
    assertEquals(FailureCode.NON_CANONICAL_ENCODING, e.code());
    assertEquals(ValidationPhase.STRUCTURE, e.phase());
  }

  @Test
  void enforcesPolicyAndCallerFooter() {
    ValidationPolicy matching = ValidationPolicy.builder().expectFooter(FOOTER).build();
    assertEquals(PAYLOAD, Paseto.decrypt(SECRET_KEY, FOOTER_TOKEN, FOOTER, matching));

    ValidationException mismatch =
        assertThrows(
            ValidationException.class,
            () ->
                Paseto.decrypt(
                    SECRET_KEY,
                    FOOTER_TOKEN,
                    FOOTER,
                    ValidationPolicy.builder().expectFooter("other").build()));
    assertEquals(FailureCode.FOOTER_MISMATCH, mismatch.code());
    assertEquals(ValidationPhase.FOOTER, mismatch.phase());

    ValidationException callerMismatch =
        assertThrows(
            ValidationException.class,
            () ->
                Paseto.decrypt(
                    SECRET_KEY, FOOTER_TOKEN, "wrong footer", ValidationPolicy.permissive()));
    assertEquals(FailureCode.FOOTER_MISMATCH, callerMismatch.code());
    assertEquals(ValidationPhase.FOOTER, callerMismatch.phase());
  }

  @Test
  void rejectsImplicitAssertionRequirementOnV2() {
    ValidationException e =
        assertThrows(
            ValidationException.class,
            () ->
                Paseto.decrypt(
                    SECRET_KEY,
                    TOKEN,
                    "",
                    ValidationPolicy.builder().requireImplicitAssertion().build()));
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
  void publicPurposePolicyMatrix() throws Exception {
    PublicKey publicKey = PublicKey.fromBytes(hexToBytes(SIGN_PUBLIC));

    // legacy API still works
    assertEquals(SIGNED_PAYLOAD, Paseto.parse(publicKey, SIGNED_TOKEN, ""));
    // permissive policy matches legacy
    assertEquals(
        SIGNED_PAYLOAD, Paseto.parse(publicKey, SIGNED_TOKEN, "", ValidationPolicy.permissive()));
    // purpose-restricted policy accepts public tokens
    assertEquals(
        SIGNED_PAYLOAD,
        Paseto.parse(
            publicKey,
            SIGNED_TOKEN,
            "",
            ValidationPolicy.builder()
                .allowVersions(Version.V2)
                .allowPurposes(Purpose.PURPOSE_PUBLIC)
                .build()));

    PrivateKey otherPrivate = PrivateKey.fromBytes(new byte[64]);
    byte[] otherPublicBytes = new byte[32];
    System.arraycopy(otherPrivate.toBytes(), 32, otherPublicBytes, 0, 32);
    PublicKey otherPublic = PublicKey.fromBytes(otherPublicBytes);

    ValidationException wrongKey =
        assertThrows(
            ValidationException.class,
            () -> Paseto.parse(otherPublic, SIGNED_TOKEN, "", ValidationPolicy.permissive()));
    assertEquals(FailureCode.AUTHENTICATION_FAILED, wrongKey.code());
    assertEquals(ValidationPhase.AUTHENTICATION, wrongKey.phase());
    assertFalse(wrongKey.getMessage().contains(SIGNED_TOKEN));
    assertFalse(wrongKey.getMessage().contains(SIGNED_PAYLOAD));
  }

  @Test
  void signThenParseWithPolicy() throws Exception {
    PrivateKey privateKey = PrivateKey.fromBytes(hexToBytes(SIGN_SECRET));
    PublicKey publicKey = PublicKey.fromBytes(hexToBytes(SIGN_PUBLIC));

    String signed = Paseto.sign(privateKey, SIGNED_PAYLOAD, FOOTER);
    assertEquals(
        SIGNED_PAYLOAD,
        Paseto.parse(
            publicKey,
            signed,
            FOOTER,
            ValidationPolicy.builder().expectFooter(FOOTER).build()));
  }
}
