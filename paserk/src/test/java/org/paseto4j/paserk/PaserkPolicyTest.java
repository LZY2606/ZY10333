/*
 * SPDX-FileCopyrightText: Copyright © 2026 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.paserk;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import org.junit.jupiter.api.Test;
import org.paseto4j.commons.FailureCode;
import org.paseto4j.commons.HexToBytes;
import org.paseto4j.commons.TestVectors;
import org.paseto4j.commons.TestVectors.TestVector;
import org.paseto4j.commons.ValidationException;
import org.paseto4j.commons.ValidationPhase;
import org.paseto4j.commons.ValidationPolicy;
import org.paseto4j.commons.Version;
import org.paseto4j.paserk.types.Local;
import org.paseto4j.paserk.types.SecretType;

class PaserkPolicyTest {

  private static TestVector k4Local() throws IOException {
    return TestVectors.paserk("test-vectors/k4.local.json").stream()
        .filter(v -> !v.expectFail && v.key != null)
        .findFirst()
        .orElseThrow();
  }

  @Test
  void permissivePolicyMatchesLegacyDecode() throws IOException {
    TestVector v = k4Local();
    Local local = new Local(Version.V4);

    assertArrayEquals(local.decode(v.paserk), local.decode(v.paserk, ValidationPolicy.permissive()));
    assertArrayEquals(
        HexToBytes.hexToBytes(v.key), local.decode(v.paserk, ValidationPolicy.permissive()));
  }

  @Test
  void rejectsDisallowedVersion() throws IOException {
    TestVector v = k4Local();
    Local local = new Local(Version.V4);

    ValidationException e =
        assertThrows(
            ValidationException.class,
            () ->
                local.decode(
                    v.paserk, ValidationPolicy.builder().allowVersions(Version.V3).build()));
    assertEquals(FailureCode.VERSION_NOT_ALLOWED, e.code());
    assertEquals(ValidationPhase.STRUCTURE, e.phase());
  }

  @Test
  void enforcesTokenAndSegmentLengths() throws IOException {
    TestVector v = k4Local();
    Local local = new Local(Version.V4);

    local.decode(
        v.paserk, ValidationPolicy.builder().maxTokenLength(v.paserk.length()).build());

    ValidationException tooLong =
        assertThrows(
            ValidationException.class,
            () ->
                local.decode(
                    v.paserk,
                    ValidationPolicy.builder().maxTokenLength(v.paserk.length() - 1).build()));
    assertEquals(FailureCode.TOKEN_TOO_LONG, tooLong.code());
    assertEquals(ValidationPhase.STRUCTURE, tooLong.phase());

    String payloadSegment = v.paserk.split("\\.")[2];
    ValidationException segmentTooLong =
        assertThrows(
            ValidationException.class,
            () ->
                local.decode(
                    v.paserk,
                    ValidationPolicy.builder()
                        .maxPayloadLength(payloadSegment.length() - 1)
                        .build()));
    assertEquals(FailureCode.SEGMENT_TOO_LONG, segmentTooLong.code());
    assertEquals(ValidationPhase.STRUCTURE, segmentTooLong.phase());
  }

  @Test
  void rejectsMalformedPaserk() {
    Local local = new Local(Version.V4);

    ValidationException twoParts =
        assertThrows(
            ValidationException.class,
            () -> local.decode("k4.local", ValidationPolicy.permissive()));
    assertEquals(FailureCode.MALFORMED_TOKEN, twoParts.code());
    assertEquals(ValidationPhase.STRUCTURE, twoParts.phase());

    ValidationException unknownVersion =
        assertThrows(
            ValidationException.class,
            () -> local.decode("x4.local.cGF5bG9hZA", ValidationPolicy.permissive()));
    assertEquals(FailureCode.MALFORMED_TOKEN, unknownVersion.code());

    ValidationException emptyPayload =
        assertThrows(
            ValidationException.class,
            () -> local.decode("k4.local.", ValidationPolicy.permissive()));
    assertEquals(FailureCode.MALFORMED_TOKEN, emptyPayload.code());
  }

  @Test
  void rejectsNonCanonicalPayload() {
    Local local = new Local(Version.V4);

    // "QR" decodes to the same byte as canonical "QQ": a lenient decoder would accept it
    ValidationException nonCanonical =
        assertThrows(
            ValidationException.class,
            () -> local.decode("k4.local.QR", ValidationPolicy.permissive()));
    assertEquals(FailureCode.NON_CANONICAL_ENCODING, nonCanonical.code());
    assertEquals(ValidationPhase.STRUCTURE, nonCanonical.phase());

    ValidationException padded =
        assertThrows(
            ValidationException.class,
            () -> local.decode("k4.local.cGF5bG9hZA==", ValidationPolicy.permissive()));
    assertEquals(FailureCode.NON_CANONICAL_ENCODING, padded.code());
  }

  @Test
  void rejectsMismatchingTypeLabel() throws IOException {
    TestVector v = k4Local();
    SecretType secret = new SecretType(Version.V4);

    assertThrows(
        PaserkException.class, () -> secret.decode(v.paserk, ValidationPolicy.permissive()));
  }

  @Test
  void validatesStructureBeforeDecoding() throws IOException {
    TestVector v = k4Local();

    ValidatedPaserk validated = ValidatedPaserk.parse(v.paserk, ValidationPolicy.permissive());
    assertEquals(Version.V4, validated.version());
    assertEquals("local", validated.type());
    assertArrayEquals(HexToBytes.hexToBytes(v.key), validated.payload());
  }

  @Test
  void failureMessagesDoNotContainSecrets() throws IOException {
    TestVector v = k4Local();
    Local local = new Local(Version.V4);

    ValidationException e =
        assertThrows(
            ValidationException.class,
            () ->
                local.decode(
                    v.paserk,
                    ValidationPolicy.builder().maxTokenLength(v.paserk.length() - 1).build()));
    assertFalse(e.getMessage().contains(v.paserk));
    assertFalse(e.getMessage().contains(v.key));
  }
}
