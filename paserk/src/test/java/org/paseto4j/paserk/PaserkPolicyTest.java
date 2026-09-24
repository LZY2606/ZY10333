/*
 * SPDX-FileCopyrightText: Copyright © 2026 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.paserk;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.paseto4j.commons.PolicyAssertions.assertSafeMessage;
import static org.paseto4j.commons.PolicyAssertions.assertViolation;

import org.junit.jupiter.api.Test;
import org.paseto4j.commons.PolicyStage;
import org.paseto4j.commons.PolicyViolationException;
import org.paseto4j.commons.SecretKey;
import org.paseto4j.commons.ValidationPolicy;
import org.paseto4j.commons.Version;

class PaserkPolicyTest {

  private static final SecretKey KEY = SecretKey.fromBytes(new byte[32]);

  @Test
  void legacyDecodeRemainsCompatible() {
    String paserk = org.paseto4j.paserk.version4.Paserk.encodeLocal(KEY);
    assertEquals(KEY, org.paseto4j.paserk.version4.Paserk.decodeLocal(paserk));
    assertEquals(
        KEY,
        org.paseto4j.paserk.version4.Paserk.decodeLocal(paserk, ValidationPolicy.permissive()));
  }

  @Test
  void versionMustBeAllowed() {
    String paserk = org.paseto4j.paserk.version4.Paserk.encodeLocal(KEY);
    PolicyViolationException exception =
        assertViolation(
            () ->
                org.paseto4j.paserk.version4.Paserk.decodeLocal(
                    paserk, ValidationPolicy.builder().allowVersions(Version.V3).build()),
            "POLICY_VERSION_NOT_ALLOWED",
            PolicyStage.VERSION);
    assertSafeMessage(exception, paserk);
    assertDoesNotThrow(
        () ->
            org.paseto4j.paserk.version4.Paserk.decodeLocal(
                paserk, ValidationPolicy.builder().allowVersions(Version.V4).build()));
  }

  @Test
  void lengthBoundariesAreEnforced() {
    String paserk = org.paseto4j.paserk.version3.Paserk.encodeLocal(KEY);
    String payloadSegment = paserk.substring("k3.local.".length());
    assertDoesNotThrow(
        () ->
            org.paseto4j.paserk.version3.Paserk.decodeLocal(
                paserk,
                ValidationPolicy.builder()
                    .maxTokenLength(paserk.length())
                    .maxPayloadLength(payloadSegment.length())
                    .build()));
    assertViolation(
        () ->
            org.paseto4j.paserk.version3.Paserk.decodeLocal(
                paserk, ValidationPolicy.builder().maxTokenLength(paserk.length() - 1).build()),
        "POLICY_TOKEN_TOO_LONG",
        PolicyStage.LENGTH);
    assertViolation(
        () ->
            org.paseto4j.paserk.version3.Paserk.decodeLocal(
                paserk,
                ValidationPolicy.builder().maxPayloadLength(payloadSegment.length() - 1).build()),
        "POLICY_PAYLOAD_TOO_LONG",
        PolicyStage.LENGTH);
  }

  @Test
  void nonCanonicalEncodingIsRejected() {
    String paserk = org.paseto4j.paserk.version4.Paserk.encodeLocal(KEY);
    // shared canonical base64url decoder rejects padding
    assertThrows(
        PaserkException.class,
        () ->
            org.paseto4j.paserk.version4.Paserk.decodeLocal(paserk + "=", ValidationPolicy.permissive()));
    assertThrows(PaserkException.class, () -> org.paseto4j.paserk.version4.Paserk.decodeLocal(paserk + "="));
  }

  @Test
  void policyRejectionIsDistinguishableFromAuthenticationFailure() {
    String paserk = org.paseto4j.paserk.version4.Paserk.encodeLocal(KEY);
    // a structurally valid PASERK of the wrong type fails inside the core logic, not the policy
    assertThrows(
        PaserkException.class,
        () ->
            org.paseto4j.paserk.version4.Paserk.decodePublicKey(
                paserk, ValidationPolicy.permissive()));
    PolicyViolationException exception =
        assertThrows(
            PolicyViolationException.class,
            () ->
                org.paseto4j.paserk.version4.Paserk.decodeLocal(
                    paserk, ValidationPolicy.builder().maxTokenLength(8).build()));
    assertEquals("POLICY_TOKEN_TOO_LONG", exception.getCode());
    assertEquals(PolicyStage.LENGTH, exception.getStage());
  }
}
