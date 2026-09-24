/*
 * SPDX-FileCopyrightText: Copyright © 2026 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.commons;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class Base64UrlTest {

  @Test
  void canonicalEncodingRoundTrips() {
    byte[] bytes = new byte[] {0, 1, 2, 3, (byte) 250, (byte) 251};
    assertArrayEquals(bytes, Base64Url.decode(Base64Url.encode(bytes)));
  }

  @Test
  void emptyInputIsCanonical() {
    assertDoesNotThrow(() -> Base64Url.decode(""));
    assertTrue(Base64Url.isCanonical(""));
  }

  @Test
  void paddingIsRejected() {
    assertThrows(PasetoException.class, () -> Base64Url.decode("AQIDBA=="));
    assertFalse(Base64Url.isCanonical("AQIDBA=="));
  }

  @Test
  void invalidCharactersAreRejected() {
    assertThrows(PasetoException.class, () -> Base64Url.decode("AQ+D"));
    assertThrows(PasetoException.class, () -> Base64Url.decode("AQ/D"));
    assertThrows(PasetoException.class, () -> Base64Url.decode("AQID!"));
  }

  @Test
  void nonCanonicalTrailingBitsAreRejected() {
    // 0x01 encodes canonically as "AQ"; "AR" decodes to the same byte but is not canonical
    assertThrows(PasetoException.class, () -> Base64Url.decode("AR"));
    assertFalse(Base64Url.isCanonical("AR"));
    assertTrue(Base64Url.isCanonical("AQ"));
  }

  @Test
  void illegalLengthIsRejected() {
    assertThrows(PasetoException.class, () -> Base64Url.decode("A"));
    assertFalse(Base64Url.isCanonical("A"));
  }
}
