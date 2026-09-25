/*
 * SPDX-FileCopyrightText: Copyright © 2026 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.commons;

import java.util.Base64;
import java.util.regex.Pattern;

/** Canonical, unpadded RFC 4648 base64url helpers shared by PASETO and PASERK parsing. */
public final class Base64Url {

  private static final Pattern ALPHABET = Pattern.compile("[A-Za-z0-9_-]*");

  private Base64Url() {}

  public static String encode(byte[] bytes) {
    return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
  }

  /**
   * Returns {@code true} when {@code encoded} is the canonical unpadded base64url encoding of its
   * decoded bytes: only alphabet characters, no padding, no trailing zero-bit variations.
   */
  public static boolean isCanonical(String encoded) {
    if (encoded == null || encoded.indexOf('=') >= 0 || !ALPHABET.matcher(encoded).matches()) {
      return false;
    }
    if ((encoded.length() & 3) == 1) {
      return false;
    }
    try {
      return encode(Base64.getUrlDecoder().decode(encoded)).equals(encoded);
    } catch (IllegalArgumentException e) {
      return false;
    }
  }

  /**
   * Decodes {@code encoded} after verifying it is canonical.
   *
   * @throws IllegalArgumentException when the input is not canonical base64url
   */
  public static byte[] decode(String encoded) {
    if (!isCanonical(encoded)) {
      throw new IllegalArgumentException("Input is not canonical base64url");
    }
    return Base64.getUrlDecoder().decode(encoded);
  }
}
