/*
 * SPDX-FileCopyrightText: Copyright © 2026 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.commons;

import java.util.Base64;
import java.util.regex.Pattern;

/**
 * Canonical, unpadded RFC 4648 base64url codec shared by PASETO tokens and PASERK. Decoding is
 * strict: padding, characters outside the base64url alphabet and non-canonical trailing bits are
 * rejected instead of being silently accepted by a lenient decoder.
 */
public final class Base64Url {

  private static final Pattern BASE64URL = Pattern.compile("[A-Za-z0-9_-]*");

  private Base64Url() {}

  public static String encode(byte[] bytes) {
    return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
  }

  /**
   * Decodes canonical, unpadded base64url.
   *
   * @throws PasetoException if the input is not canonical base64url
   */
  public static byte[] decode(String encoded) {
    if (encoded == null || encoded.indexOf('=') >= 0 || !BASE64URL.matcher(encoded).matches()) {
      throw new PasetoException("Invalid base64url encoding");
    }
    if ((encoded.length() & 3) == 1) {
      throw new PasetoException("Invalid base64url encoding");
    }
    try {
      byte[] decoded = Base64.getUrlDecoder().decode(encoded);
      if (!encode(decoded).equals(encoded)) {
        throw new PasetoException("Non-canonical base64url encoding");
      }
      return decoded;
    } catch (IllegalArgumentException e) {
      throw new PasetoException("Invalid base64url encoding", e);
    }
  }

  /** Returns whether the given string is canonical, unpadded base64url. */
  public static boolean isCanonical(String encoded) {
    if (encoded == null || encoded.indexOf('=') >= 0 || !BASE64URL.matcher(encoded).matches()) {
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
}
