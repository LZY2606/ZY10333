/*
 * SPDX-FileCopyrightText: Copyright © 2026 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.paserk;

import java.nio.ByteBuffer;
import java.util.Base64;
import java.util.Arrays;
import org.paseto4j.commons.Base64Url;
import org.paseto4j.commons.ByteUtils;
import org.paseto4j.commons.PasetoException;
import org.paseto4j.commons.TokenValidator;
import org.paseto4j.commons.ValidationPolicy;
import org.paseto4j.commons.Version;

/** Shared encoding and validation helpers for PASERK implementations. */
public final class Util {

  private Util() {}

  public static String encode(byte[] bytes) {
    return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
  }

  /** Decodes canonical, unpadded RFC 4648 base64url. */
  public static byte[] decode(String encoded) {
    try {
      return Base64Url.decode(encoded);
    } catch (PasetoException e) {
      throw new PaserkException(e.getMessage(), e);
    }
  }

  /**
   * Extracts the payload of a PASERK after applying the applicable stages of the given
   * validation policy (allowed version, total and payload segment length). Runs before any
   * cryptographic operation.
   */
  public static String payload(String paserk, String expectedHeader, ValidationPolicy policy) {
    String payload = payload(paserk, expectedHeader);
    Version version = PaserkVersion.parse(expectedHeader.substring(0, expectedHeader.indexOf('.')));
    TokenValidator.requireVersionAllowed(version, policy);
    TokenValidator.requireLengthWithinLimits(paserk.length(), payload.length(), 0, policy);
    return payload;
  }

  public static String payload(String paserk, String expectedHeader) {
    if (paserk == null || !paserk.startsWith(expectedHeader)) {
      throw new PaserkException("Invalid PASERK header; expected " + expectedHeader);
    }
    String payload = paserk.substring(expectedHeader.length());
    if (payload.isEmpty() || payload.indexOf('.') >= 0) {
      throw new PaserkException("Invalid PASERK payload");
    }
    return payload;
  }

  public static byte[] slice(byte[] bytes, int offset, int length) {
    if (bytes == null || offset < 0 || length < 0 || offset > bytes.length - length) {
      throw new PaserkException("Invalid PASERK length");
    }
    return Arrays.copyOfRange(bytes, offset, offset + length);
  }

  public static byte[] intToBytes(int value) {
    return ByteBuffer.allocate(Integer.BYTES).putInt(value).array();
  }

  public static byte[] longToBytes(long value) {
    return ByteBuffer.allocate(Long.BYTES).putLong(value).array();
  }

  public static int bytesToInt(byte[] bytes) {
    if (bytes.length != Integer.BYTES) {
      throw new PaserkException("Invalid integer encoding");
    }
    return ByteBuffer.wrap(bytes).getInt();
  }

  public static long bytesToLong(byte[] bytes) {
    if (bytes.length != Long.BYTES) {
      throw new PaserkException("Invalid integer encoding");
    }
    return ByteBuffer.wrap(bytes).getLong();
  }

  public static void wipe(byte[]... values) {
    ByteUtils.wipe(values);
  }
}
