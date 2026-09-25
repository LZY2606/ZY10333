/*
 * SPDX-FileCopyrightText: Copyright © 2026 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.commons;

import static java.nio.charset.StandardCharsets.UTF_8;

import java.security.MessageDigest;
import java.util.Locale;

/**
 * A PASETO token that passed structural and policy validation <em>before</em> any cryptographic
 * operation. All checks are cheap and run in a fixed order so that malformed input is rejected
 * before expensive crypto and no partial authentication result is observable.
 */
public final class ValidatedToken {

  private final Version version;
  private final Purpose purpose;
  private final byte[] payload;
  private final byte[] footer;

  private ValidatedToken(Version version, Purpose purpose, byte[] payload, byte[] footer) {
    this.version = version;
    this.purpose = purpose;
    this.payload = payload;
    this.footer = footer;
  }

  /**
   * Parses and validates {@code token} against {@code policy}. On success the returned object
   * exposes the decoded payload and footer for the cryptographic step.
   *
   * @throws ValidationException when the token is malformed or rejected by the policy
   */
  public static ValidatedToken parse(String token, ValidationPolicy policy) {
    if (token == null || token.isEmpty()) {
      throw new ValidationException(FailureCode.MALFORMED_TOKEN, "token is null or empty");
    }
    if (policy.maxTokenLength() > 0 && token.length() > policy.maxTokenLength()) {
      throw new ValidationException(
          FailureCode.TOKEN_TOO_LONG,
          String.format(
              Locale.ROOT,
              "token length %d exceeds the policy limit of %d",
              token.length(),
              policy.maxTokenLength()));
    }

    String[] parts = token.split("\\.", -1);
    if (parts.length != 3 && parts.length != 4) {
      throw new ValidationException(
          FailureCode.MALFORMED_TOKEN, "token must consist of exactly 3 or 4 segments");
    }

    Version version = parseVersion(parts[0]);
    Purpose purpose = parsePurpose(parts[1]);
    if (!policy.allowedVersions().isEmpty() && !policy.allowedVersions().contains(version)) {
      throw new ValidationException(
          FailureCode.VERSION_NOT_ALLOWED,
          String.format(Locale.ROOT, "version %s is not allowed by the policy", version));
    }
    if (!policy.allowedPurposes().isEmpty() && !policy.allowedPurposes().contains(purpose)) {
      throw new ValidationException(
          FailureCode.PURPOSE_NOT_ALLOWED,
          String.format(Locale.ROOT, "purpose %s is not allowed by the policy", purpose));
    }

    byte[] payload = decodeSegment(parts[2], "payload", policy.maxPayloadLength());
    if (payload.length == 0) {
      throw new ValidationException(FailureCode.MALFORMED_TOKEN, "payload segment is empty");
    }

    byte[] footer = new byte[0];
    if (parts.length == 4 && !parts[3].isEmpty()) {
      footer = decodeSegment(parts[3], "footer", policy.maxFooterLength());
    }

    ValidatedToken validated = new ValidatedToken(version, purpose, payload, footer);
    policy.verifyPolicyFooter(footer);
    return validated;
  }

  /**
   * Verifies that the caller-supplied footer matches the footer embedded in the token, using
   * protocol byte semantics: a missing footer and an empty footer segment both represent the
   * empty byte string.
   *
   * @throws ValidationException with code {@link FailureCode#FOOTER_MISMATCH} on mismatch
   */
  public void verifyFooter(String expectedFooter) {
    String expected = expectedFooter == null ? "" : expectedFooter;
    if (!MessageDigest.isEqual(footer, expected.getBytes(UTF_8))) {
      throw new ValidationException(
          FailureCode.FOOTER_MISMATCH, "token footer does not match the expected footer");
    }
  }

  public Version version() {
    return version;
  }

  public Purpose purpose() {
    return purpose;
  }

  /** Decoded payload segment; a defensive copy is returned. */
  public byte[] payload() {
    return payload.clone();
  }

  /** Decoded footer (empty when the token carries no footer); a defensive copy is returned. */
  public byte[] footer() {
    return footer.clone();
  }

  public byte[] header() {
    return String.format(Locale.ROOT, "%s.%s.", version, purpose).getBytes(UTF_8);
  }

  private static Version parseVersion(String segment) {
    for (Version version : Version.values()) {
      if (version.toString().equals(segment)) {
        return version;
      }
    }
    throw new ValidationException(
        FailureCode.MALFORMED_TOKEN, "token header contains an unknown version");
  }

  private static Purpose parsePurpose(String segment) {
    for (Purpose purpose : Purpose.values()) {
      if (purpose.toString().equals(segment)) {
        return purpose;
      }
    }
    throw new ValidationException(
        FailureCode.MALFORMED_TOKEN, "token header contains an unknown purpose");
  }

  private static byte[] decodeSegment(String segment, String name, int maxLength) {
    checkSegmentLength(segment, name, maxLength);
    if (!Base64Url.isCanonical(segment)) {
      throw new ValidationException(
          FailureCode.NON_CANONICAL_ENCODING,
          String.format(Locale.ROOT, "%s segment is not canonical base64url", name));
    }
    return Base64Url.decode(segment);
  }

  private static void checkSegmentLength(String segment, String name, int maxLength) {
    if (maxLength > 0 && segment.length() > maxLength) {
      throw new ValidationException(
          FailureCode.SEGMENT_TOO_LONG,
          String.format(
              Locale.ROOT,
              "%s segment length %d exceeds the policy limit of %d",
              name,
              segment.length(),
              maxLength));
    }
  }
}
