/*
 * SPDX-FileCopyrightText: Copyright © 2026 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.paserk;

import java.util.Locale;
import org.paseto4j.commons.Base64Url;
import org.paseto4j.commons.FailureCode;
import org.paseto4j.commons.ValidationException;
import org.paseto4j.commons.ValidationPolicy;
import org.paseto4j.commons.Version;

/**
 * A PASERK string that passed structural and policy validation before any key material is
 * handled. Shares its validation rules and failure codes with PASETO token validation.
 */
public final class ValidatedPaserk {

  private final Version version;
  private final String type;
  private final byte[] payload;

  private ValidatedPaserk(Version version, String type, byte[] payload) {
    this.version = version;
    this.type = type;
    this.payload = payload;
  }

  /**
   * Parses and validates {@code paserk} against {@code policy}.
   *
   * @throws ValidationException when the PASERK is malformed or rejected by the policy
   */
  public static ValidatedPaserk parse(String paserk, ValidationPolicy policy) {
    if (paserk == null || paserk.isEmpty()) {
      throw new ValidationException(FailureCode.MALFORMED_TOKEN, "PASERK is null or empty");
    }
    if (policy.maxTokenLength() > 0 && paserk.length() > policy.maxTokenLength()) {
      throw new ValidationException(
          FailureCode.TOKEN_TOO_LONG,
          String.format(
              Locale.ROOT,
              "PASERK length %d exceeds the policy limit of %d",
              paserk.length(),
              policy.maxTokenLength()));
    }

    String[] parts = paserk.split("\\.", -1);
    if (parts.length != 3) {
      throw new ValidationException(
          FailureCode.MALFORMED_TOKEN, "PASERK must consist of exactly 3 segments");
    }

    Version version = parseVersion(parts[0]);
    if (!policy.allowedVersions().isEmpty() && !policy.allowedVersions().contains(version)) {
      throw new ValidationException(
          FailureCode.VERSION_NOT_ALLOWED,
          String.format(Locale.ROOT, "version %s is not allowed by the policy", version));
    }

    String type = parts[1];
    if (type.isEmpty()) {
      throw new ValidationException(
          FailureCode.MALFORMED_TOKEN, "PASERK type label is empty");
    }

    String payloadSegment = parts[2];
    if (payloadSegment.isEmpty()) {
      throw new ValidationException(
          FailureCode.MALFORMED_TOKEN, "PASERK payload segment is empty");
    }
    if (policy.maxPayloadLength() > 0 && payloadSegment.length() > policy.maxPayloadLength()) {
      throw new ValidationException(
          FailureCode.SEGMENT_TOO_LONG,
          String.format(
              Locale.ROOT,
              "payload segment length %d exceeds the policy limit of %d",
              payloadSegment.length(),
              policy.maxPayloadLength()));
    }
    if (!Base64Url.isCanonical(payloadSegment)) {
      throw new ValidationException(
          FailureCode.NON_CANONICAL_ENCODING, "payload segment is not canonical base64url");
    }

    return new ValidatedPaserk(version, type, Base64Url.decode(payloadSegment));
  }

  public Version version() {
    return version;
  }

  public String type() {
    return type;
  }

  /** Decoded payload segment; a defensive copy is returned. */
  public byte[] payload() {
    return payload.clone();
  }

  private static Version parseVersion(String segment) {
    return switch (segment) {
      case "k1" -> Version.V1;
      case "k2" -> Version.V2;
      case "k3" -> Version.V3;
      case "k4" -> Version.V4;
      default ->
          throw new ValidationException(
              FailureCode.MALFORMED_TOKEN, "PASERK header contains an unknown version");
    };
  }
}
