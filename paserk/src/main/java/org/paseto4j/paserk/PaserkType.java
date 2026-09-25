/*
 * SPDX-FileCopyrightText: Copyright © 2026 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.paserk;

import org.paseto4j.commons.ValidationPolicy;

/** Common contract for PASERK types that encode raw PASETO key material. */
public interface PaserkType {

  byte[] decode(String paserk);

  /**
   * Decodes after validating the PASERK against {@code policy}; structural and policy checks run
   * before any key material is handled.
   *
   * @throws org.paseto4j.commons.ValidationException when the policy rejects the PASERK
   */
  default byte[] decode(String paserk, ValidationPolicy policy) {
    ValidatedPaserk validated = ValidatedPaserk.parse(paserk, policy);
    if (!typeLabel().equals(validated.type())) {
      throw new PaserkException("Invalid PASERK type; expected " + typeLabel());
    }
    return decode(paserk);
  }

  String encode(byte[] key);

  String id(byte[] key);

  String typeLabel();
}
