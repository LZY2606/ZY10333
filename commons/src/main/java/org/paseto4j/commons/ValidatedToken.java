/*
 * SPDX-FileCopyrightText: Copyright © 2026 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.commons;

import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * A token that passed the pre-cryptographic stages of a {@link ValidationPolicy}. Exposes the
 * decoded payload and footer so the version-specific cryptographic code does not need to re-parse
 * or re-decode the token.
 */
public final class ValidatedToken {

  private final TokenAlgorithm tokenAlgorithm;
  private final byte[] payload;
  private final byte[] footer;

  ValidatedToken(TokenAlgorithm tokenAlgorithm, byte[] payload, byte[] footer) {
    this.tokenAlgorithm = tokenAlgorithm;
    this.payload = payload;
    this.footer = footer;
  }

  public Version version() {
    return tokenAlgorithm.version();
  }

  public Purpose purpose() {
    return tokenAlgorithm.purpose();
  }

  public byte[] header() {
    return tokenAlgorithm.header().getBytes(UTF_8);
  }

  /** The decoded payload segment. */
  public byte[] payload() {
    return payload;
  }

  /** The decoded footer, or an empty array when the token carries no footer. */
  public byte[] footer() {
    return footer;
  }
}
