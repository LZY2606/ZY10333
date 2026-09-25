/*
 * SPDX-FileCopyrightText: Copyright © 2026 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.commons;

/**
 * Thrown when a token or PASERK is rejected by a {@link ValidationPolicy} or fails authentication
 * while validated against one. The message is a safe summary: it never contains key material, the
 * plaintext payload, or the complete token.
 */
public class ValidationException extends PasetoException {

  private final FailureCode code;

  public ValidationException(FailureCode code, String message) {
    super(message);
    this.code = code;
  }

  public ValidationException(FailureCode code, String message, Throwable cause) {
    super(message);
    this.code = code;
    initCause(cause);
  }

  /** Stable machine-readable failure code. */
  public FailureCode code() {
    return code;
  }

  /** Stage of validation at which the failure occurred. */
  public ValidationPhase phase() {
    return code.phase();
  }
}
