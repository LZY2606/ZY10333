/*
 * SPDX-FileCopyrightText: Copyright © 2026 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.commons;

/** Stable machine-readable reason for a {@link ValidationException}. */
public enum FailureCode {
  MALFORMED_TOKEN(ValidationPhase.STRUCTURE),
  NON_CANONICAL_ENCODING(ValidationPhase.STRUCTURE),
  VERSION_NOT_ALLOWED(ValidationPhase.STRUCTURE),
  PURPOSE_NOT_ALLOWED(ValidationPhase.STRUCTURE),
  TOKEN_TOO_LONG(ValidationPhase.STRUCTURE),
  SEGMENT_TOO_LONG(ValidationPhase.STRUCTURE),
  FOOTER_MISMATCH(ValidationPhase.FOOTER),
  FOOTER_REJECTED(ValidationPhase.FOOTER),
  IMPLICIT_ASSERTION_REQUIRED(ValidationPhase.IMPLICIT_ASSERTION),
  IMPLICIT_ASSERTION_MISMATCH(ValidationPhase.IMPLICIT_ASSERTION),
  AUTHENTICATION_FAILED(ValidationPhase.AUTHENTICATION),
  MALFORMED_CLAIMS(ValidationPhase.CLAIMS),
  MISSING_CLAIM(ValidationPhase.CLAIMS),
  TOKEN_EXPIRED(ValidationPhase.CLAIMS),
  TOKEN_NOT_YET_VALID(ValidationPhase.CLAIMS),
  ISSUED_IN_FUTURE(ValidationPhase.CLAIMS),
  UNEXPECTED_ISSUER(ValidationPhase.CLAIMS),
  UNEXPECTED_AUDIENCE(ValidationPhase.CLAIMS);

  private final ValidationPhase phase;

  FailureCode(ValidationPhase phase) {
    this.phase = phase;
  }

  /** The validation phase this code belongs to. */
  public ValidationPhase phase() {
    return phase;
  }
}
