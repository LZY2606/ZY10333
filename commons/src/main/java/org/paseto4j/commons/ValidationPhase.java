/*
 * SPDX-FileCopyrightText: Copyright © 2026 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.commons;

/** Stage of token validation at which a {@link ValidationException} was raised. */
public enum ValidationPhase {
  /** Structural checks: header, segment count, lengths, canonical encoding, version/purpose. */
  STRUCTURE,
  /** Footer checks against the policy or the caller-supplied footer. */
  FOOTER,
  /** Implicit-assertion checks. */
  IMPLICIT_ASSERTION,
  /** Decryption or signature verification. */
  AUTHENTICATION,
  /** Claim checks on the verified payload. */
  CLAIMS
}
