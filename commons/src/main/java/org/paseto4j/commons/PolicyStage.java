/*
 * SPDX-FileCopyrightText: Copyright © 2026 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.commons;

/**
 * The validation stage at which a token or PASERK was rejected. Stages are ordered: all
 * structural and policy stages run before any cryptographic operation, and {@link #CLAIMS} runs
 * only after successful authentication.
 */
public enum PolicyStage {
  /** Token structure: number of segments, empty segments, header shape. */
  STRUCTURE,
  /** Protocol version is not allowed by the policy. */
  VERSION,
  /** Token purpose is not allowed by the policy. */
  PURPOSE,
  /** Total token length or an individual segment length exceeds the policy limit. */
  LENGTH,
  /** A segment is not canonical base64url. */
  ENCODING,
  /** The footer does not satisfy the policy. */
  FOOTER,
  /** The implicit assertion requirements of the policy are not met. */
  IMPLICIT_ASSERTION,
  /** A payload claim does not satisfy the policy (checked after authentication). */
  CLAIMS
}
