/*
 * SPDX-FileCopyrightText: Copyright © 2026 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.commons;

/**
 * Thrown when a token or PASERK is rejected by a {@link ValidationPolicy}. Carries a stable
 * machine-readable {@link #getCode() code} and the {@link #getStage() stage} at which validation
 * failed. The message is a safe summary: it never contains key material, plaintext payloads or
 * (parts of) the token.
 */
public class PolicyViolationException extends PasetoException {

  private final String code;
  private final PolicyStage stage;

  public PolicyViolationException(String code, PolicyStage stage, String safeSummary) {
    super(code + ": " + safeSummary);
    this.code = code;
    this.stage = stage;
  }

  /** Stable machine-readable failure code, safe to log and compare. */
  public String getCode() {
    return code;
  }

  /** The validation stage at which the failure occurred. */
  public PolicyStage getStage() {
    return stage;
  }
}
