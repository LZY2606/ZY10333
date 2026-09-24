/*
 * SPDX-FileCopyrightText: Copyright © 2026 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.commons;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.function.Executable;

/** Shared assertions for validation-policy tests across all modules. */
public final class PolicyAssertions {

  private PolicyAssertions() {}

  /** Asserts that the executable rejects with the given stable code and stage. */
  public static PolicyViolationException assertViolation(
      Executable executable, String code, PolicyStage stage) {
    PolicyViolationException exception =
        assertThrows(PolicyViolationException.class, executable);
    assertEquals(code, exception.getCode(), "failure code");
    assertEquals(stage, exception.getStage(), "failure stage");
    return exception;
  }

  /** Asserts that the message never leaks key material, payloads or token contents. */
  public static void assertSafeMessage(Throwable exception, String... secrets) {
    String message = exception.getMessage();
    for (String secret : secrets) {
      if (secret != null && !secret.isEmpty()) {
        assertFalse(
            message.contains(secret),
            "exception message must not contain sensitive material: " + secret);
      }
    }
  }
}
