/*
 * SPDX-FileCopyrightText: Copyright © 2026 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.commons;

import static java.nio.charset.StandardCharsets.UTF_8;

import java.security.MessageDigest;
import java.util.function.Predicate;

/**
 * Immutable description of how a {@link ValidationPolicy} expects the footer of a token to look.
 * Note that per the PASETO specification an empty footer and a missing footer have identical byte
 * semantics (both are the empty byte string in the pre-authentication encoding), so {@link
 * #absent()} also accepts a missing footer only; a token carrying a non-empty footer segment is
 * rejected.
 */
public final class FooterExpectation {

  enum Kind {
    ANY,
    ABSENT,
    EXACT,
    PREDICATE
  }

  private static final FooterExpectation ANY = new FooterExpectation(Kind.ANY, null, null);
  private static final FooterExpectation ABSENT = new FooterExpectation(Kind.ABSENT, null, null);

  private final Kind kind;
  private final byte[] expected;
  private final Predicate<String> predicate;

  private FooterExpectation(Kind kind, byte[] expected, Predicate<String> predicate) {
    this.kind = kind;
    this.expected = expected;
    this.predicate = predicate;
  }

  /** Any footer (including none) is accepted. */
  public static FooterExpectation any() {
    return ANY;
  }

  /** The token must not carry a (non-empty) footer. */
  public static FooterExpectation absent() {
    return ABSENT;
  }

  /** The footer must be exactly equal to the given value (compared in constant time). */
  public static FooterExpectation exact(String footer) {
    Conditions.verify(footer != null, "footer must not be null");
    return new FooterExpectation(Kind.EXACT, footer.getBytes(UTF_8), null);
  }

  /** The decoded footer (as UTF-8 string, empty when absent) must satisfy the predicate. */
  public static FooterExpectation matching(Predicate<String> predicate) {
    Conditions.verify(predicate != null, "predicate must not be null");
    return new FooterExpectation(Kind.PREDICATE, null, predicate);
  }

  /**
   * Checks the footer of a token.
   *
   * @param footer the decoded footer bytes, empty when the token has no footer segment
   */
  void validate(byte[] footer) {
    switch (kind) {
      case ANY -> {
        // no constraint
      }
      case ABSENT -> {
        if (footer.length != 0) {
          throw new PolicyViolationException(
              "POLICY_FOOTER_NOT_ALLOWED", PolicyStage.FOOTER, "the token must not carry a footer");
        }
      }
      case EXACT -> {
        if (!MessageDigest.isEqual(expected, footer)) {
          throw new PolicyViolationException(
              "POLICY_FOOTER_MISMATCH", PolicyStage.FOOTER, "the footer does not match the policy");
        }
      }
      case PREDICATE -> {
        boolean accepted;
        try {
          accepted = predicate.test(new String(footer, UTF_8));
        } catch (RuntimeException e) {
          accepted = false;
        }
        if (!accepted) {
          throw new PolicyViolationException(
              "POLICY_FOOTER_REJECTED",
              PolicyStage.FOOTER,
              "the footer was rejected by the policy predicate");
        }
      }
    }
  }
}
