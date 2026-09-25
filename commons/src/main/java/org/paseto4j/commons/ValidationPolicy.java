/*
 * SPDX-FileCopyrightText: Copyright © 2026 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.commons;

import static java.nio.charset.StandardCharsets.UTF_8;

import java.security.MessageDigest;
import java.time.Clock;
import java.time.Duration;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.function.Predicate;

/**
 * Immutable, thread-safe policy applied before (and, for claims, after) the cryptographic
 * operations of PASETO v1-v4 and PASERK parsing. All restrictions are optional; a policy built
 * with defaults imposes only structural validation (well-formed header, canonical base64url).
 *
 * <p>Failure messages never contain key material, plaintext payloads, or complete tokens.
 */
public final class ValidationPolicy {

  private final Set<Version> allowedVersions;
  private final Set<Purpose> allowedPurposes;
  private final int maxTokenLength;
  private final int maxPayloadLength;
  private final int maxFooterLength;
  private final String expectedFooter;
  private final Predicate<String> footerPredicate;
  private final boolean implicitAssertionRequired;
  private final String expectedImplicitAssertion;
  private final Clock clock;
  private final Duration maxClockSkew;
  private final boolean temporalValidation;
  private final Set<String> requiredClaims;
  private final String expectedIssuer;
  private final String expectedAudience;

  private ValidationPolicy(Builder builder) {
    this.allowedVersions = Set.copyOf(builder.allowedVersions);
    this.allowedPurposes = Set.copyOf(builder.allowedPurposes);
    this.maxTokenLength = builder.maxTokenLength;
    this.maxPayloadLength = builder.maxPayloadLength;
    this.maxFooterLength = builder.maxFooterLength;
    this.expectedFooter = builder.expectedFooter;
    this.footerPredicate = builder.footerPredicate;
    this.implicitAssertionRequired = builder.implicitAssertionRequired;
    this.expectedImplicitAssertion = builder.expectedImplicitAssertion;
    this.clock = builder.clock;
    this.maxClockSkew = builder.maxClockSkew;
    this.temporalValidation = builder.temporalValidation;
    this.requiredClaims = Set.copyOf(builder.requiredClaims);
    this.expectedIssuer = builder.expectedIssuer;
    this.expectedAudience = builder.expectedAudience;
  }

  public static Builder builder() {
    return new Builder();
  }

  /** A policy imposing only structural validation. */
  public static ValidationPolicy permissive() {
    return builder().build();
  }

  /** Allowed versions; an empty set means every version is allowed. */
  public Set<Version> allowedVersions() {
    return allowedVersions;
  }

  /** Allowed purposes; an empty set means every purpose is allowed. */
  public Set<Purpose> allowedPurposes() {
    return allowedPurposes;
  }

  /** Maximum accepted token length in characters; {@code 0} means unlimited. */
  public int maxTokenLength() {
    return maxTokenLength;
  }

  /** Maximum accepted payload segment length in characters; {@code 0} means unlimited. */
  public int maxPayloadLength() {
    return maxPayloadLength;
  }

  /** Maximum accepted footer segment length in characters; {@code 0} means unlimited. */
  public int maxFooterLength() {
    return maxFooterLength;
  }

  public Clock clock() {
    return clock;
  }

  public Duration maxClockSkew() {
    return maxClockSkew;
  }

  public boolean temporalValidation() {
    return temporalValidation;
  }

  public Set<String> requiredClaims() {
    return requiredClaims;
  }

  public String expectedIssuer() {
    return expectedIssuer;
  }

  public String expectedAudience() {
    return expectedAudience;
  }

  boolean hasClaimRules() {
    return temporalValidation
        || !requiredClaims.isEmpty()
        || expectedIssuer != null
        || expectedAudience != null;
  }

  void verifyPolicyFooter(byte[] tokenFooter) {
    if (expectedFooter != null
        && !MessageDigest.isEqual(tokenFooter, expectedFooter.getBytes(UTF_8))) {
      throw new ValidationException(
          FailureCode.FOOTER_MISMATCH, "token footer does not match the policy footer");
    }
    if (footerPredicate != null && !footerPredicate.test(new String(tokenFooter, UTF_8))) {
      throw new ValidationException(
          FailureCode.FOOTER_REJECTED, "token footer rejected by the policy predicate");
    }
  }

  /**
   * Verifies the implicit assertion supplied by the caller against the policy.
   *
   * @param implicitAssertion the assertion supplied by the caller, may be {@code null}
   * @param supportedByVersion whether the PASETO version in use supports implicit assertions
   */
  public void verifyImplicitAssertion(String implicitAssertion, boolean supportedByVersion) {
    String implicit = implicitAssertion == null ? "" : implicitAssertion;
    if (implicitAssertionRequired || expectedImplicitAssertion != null) {
      if (!supportedByVersion) {
        throw new ValidationException(
            FailureCode.IMPLICIT_ASSERTION_REQUIRED,
            "policy requires an implicit assertion but this PASETO version does not support one");
      }
      if (implicit.isEmpty()) {
        throw new ValidationException(
            FailureCode.IMPLICIT_ASSERTION_REQUIRED, "policy requires an implicit assertion");
      }
    }
    if (expectedImplicitAssertion != null
        && !MessageDigest.isEqual(
            implicit.getBytes(UTF_8), expectedImplicitAssertion.getBytes(UTF_8))) {
      throw new ValidationException(
          FailureCode.IMPLICIT_ASSERTION_MISMATCH,
          "implicit assertion does not match the policy expectation");
    }
  }

  public static final class Builder {

    private final Set<Version> allowedVersions = new LinkedHashSet<>();
    private final Set<Purpose> allowedPurposes = new LinkedHashSet<>();
    private int maxTokenLength;
    private int maxPayloadLength;
    private int maxFooterLength;
    private String expectedFooter;
    private Predicate<String> footerPredicate;
    private boolean implicitAssertionRequired;
    private String expectedImplicitAssertion;
    private Clock clock = Clock.systemUTC();
    private Duration maxClockSkew = Duration.ZERO;
    private boolean temporalValidation;
    private final Set<String> requiredClaims = new LinkedHashSet<>();
    private String expectedIssuer;
    private String expectedAudience;

    private Builder() {}

    public Builder allowVersions(Version... versions) {
      allowedVersions.addAll(Arrays.asList(versions));
      return this;
    }

    public Builder allowPurposes(Purpose... purposes) {
      allowedPurposes.addAll(Arrays.asList(purposes));
      return this;
    }

    public Builder maxTokenLength(int maxTokenLength) {
      this.maxTokenLength = requireNonNegative(maxTokenLength, "maxTokenLength");
      return this;
    }

    public Builder maxPayloadLength(int maxPayloadLength) {
      this.maxPayloadLength = requireNonNegative(maxPayloadLength, "maxPayloadLength");
      return this;
    }

    public Builder maxFooterLength(int maxFooterLength) {
      this.maxFooterLength = requireNonNegative(maxFooterLength, "maxFooterLength");
      return this;
    }

    /** Requires the token footer to equal this exact value (byte semantics). */
    public Builder expectFooter(String expectedFooter) {
      this.expectedFooter = expectedFooter;
      return this;
    }

    /** Requires the decoded token footer to satisfy this predicate. */
    public Builder footerPredicate(Predicate<String> footerPredicate) {
      this.footerPredicate = footerPredicate;
      return this;
    }

    public Builder requireImplicitAssertion() {
      this.implicitAssertionRequired = true;
      return this;
    }

    /** Requires the implicit assertion to equal this exact value; implies {@link
     * #requireImplicitAssertion()}. */
    public Builder expectImplicitAssertion(String expectedImplicitAssertion) {
      this.expectedImplicitAssertion = expectedImplicitAssertion;
      return this;
    }

    public Builder clock(Clock clock) {
      this.clock = clock;
      return this;
    }

    public Builder maxClockSkew(Duration maxClockSkew) {
      this.maxClockSkew = maxClockSkew;
      return this;
    }

    /** Validates {@code exp}, {@code nbf} and {@code iat} claims against the policy clock. */
    public Builder validateTemporalClaims() {
      this.temporalValidation = true;
      return this;
    }

    public Builder requireClaims(String... claims) {
      requiredClaims.addAll(Arrays.asList(claims));
      return this;
    }

    public Builder expectIssuer(String expectedIssuer) {
      this.expectedIssuer = expectedIssuer;
      return this;
    }

    public Builder expectAudience(String expectedAudience) {
      this.expectedAudience = expectedAudience;
      return this;
    }

    public ValidationPolicy build() {
      return new ValidationPolicy(this);
    }

    private static int requireNonNegative(int value, String name) {
      if (value < 0) {
        throw new IllegalArgumentException(name + " must not be negative");
      }
      return value;
    }
  }
}
