/*
 * SPDX-FileCopyrightText: Copyright © 2026 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.commons;

import java.time.Clock;
import java.time.Duration;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.function.Predicate;

/**
 * Immutable, thread-safe validation policy applied before (structure, version, purpose, length,
 * encoding, footer, implicit assertion) and after (claims) the cryptographic operations of
 * PASETO v1-v4 and PASERK decoding.
 *
 * <p>All constraints are optional; an unset constraint means "no restriction". Use {@link
 * #permissive()} for a policy equivalent to the legacy entry points and {@link #legacy(String)}
 * to reproduce the exact footer semantics of the legacy {@code (key, token, footer)} methods.
 *
 * <p>Instances are immutable and safely shared between threads; the builder is not.
 */
public final class ValidationPolicy {

  private static final ValidationPolicy PERMISSIVE = builder().build();

  private final Set<Version> allowedVersions;
  private final Set<Purpose> allowedPurposes;
  private final Integer maxTokenLength;
  private final Integer maxPayloadLength;
  private final Integer maxFooterLength;
  private final FooterExpectation footerExpectation;
  private final boolean implicitAssertionRequired;
  private final Clock clock;
  private final Duration allowedClockSkew;
  private final boolean validateTimestamps;
  private final Set<String> requiredClaims;
  private final Map<String, String> expectedClaims;

  private ValidationPolicy(Builder builder) {
    this.allowedVersions = Collections.unmodifiableSet(new LinkedHashSet<>(builder.allowedVersions));
    this.allowedPurposes = Collections.unmodifiableSet(new LinkedHashSet<>(builder.allowedPurposes));
    this.maxTokenLength = builder.maxTokenLength;
    this.maxPayloadLength = builder.maxPayloadLength;
    this.maxFooterLength = builder.maxFooterLength;
    this.footerExpectation = builder.footerExpectation;
    this.implicitAssertionRequired = builder.implicitAssertionRequired;
    this.clock = builder.clock;
    this.allowedClockSkew = builder.allowedClockSkew;
    this.validateTimestamps = builder.validateTimestamps;
    this.requiredClaims = Collections.unmodifiableSet(new LinkedHashSet<>(builder.requiredClaims));
    this.expectedClaims = Collections.unmodifiableMap(new LinkedHashMap<>(builder.expectedClaims));
  }

  /** A policy without any restriction; equivalent to the legacy entry points. */
  public static ValidationPolicy permissive() {
    return PERMISSIVE;
  }

  /**
   * A policy reproducing the legacy footer semantics: a {@code null} or empty footer requires the
   * token to carry no footer, any other footer must match exactly.
   */
  public static ValidationPolicy legacy(String footer) {
    return builder()
        .footer(Conditions.isNullOrEmpty(footer) ? FooterExpectation.absent() : FooterExpectation.exact(footer))
        .build();
  }

  public static Builder builder() {
    return new Builder();
  }

  public Set<Version> allowedVersions() {
    return allowedVersions;
  }

  public Set<Purpose> allowedPurposes() {
    return allowedPurposes;
  }

  public Integer maxTokenLength() {
    return maxTokenLength;
  }

  public Integer maxPayloadLength() {
    return maxPayloadLength;
  }

  public Integer maxFooterLength() {
    return maxFooterLength;
  }

  public FooterExpectation footerExpectation() {
    return footerExpectation;
  }

  public boolean implicitAssertionRequired() {
    return implicitAssertionRequired;
  }

  public Clock clock() {
    return clock;
  }

  public Duration allowedClockSkew() {
    return allowedClockSkew;
  }

  public boolean validateTimestamps() {
    return validateTimestamps;
  }

  public Set<String> requiredClaims() {
    return requiredClaims;
  }

  public Map<String, String> expectedClaims() {
    return expectedClaims;
  }

  /** Builder for {@link ValidationPolicy}. Not thread-safe. */
  public static final class Builder {

    private final Set<Version> allowedVersions = new LinkedHashSet<>();
    private final Set<Purpose> allowedPurposes = new LinkedHashSet<>();
    private Integer maxTokenLength;
    private Integer maxPayloadLength;
    private Integer maxFooterLength;
    private FooterExpectation footerExpectation = FooterExpectation.any();
    private boolean implicitAssertionRequired;
    private Clock clock = Clock.systemUTC();
    private Duration allowedClockSkew = Duration.ZERO;
    private boolean validateTimestamps;
    private final Set<String> requiredClaims = new LinkedHashSet<>();
    private final Map<String, String> expectedClaims = new LinkedHashMap<>();

    private Builder() {}

    /** Restricts the accepted protocol versions. */
    public Builder allowVersions(Version... versions) {
      Collections.addAll(allowedVersions, versions);
      return this;
    }

    /** Restricts the accepted purposes. */
    public Builder allowPurposes(Purpose... purposes) {
      Collections.addAll(allowedPurposes, purposes);
      return this;
    }

    /** Maximum total token length in characters (including header and footer). */
    public Builder maxTokenLength(int maxTokenLength) {
      Conditions.verify(maxTokenLength > 0, "maxTokenLength must be positive");
      this.maxTokenLength = maxTokenLength;
      return this;
    }

    /** Maximum length of the payload segment in characters. */
    public Builder maxPayloadLength(int maxPayloadLength) {
      Conditions.verify(maxPayloadLength > 0, "maxPayloadLength must be positive");
      this.maxPayloadLength = maxPayloadLength;
      return this;
    }

    /** Maximum length of the footer segment in characters. */
    public Builder maxFooterLength(int maxFooterLength) {
      Conditions.verify(maxFooterLength > 0, "maxFooterLength must be positive");
      this.maxFooterLength = maxFooterLength;
      return this;
    }

    /** Sets the footer expectation. */
    public Builder footer(FooterExpectation expectation) {
      this.footerExpectation = Objects.requireNonNull(expectation);
      return this;
    }

    /** The footer must be exactly this value. */
    public Builder expectFooter(String footer) {
      return footer(FooterExpectation.exact(footer));
    }

    /** The token must not carry a footer. */
    public Builder requireNoFooter() {
      return footer(FooterExpectation.absent());
    }

    /** The decoded footer must satisfy the given predicate. */
    public Builder footerMatching(Predicate<String> predicate) {
      return footer(FooterExpectation.matching(predicate));
    }

    /** Requires a non-empty implicit assertion (only supported by v3 and v4). */
    public Builder requireImplicitAssertion() {
      this.implicitAssertionRequired = true;
      return this;
    }

    /**
     * Enables validation of the {@code exp}, {@code nbf} and {@code iat} claims against the given
     * clock with the allowed clock skew.
     */
    public Builder clock(Clock clock, Duration allowedClockSkew) {
      this.clock = Objects.requireNonNull(clock);
      this.allowedClockSkew = Objects.requireNonNull(allowedClockSkew);
      this.validateTimestamps = true;
      return this;
    }

    /** Claims that must be present in the payload. */
    public Builder requireClaims(String... claims) {
      Collections.addAll(requiredClaims, claims);
      return this;
    }

    /** Requires a claim to have exactly the given string value (for example {@code iss}). */
    public Builder expectClaim(String claim, String expectedValue) {
      expectedClaims.put(Objects.requireNonNull(claim), Objects.requireNonNull(expectedValue));
      return this;
    }

    public ValidationPolicy build() {
      return new ValidationPolicy(this);
    }
  }
}
