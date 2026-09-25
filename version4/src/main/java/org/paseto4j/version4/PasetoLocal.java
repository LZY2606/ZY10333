/*
 * SPDX-FileCopyrightText: Copyright © 2025 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.version4;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Base64.getUrlDecoder;
import static java.util.Objects.requireNonNull;
import static org.paseto4j.commons.ByteUtils.concat;
import static org.paseto4j.commons.ByteUtils.wipe;
import static org.paseto4j.commons.Conditions.verify;
import static org.paseto4j.commons.Purpose.PURPOSE_LOCAL;
import static org.paseto4j.commons.Version.V4;

import java.security.MessageDigest;
import java.util.Arrays;
import org.paseto4j.commons.ClaimValidator;
import org.paseto4j.commons.FailureCode;
import org.paseto4j.commons.PasetoException;
import org.paseto4j.commons.PreAuthenticationEncoder;
import org.paseto4j.commons.SecretKey;
import org.paseto4j.commons.Token;
import org.paseto4j.commons.TokenOut;
import org.paseto4j.commons.ValidatedToken;
import org.paseto4j.commons.ValidationException;
import org.paseto4j.commons.ValidationPolicy;

public class PasetoLocal {
  private PasetoLocal() {}

  public static String encrypt(SecretKey key, String payload, String footer, String implicit) {
    return encrypt(key, CryptoFunctions.randomBytes(), payload, footer, implicit);
  }

  /**
   * <a
   * href="https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version4.md#encrypt">encrypt</a>
   */
  static String encrypt(
      SecretKey key, byte[] nonce, String payload, String footer, String implicitAssertion) {
    requireNonNull(key);
    requireNonNull(payload);
    verify(nonce.length == 32, "nonce should be 32 bytes");

    TokenOut token = new TokenOut(V4, PURPOSE_LOCAL);

    // 4
    byte[] tmp = encryptionKey(key, nonce);
    byte[] ek = Arrays.copyOfRange(tmp, 0, 32);
    byte[] n2 = Arrays.copyOfRange(tmp, 32, 56);
    byte[] ak = authenticationKey(key, nonce);
    try {
      // 5
      byte[] c = CryptoFunctions.xchacha20(payload.getBytes(UTF_8), n2, ek);

      // 6
      byte[] preAuth =
          PreAuthenticationEncoder.encode(
              token.header(), nonce, c, footer.getBytes(UTF_8), implicitAssertion.getBytes(UTF_8));

      // 7
      byte[] t = CryptoFunctions.blake2b(32, preAuth, ak);

      return token.payload(concat(nonce, c, t)).footer(footer).doFinal();
    } finally {
      wipe(tmp, ek, n2, ak);
    }
  }

  /**
   * <a
   * href="https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version4.md#decrypt">decrypt</a>
   */
  public static String decrypt(SecretKey key, String token, String footer) {
    return decrypt(key, token, footer, "");
  }

  /**
   * <a
   * href="https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version4.md#decrypt">decrypt</a>
   */
  static String decrypt(SecretKey key, String token, String footer, String implicitAssertion) {
    requireNonNull(key);
    requireNonNull(token);

    Token pasetoToken = new Token(token, V4, PURPOSE_LOCAL, footer);

    return doDecrypt(
        key,
        pasetoToken.header(),
        getUrlDecoder().decode(pasetoToken.getPayload()),
        footer.getBytes(UTF_8),
        implicitAssertion.getBytes(UTF_8));
  }

  /**
   * Decrypts after validating the token against {@code policy}; validation runs before any
   * cryptographic operation and claim rules are enforced on the decrypted payload.
   */
  static String decrypt(
      SecretKey key,
      String token,
      String footer,
      String implicitAssertion,
      ValidationPolicy policy) {
    requireNonNull(key);
    requireNonNull(token);
    requireNonNull(policy);

    ValidatedToken pasetoToken = ValidatedToken.parse(token, policy);
    pasetoToken.verifyFooter(footer);
    policy.verifyImplicitAssertion(implicitAssertion, true);

    String payload;
    try {
      payload =
          doDecrypt(
              key,
              pasetoToken.header(),
              pasetoToken.payload(),
              (footer == null ? "" : footer).getBytes(UTF_8),
              (implicitAssertion == null ? "" : implicitAssertion).getBytes(UTF_8));
    } catch (IllegalStateException | PasetoException e) {
      throw new ValidationException(
          FailureCode.AUTHENTICATION_FAILED, "token authentication failed", e);
    }
    ClaimValidator.validate(payload, policy);
    return payload;
  }

  private static String doDecrypt(
      SecretKey key,
      byte[] header,
      byte[] nct,
      byte[] footerBytes,
      byte[] implicitAssertionBytes) {
    // 4
    byte[] nonce = Arrays.copyOfRange(nct, 0, 32);
    byte[] t = Arrays.copyOfRange(nct, nct.length - 32, nct.length);
    byte[] c = Arrays.copyOfRange(nct, 32, nct.length - 32);

    // 5
    byte[] tmp = encryptionKey(key, nonce);
    byte[] ek = Arrays.copyOfRange(tmp, 0, 32);
    byte[] n2 = Arrays.copyOfRange(tmp, 32, 56);
    byte[] ak = authenticationKey(key, nonce);
    byte[] message = null;
    try {
      // 6
      byte[] preAuth =
          PreAuthenticationEncoder.encode(
              header, nonce, c, footerBytes, implicitAssertionBytes);

      // 7
      byte[] t2 = CryptoFunctions.blake2b(32, preAuth, ak);

      // 8
      if (!MessageDigest.isEqual(t, t2)) {
        throw new IllegalStateException("HMAC verification failed");
      }

      message = CryptoFunctions.xchacha20(c, n2, ek);
      return new String(message, UTF_8);
    } finally {
      wipe(tmp, ek, n2, ak, message);
    }
  }

  private static byte[] encryptionKey(SecretKey key, byte[] nonce) {
    byte[] rawKey = key.toBytes();
    try {
      return CryptoFunctions.blake2b(
          56, concat("paseto-encryption-key".getBytes(UTF_8), nonce), rawKey);
    } finally {
      wipe(rawKey);
    }
  }

  private static byte[] authenticationKey(SecretKey key, byte[] nonce) {
    byte[] rawKey = key.toBytes();
    try {
      return CryptoFunctions.blake2b(
          32, concat("paseto-auth-key-for-aead".getBytes(UTF_8), nonce), rawKey);
    } finally {
      wipe(rawKey);
    }
  }
}
