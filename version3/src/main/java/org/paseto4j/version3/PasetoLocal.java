/*
 * SPDX-FileCopyrightText: Copyright © 2018 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.version3;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Base64.getUrlDecoder;
import static java.util.Objects.requireNonNull;
import static org.paseto4j.commons.ByteUtils.concat;
import static org.paseto4j.commons.ByteUtils.wipe;
import static org.paseto4j.commons.Purpose.PURPOSE_LOCAL;
import static org.paseto4j.commons.Version.V3;
import static org.paseto4j.version3.CryptoFunctions.decryptAesCtr;
import static org.paseto4j.version3.CryptoFunctions.encryptAesCtr;
import static org.paseto4j.version3.CryptoFunctions.hkdfSha384;
import static org.paseto4j.version3.CryptoFunctions.hmac384;
import static org.paseto4j.version3.CryptoFunctions.randomBytes;

import java.security.MessageDigest;
import java.security.Security;
import java.util.Arrays;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.paseto4j.commons.ByteUtils;
import org.paseto4j.commons.ClaimValidator;
import org.paseto4j.commons.FailureCode;
import org.paseto4j.commons.Pair;
import org.paseto4j.commons.PasetoException;
import org.paseto4j.commons.PreAuthenticationEncoder;
import org.paseto4j.commons.SecretKey;
import org.paseto4j.commons.Token;
import org.paseto4j.commons.TokenOut;
import org.paseto4j.commons.ValidatedToken;
import org.paseto4j.commons.ValidationException;
import org.paseto4j.commons.ValidationPolicy;

class PasetoLocal {

  static {
    Security.addProvider(new BouncyCastleProvider());
  }

  private PasetoLocal() {}

  public static String encrypt(SecretKey key, String payload, String footer, String implicit) {
    return encrypt(key, randomBytes(32), payload, footer, implicit);
  }

  static String encrypt(
      SecretKey key, byte[] nonce, String payload, String footer, String implicit) {
    requireNonNull(key);
    requireNonNull(payload);

    var token = new TokenOut(V3, PURPOSE_LOCAL);

    // 4
    byte[] tmp = encryptionKey(key, nonce);
    Pair<byte[]> split = ByteUtils.split(tmp, 32);
    byte[] ek = split.getFirst();
    byte[] n2 = split.getSecond();
    byte[] ak = authenticationKey(key, nonce);
    try {
      // 5
      byte[] cipherText = encryptAesCtr(ek, n2, payload.getBytes(UTF_8));

      // 6
      byte[] preAuth =
          PreAuthenticationEncoder.encode(
              token.header(), nonce, cipherText, footer.getBytes(UTF_8), implicit.getBytes(UTF_8));

      // 7
      byte[] t = hmac384(ak, preAuth);

      // 8
      return token.payload(concat(nonce, cipherText, t)).footer(footer).doFinal();
    } finally {
      wipe(tmp, ek, n2, ak);
    }
  }

  private static byte[] encryptionKey(SecretKey key, byte[] nonce) {
    byte[] rawKey = key.toBytes();
    try {
      return hkdfSha384(rawKey, concat("paseto-encryption-key".getBytes(UTF_8), nonce));
    } finally {
      wipe(rawKey);
    }
  }

  private static byte[] authenticationKey(SecretKey key, byte[] nonce) {
    byte[] rawKey = key.toBytes();
    try {
      return hkdfSha384(rawKey, concat("paseto-auth-key-for-aead".getBytes(UTF_8), nonce));
    } finally {
      wipe(rawKey);
    }
  }

  /**
   * <a
   * href="https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version3.md#decrypt">...</a>
   */
  public static String decrypt(SecretKey key, String token) {
    return decrypt(key, token, "");
  }

  /**
   * <a
   * href="https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version3.md#decrypt">...</a>
   */
  public static String decrypt(SecretKey key, String token, String footer) {
    return decrypt(key, token, footer, "");
  }

  static String decrypt(SecretKey key, String token, String footer, String implicitAssertion) {
    requireNonNull(key);
    requireNonNull(token);

    // 2 and 3
    var pasetoToken = new Token(token, V3, PURPOSE_LOCAL, footer);

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
      byte[] ct,
      byte[] footerBytes,
      byte[] implicitAssertionBytes) {
    // 4
    byte[] nonce = Arrays.copyOfRange(ct, 0, 32);
    byte[] t = Arrays.copyOfRange(ct, ct.length - 48, ct.length);
    byte[] c = Arrays.copyOfRange(ct, 32, ct.length - 48);

    // 5
    byte[] tmp = encryptionKey(key, nonce);
    Pair<byte[]> split = ByteUtils.split(tmp, 32);
    byte[] ek = split.getFirst();
    byte[] n2 = split.getSecond();
    byte[] ak = authenticationKey(key, nonce);
    byte[] message = null;
    try {
      // 6
      byte[] preAuth =
          PreAuthenticationEncoder.encode(
              header, nonce, c, footerBytes, implicitAssertionBytes);

      // 7
      byte[] t2 = hmac384(ak, preAuth);

      // 8
      if (!MessageDigest.isEqual(t, t2)) {
        throw new IllegalStateException("HMAC verification failed");
      }

      // 9
      message = decryptAesCtr(ek, n2, c);
      return new String(message, UTF_8);
    } finally {
      wipe(tmp, ek, n2, ak, message);
    }
  }
}
