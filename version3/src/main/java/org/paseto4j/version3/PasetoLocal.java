/*
 * SPDX-FileCopyrightText: Copyright © 2018 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.version3;

import static java.nio.charset.StandardCharsets.UTF_8;
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
import org.paseto4j.commons.Pair;
import org.paseto4j.commons.PasetoException;
import org.paseto4j.commons.PreAuthenticationEncoder;
import org.paseto4j.commons.SecretKey;
import org.paseto4j.commons.TokenOut;
import org.paseto4j.commons.TokenValidator;
import org.paseto4j.commons.ValidatedToken;
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
    return decrypt(key, token, ValidationPolicy.legacy(footer), implicitAssertion);
  }

  /**
   * Decrypt the token after applying the given validation policy. All policy checks run before
   * any cryptographic operation.
   */
  public static String decrypt(
      SecretKey key, String token, ValidationPolicy policy, String implicitAssertion) {
    requireNonNull(key);
    requireNonNull(token);
    requireNonNull(policy);

    // 2 and 3
    var pasetoToken = TokenValidator.parse(token, V3, PURPOSE_LOCAL, policy, implicitAssertion);

    // 4
    byte[] ct = pasetoToken.payload();
    if (ct.length < 32 + 48) {
      throw new PasetoException("Invalid token payload");
    }
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
              pasetoToken.header(),
              nonce,
              c,
              pasetoToken.footer(),
              implicitAssertion.getBytes(UTF_8));

      // 7
      byte[] t2 = hmac384(ak, preAuth);

      // 8
      if (!MessageDigest.isEqual(t, t2)) {
        throw new IllegalStateException("HMAC verification failed");
      }

      // 9
      message = decryptAesCtr(ek, n2, c);
      String payload = new String(message, UTF_8);
      TokenValidator.validateClaims(payload, policy);
      return payload;
    } finally {
      wipe(tmp, ek, n2, ak, message);
    }
  }
}
