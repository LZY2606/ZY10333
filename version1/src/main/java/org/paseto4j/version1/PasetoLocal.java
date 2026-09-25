/*
 * SPDX-FileCopyrightText: Copyright © 2018 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.version1;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Base64.getUrlDecoder;
import static java.util.Objects.requireNonNull;
import static org.paseto4j.commons.ByteUtils.concat;
import static org.paseto4j.commons.PreAuthenticationEncoder.encode;
import static org.paseto4j.commons.Purpose.PURPOSE_LOCAL;
import static org.paseto4j.commons.Version.V1;
import static org.paseto4j.version1.CryptoFunctions.decryptAesCtr;
import static org.paseto4j.version1.CryptoFunctions.encryptAesCtr;
import static org.paseto4j.version1.CryptoFunctions.hkdfSha384;
import static org.paseto4j.version1.CryptoFunctions.hmac384;
import static org.paseto4j.version1.CryptoFunctions.randomBytes;

import java.security.MessageDigest;
import java.security.Security;
import java.util.Arrays;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.paseto4j.commons.ClaimValidator;
import org.paseto4j.commons.FailureCode;
import org.paseto4j.commons.PasetoException;
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

  public static String encrypt(SecretKey key, String payload, String footer) {
    return encrypt(key, randomBytes(), payload, footer);
  }

  static String encrypt(SecretKey key, byte[] randomKey, String payload, String footer) {
    requireNonNull(key);
    requireNonNull(payload);

    TokenOut token = new TokenOut(V1, PURPOSE_LOCAL);

    // 3
    byte[] nonce = getNonce(payload.getBytes(UTF_8), randomKey);

    // 4
    byte[] ek = encryptionKey(key, nonce);
    byte[] ak = authenticationKey(key, nonce);

    // 5
    byte[] cipherText =
        encryptAesCtr(ek, Arrays.copyOfRange(nonce, 16, 32), payload.getBytes(UTF_8));

    // 6
    byte[] preAuth = encode(token.header(), nonce, cipherText, footer.getBytes(UTF_8));

    // 7
    byte[] t = hmac384(ak, preAuth);

    // 8
    return token.payload(concat(nonce, cipherText, t)).footer(footer).doFinal();
  }

  private static byte[] getNonce(byte[] payload, byte[] randomKey) {
    return Arrays.copyOfRange(CryptoFunctions.hmac384(randomKey, payload), 0, 32);
  }

  private static byte[] encryptionKey(SecretKey key, byte[] nonce) {
    return hkdfSha384(
        key.toBytes(), Arrays.copyOfRange(nonce, 0, 16), "paseto-encryption-key".getBytes(UTF_8));
  }

  private static byte[] authenticationKey(SecretKey key, byte[] nonce) {
    return hkdfSha384(
        key.toBytes(),
        Arrays.copyOfRange(nonce, 0, 16),
        "paseto-auth-key-for-aead".getBytes(UTF_8));
  }

  /**
   * <a
   * href="https://github.com/paragonie/paseto/blob/master/docs/01-Protocol-Versions/Version1.md#decrypt">...</a>
   */
  static String decrypt(SecretKey key, String token, String footer) {
    requireNonNull(key);
    requireNonNull(token);

    // 1 & 2
    Token pasetoToken = new Token(token, V1, PURPOSE_LOCAL, footer);

    return doDecrypt(
        key,
        pasetoToken.header(),
        getUrlDecoder().decode(pasetoToken.getPayload()),
        footer.getBytes(UTF_8));
  }

  /**
   * Decrypts after validating the token against {@code policy}; validation runs before any
   * cryptographic operation and claim rules are enforced on the decrypted payload.
   */
  static String decrypt(SecretKey key, String token, String footer, ValidationPolicy policy) {
    requireNonNull(key);
    requireNonNull(token);
    requireNonNull(policy);

    ValidatedToken pasetoToken = ValidatedToken.parse(token, policy);
    pasetoToken.verifyFooter(footer);
    policy.verifyImplicitAssertion("", false);

    String payload;
    try {
      payload =
          doDecrypt(
              key,
              pasetoToken.header(),
              pasetoToken.payload(),
              (footer == null ? "" : footer).getBytes(UTF_8));
    } catch (IllegalStateException | PasetoException e) {
      throw new ValidationException(
          FailureCode.AUTHENTICATION_FAILED, "token authentication failed", e);
    }
    ClaimValidator.validate(payload, policy);
    return payload;
  }

  private static String doDecrypt(SecretKey key, byte[] header, byte[] ct, byte[] footerBytes) {
    // 3
    byte[] nonce = Arrays.copyOfRange(ct, 0, 32);
    byte[] t = Arrays.copyOfRange(ct, ct.length - 48, ct.length);
    byte[] c = Arrays.copyOfRange(ct, 32, ct.length - 48);

    // 4
    byte[] ek = encryptionKey(key, nonce);
    byte[] ak = authenticationKey(key, nonce);

    // 5
    byte[] preAuth = encode(header, nonce, c, footerBytes);

    // 6
    byte[] t2 = hmac384(ak, preAuth);

    // 7
    if (!MessageDigest.isEqual(t, t2)) {
      throw new IllegalStateException("HMAC verification failed");
    }

    // 8
    byte[] message = decryptAesCtr(ek, Arrays.copyOfRange(nonce, 16, 32), c);
    return new String(message, UTF_8);
  }
}
