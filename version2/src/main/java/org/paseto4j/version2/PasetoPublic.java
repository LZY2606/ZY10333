/*
 * SPDX-FileCopyrightText: Copyright © 2018 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.version2;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Base64.getUrlDecoder;
import static java.util.Objects.requireNonNull;
import static org.paseto4j.commons.ByteUtils.concat;
import static org.paseto4j.commons.PreAuthenticationEncoder.encode;
import static org.paseto4j.commons.Purpose.PURPOSE_PUBLIC;
import static org.paseto4j.commons.Version.V2;

import com.goterl.lazysodium.LazySodiumJava;
import com.goterl.lazysodium.SodiumJava;
import java.security.SignatureException;
import java.util.Arrays;
import org.paseto4j.commons.ClaimValidator;
import org.paseto4j.commons.FailureCode;
import org.paseto4j.commons.PreAuthenticationEncoder;
import org.paseto4j.commons.Token;
import org.paseto4j.commons.TokenOut;
import org.paseto4j.commons.ValidatedToken;
import org.paseto4j.commons.ValidationException;
import org.paseto4j.commons.ValidationPolicy;

class PasetoPublic {

  private static final LazySodiumJava SODIUM;

  static {
    try {
      SODIUM = new LazySodiumJava(new SodiumJava());
    } catch (Exception e) {
      throw new RuntimeException("Failed to initialize libsodium", e);
    }
  }

  private PasetoPublic() {}

  static String sign(PrivateKey privateKey, String payload, String footer) {
    requireNonNull(privateKey);
    requireNonNull(payload);

    TokenOut token = new TokenOut(V2, PURPOSE_PUBLIC);

    byte[] m2 = encode(token.header(), payload.getBytes(UTF_8), footer.getBytes(UTF_8));
    byte[] signature = new byte[64];
    byte[] sk = Arrays.copyOf(privateKey.toBytes(), 64);
    SODIUM.cryptoSignDetached(signature, m2, m2.length, sk);

    return token.payload(concat(payload.getBytes(UTF_8), signature)).footer(footer).doFinal();
  }

  static String parse(PublicKey publicKey, String signedMessage, String footer)
      throws SignatureException {
    requireNonNull(publicKey);
    requireNonNull(signedMessage);

    Token pasetoToken = new Token(signedMessage, V2, PURPOSE_PUBLIC, footer);

    return doParse(
        publicKey,
        pasetoToken.header(),
        getUrlDecoder().decode(pasetoToken.getPayload()),
        footer.getBytes(UTF_8));
  }

  /**
   * Verifies after validating the token against {@code policy}; validation runs before any
   * cryptographic operation and claim rules are enforced on the verified payload.
   */
  static String parse(
      PublicKey publicKey, String signedMessage, String footer, ValidationPolicy policy) {
    requireNonNull(publicKey);
    requireNonNull(signedMessage);
    requireNonNull(policy);

    ValidatedToken pasetoToken = ValidatedToken.parse(signedMessage, policy);
    pasetoToken.verifyFooter(footer);
    policy.verifyImplicitAssertion("", false);

    String payload;
    try {
      payload =
          doParse(
              publicKey,
              pasetoToken.header(),
              pasetoToken.payload(),
              (footer == null ? "" : footer).getBytes(UTF_8));
    } catch (SignatureException e) {
      throw new ValidationException(
          FailureCode.AUTHENTICATION_FAILED, "token authentication failed", e);
    }
    ClaimValidator.validate(payload, policy);
    return payload;
  }

  private static String doParse(PublicKey publicKey, byte[] header, byte[] sm, byte[] footerBytes)
      throws SignatureException {
    // 3
    byte[] signature = Arrays.copyOfRange(sm, sm.length - 64, sm.length);
    byte[] message = Arrays.copyOfRange(sm, 0, sm.length - 64);

    // 4
    byte[] m2 = PreAuthenticationEncoder.encode(header, message, footerBytes);

    // 5
    verifySignature(publicKey, m2, signature);

    return new String(message, UTF_8);
  }

  private static void verifySignature(PublicKey key, byte[] message, byte[] signature)
      throws SignatureException {
    byte[] pk = Arrays.copyOf(key.toBytes(), 32);
    boolean valid = SODIUM.cryptoSignVerifyDetached(signature, message, message.length, pk);
    if (!valid) {
      throw new SignatureException("Invalid signature");
    }
  }
}
