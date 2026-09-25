/*
 * SPDX-FileCopyrightText: Copyright © 2018 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.version1;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Base64.getUrlDecoder;
import static java.util.Objects.requireNonNull;
import static org.paseto4j.commons.Purpose.PURPOSE_PUBLIC;
import static org.paseto4j.commons.Version.V1;

import java.security.SignatureException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import org.paseto4j.commons.ByteUtils;
import org.paseto4j.commons.ClaimValidator;
import org.paseto4j.commons.FailureCode;
import org.paseto4j.commons.PreAuthenticationEncoder;
import org.paseto4j.commons.Token;
import org.paseto4j.commons.TokenOut;
import org.paseto4j.commons.ValidatedToken;
import org.paseto4j.commons.ValidationException;
import org.paseto4j.commons.ValidationPolicy;

class PasetoPublic {

  private PasetoPublic() {}

  /**
   * Sign the token, <a
   * href="https://github.com/paragonie/paseto/blob/master/docs/01-Protocol-Versions/Version1.md#sign">...</a>
   */
  static String sign(RSAPrivateKey privateKey, String payload, String footer) {
    requireNonNull(privateKey);
    requireNonNull(payload);

    TokenOut token = new TokenOut(V1, PURPOSE_PUBLIC);

    // 2
    byte[] m2 =
        PreAuthenticationEncoder.encode(
            token.header(), payload.getBytes(UTF_8), footer.getBytes(UTF_8));

    // 3
    byte[] signature = CryptoFunctions.signRsaPssSha384(privateKey, m2);

    // 4
    return token
        .payload(ByteUtils.concat(payload.getBytes(UTF_8), signature))
        .footer(footer)
        .doFinal();
  }

  /**
   * Parse the token, <a
   * href="https://github.com/paragonie/paseto/blob/master/docs/01-Protocol-Versions/Version1.md#verify">...</a>
   */
  static String parse(RSAPublicKey publicKey, String signedMessage, String footer)
      throws SignatureException {
    requireNonNull(publicKey);
    requireNonNull(signedMessage);

    // 1 & 2
    Token token = new Token(signedMessage, V1, PURPOSE_PUBLIC, footer);

    return doParse(
        publicKey,
        token.header(),
        getUrlDecoder().decode(token.getPayload()),
        footer.getBytes(UTF_8));
  }

  /**
   * Verifies after validating the token against {@code policy}; validation runs before any
   * cryptographic operation and claim rules are enforced on the verified payload.
   */
  static String parse(
      RSAPublicKey publicKey, String signedMessage, String footer, ValidationPolicy policy) {
    requireNonNull(publicKey);
    requireNonNull(signedMessage);
    requireNonNull(policy);

    ValidatedToken token = ValidatedToken.parse(signedMessage, policy);
    token.verifyFooter(footer);
    policy.verifyImplicitAssertion("", false);

    String payload;
    try {
      payload =
          doParse(
              publicKey,
              token.header(),
              token.payload(),
              (footer == null ? "" : footer).getBytes(UTF_8));
    } catch (SignatureException e) {
      throw new ValidationException(
          FailureCode.AUTHENTICATION_FAILED, "token authentication failed", e);
    }
    ClaimValidator.validate(payload, policy);
    return payload;
  }

  private static String doParse(
      RSAPublicKey publicKey, byte[] header, byte[] sm, byte[] footerBytes)
      throws SignatureException {
    // 3
    byte[] signature = Arrays.copyOfRange(sm, sm.length - 256, sm.length);
    byte[] message = Arrays.copyOfRange(sm, 0, sm.length - 256);

    // 4
    byte[] m2 = PreAuthenticationEncoder.encode(header, message, footerBytes);

    // 5
    verifySignature(publicKey, m2, signature);

    return new String(message, UTF_8);
  }

  private static void verifySignature(RSAPublicKey key, byte[] m2, byte[] signature)
      throws SignatureException {
    if (!CryptoFunctions.verifyRsaPssSha384(key, m2, signature)) {
      throw new SignatureException("Invalid signature");
    }
  }
}
