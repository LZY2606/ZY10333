/*
 * SPDX-FileCopyrightText: Copyright © 2025 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.version4;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Base64.getUrlDecoder;
import static java.util.Objects.requireNonNull;
import static org.paseto4j.commons.ByteUtils.concat;
import static org.paseto4j.commons.Purpose.PURPOSE_PUBLIC;
import static org.paseto4j.commons.Version.V4;

import java.security.SignatureException;
import java.security.interfaces.EdECPrivateKey;
import java.security.interfaces.EdECPublicKey;
import java.util.Arrays;
import org.paseto4j.commons.*;

public class PasetoPublic {
  private PasetoPublic() {}

  static String sign(
      EdECPrivateKey privateKey, String payload, String footer, String implicitAssertion) {

    requireNonNull(privateKey);
    requireNonNull(payload);

    TokenOut token = new TokenOut(V4, PURPOSE_PUBLIC);

    // 3
    byte[] m2 =
        PreAuthenticationEncoder.encode(
            token.header(),
            payload.getBytes(UTF_8),
            footer.getBytes(UTF_8),
            implicitAssertion.getBytes(UTF_8));

    // 4
    byte[] signature = CryptoFunctions.sign(privateKey, m2);

    return token.payload(concat(payload.getBytes(UTF_8), signature)).footer(footer).doFinal();
  }

  public static String parse(
      EdECPublicKey publicKey, String signedMessage, String footer, String implicitAssertion)
      throws SignatureException {
    requireNonNull(publicKey);
    requireNonNull(signedMessage);

    // 1 and 2
    Token token = new Token(signedMessage, V4, PURPOSE_PUBLIC, footer);

    return doParse(
        publicKey,
        token.header(),
        getUrlDecoder().decode(token.getPayload()),
        footer.getBytes(UTF_8),
        implicitAssertion.getBytes(UTF_8));
  }

  /**
   * Verifies after validating the token against {@code policy}; validation runs before any
   * cryptographic operation and claim rules are enforced on the verified payload.
   */
  static String parse(
      EdECPublicKey publicKey,
      String signedMessage,
      String footer,
      String implicitAssertion,
      ValidationPolicy policy) {
    requireNonNull(publicKey);
    requireNonNull(signedMessage);
    requireNonNull(policy);

    ValidatedToken token = ValidatedToken.parse(signedMessage, policy);
    token.verifyFooter(footer);
    policy.verifyImplicitAssertion(implicitAssertion, true);

    String payload;
    try {
      payload =
          doParse(
              publicKey,
              token.header(),
              token.payload(),
              (footer == null ? "" : footer).getBytes(UTF_8),
              (implicitAssertion == null ? "" : implicitAssertion).getBytes(UTF_8));
    } catch (SignatureException e) {
      throw new ValidationException(
          FailureCode.AUTHENTICATION_FAILED, "token authentication failed", e);
    }
    ClaimValidator.validate(payload, policy);
    return payload;
  }

  private static String doParse(
      EdECPublicKey publicKey,
      byte[] header,
      byte[] sm,
      byte[] footerBytes,
      byte[] implicitAssertionBytes)
      throws SignatureException {
    // 4
    byte[] signature = Arrays.copyOfRange(sm, sm.length - 64, sm.length);
    byte[] message = Arrays.copyOfRange(sm, 0, sm.length - 64);

    // 5
    byte[] m2 =
        PreAuthenticationEncoder.encode(
            header, message, footerBytes, implicitAssertionBytes);

    // 6
    verifySignature(publicKey, m2, signature);

    return new String(message, UTF_8);
  }

  private static void verifySignature(EdECPublicKey key, byte[] m2, byte[] signature)
      throws SignatureException {
    if (!CryptoFunctions.verify(key, m2, signature)) {
      throw new SignatureException("Invalid signature");
    }
  }
}
