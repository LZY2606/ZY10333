/*
 * SPDX-FileCopyrightText: Copyright © 2025 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.version4;

import static java.nio.charset.StandardCharsets.UTF_8;
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
    return parse(publicKey, signedMessage, ValidationPolicy.legacy(footer), implicitAssertion);
  }

  /**
   * Verify the token after applying the given validation policy. All policy checks run before
   * any cryptographic operation.
   */
  public static String parse(
      EdECPublicKey publicKey, String signedMessage, ValidationPolicy policy, String implicitAssertion)
      throws SignatureException {
    requireNonNull(publicKey);
    requireNonNull(signedMessage);
    requireNonNull(policy);

    // 1 and 2
    ValidatedToken token =
        TokenValidator.parse(signedMessage, V4, PURPOSE_PUBLIC, policy, implicitAssertion);

    // 4
    byte[] sm = token.payload();
    if (sm.length < 64) {
      throw new PasetoException("Invalid token payload");
    }
    byte[] signature = Arrays.copyOfRange(sm, sm.length - 64, sm.length);
    byte[] message = Arrays.copyOfRange(sm, 0, sm.length - 64);

    // 5
    byte[] m2 =
        PreAuthenticationEncoder.encode(
            token.header(), message, token.footer(), implicitAssertion.getBytes(UTF_8));

    // 6
    verifySignature(publicKey, m2, signature);

    String payload = new String(message, UTF_8);
    TokenValidator.validateClaims(payload, policy);
    return payload;
  }

  private static void verifySignature(EdECPublicKey key, byte[] m2, byte[] signature)
      throws SignatureException {
    if (!CryptoFunctions.verify(key, m2, signature)) {
      throw new SignatureException("Invalid signature");
    }
  }
}
