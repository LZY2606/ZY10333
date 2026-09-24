/*
 * SPDX-FileCopyrightText: Copyright © 2018 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.version1;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Objects.requireNonNull;
import static org.paseto4j.commons.Purpose.PURPOSE_PUBLIC;
import static org.paseto4j.commons.Version.V1;

import java.security.SignatureException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import org.paseto4j.commons.ByteUtils;
import org.paseto4j.commons.PasetoException;
import org.paseto4j.commons.PreAuthenticationEncoder;
import org.paseto4j.commons.TokenOut;
import org.paseto4j.commons.TokenValidator;
import org.paseto4j.commons.ValidatedToken;
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
    return parse(publicKey, signedMessage, ValidationPolicy.legacy(footer));
  }

  /**
   * Verify the token after applying the given validation policy. All policy checks run before
   * any cryptographic operation.
   */
  public static String parse(RSAPublicKey publicKey, String signedMessage, ValidationPolicy policy)
      throws SignatureException {
    requireNonNull(publicKey);
    requireNonNull(signedMessage);
    requireNonNull(policy);

    // 1 & 2
    ValidatedToken token = TokenValidator.parse(signedMessage, V1, PURPOSE_PUBLIC, policy, "");

    // 3
    byte[] sm = token.payload();
    if (sm.length < 256) {
      throw new PasetoException("Invalid token payload");
    }
    byte[] signature = Arrays.copyOfRange(sm, sm.length - 256, sm.length);
    byte[] message = Arrays.copyOfRange(sm, 0, sm.length - 256);

    // 4
    byte[] m2 = PreAuthenticationEncoder.encode(token.header(), message, token.footer());

    // 5
    verifySignature(publicKey, m2, signature);

    String payload = new String(message, UTF_8);
    TokenValidator.validateClaims(payload, policy);
    return payload;
  }

  private static void verifySignature(RSAPublicKey key, byte[] m2, byte[] signature)
      throws SignatureException {
    if (!CryptoFunctions.verifyRsaPssSha384(key, m2, signature)) {
      throw new SignatureException("Invalid signature");
    }
  }
}
