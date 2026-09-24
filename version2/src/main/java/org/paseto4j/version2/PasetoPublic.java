/*
 * SPDX-FileCopyrightText: Copyright © 2018 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.version2;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Objects.requireNonNull;
import static org.paseto4j.commons.ByteUtils.concat;
import static org.paseto4j.commons.PreAuthenticationEncoder.encode;
import static org.paseto4j.commons.Purpose.PURPOSE_PUBLIC;
import static org.paseto4j.commons.Version.V2;

import com.goterl.lazysodium.LazySodiumJava;
import com.goterl.lazysodium.SodiumJava;
import java.security.SignatureException;
import java.util.Arrays;
import org.paseto4j.commons.PasetoException;
import org.paseto4j.commons.PreAuthenticationEncoder;
import org.paseto4j.commons.TokenOut;
import org.paseto4j.commons.TokenValidator;
import org.paseto4j.commons.ValidatedToken;
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
    return parse(publicKey, signedMessage, ValidationPolicy.legacy(footer));
  }

  /**
   * Verify the token after applying the given validation policy. All policy checks run before
   * any cryptographic operation.
   */
  public static String parse(PublicKey publicKey, String signedMessage, ValidationPolicy policy)
      throws SignatureException {
    requireNonNull(publicKey);
    requireNonNull(signedMessage);
    requireNonNull(policy);

    ValidatedToken pasetoToken = TokenValidator.parse(signedMessage, V2, PURPOSE_PUBLIC, policy, "");

    // 3
    byte[] sm = pasetoToken.payload();
    if (sm.length < 64) {
      throw new PasetoException("Invalid token payload");
    }
    byte[] signature = Arrays.copyOfRange(sm, sm.length - 64, sm.length);
    byte[] message = Arrays.copyOfRange(sm, 0, sm.length - 64);

    // 4
    byte[] m2 =
        PreAuthenticationEncoder.encode(pasetoToken.header(), message, pasetoToken.footer());

    // 5
    verifySignature(publicKey, m2, signature);

    String payload = new String(message, UTF_8);
    TokenValidator.validateClaims(payload, policy);
    return payload;
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
