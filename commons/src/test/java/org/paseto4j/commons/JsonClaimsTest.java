/*
 * SPDX-FileCopyrightText: Copyright © 2026 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.commons;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigDecimal;
import java.util.Map;
import org.junit.jupiter.api.Test;

class JsonClaimsTest {

  @Test
  void parsesScalarClaims() {
    Map<String, JsonClaims.Value> claims =
        JsonClaims.parseObject("{\"iss\":\"paseto4j\",\"exp\":1767225600,\"admin\":true}");

    assertEquals(new JsonClaims.Text("paseto4j"), claims.get("iss"));
    assertEquals(new JsonClaims.Number(new BigDecimal("1767225600")), claims.get("exp"));
    assertInstanceOf(JsonClaims.Other.class, claims.get("admin"));
  }

  @Test
  void skipsNestedStructures() {
    Map<String, JsonClaims.Value> claims =
        JsonClaims.parseObject(
            "{\"nested\":{\"a\":[1,2,{\"b\":\"c\"}]},\"arr\":[\"x\",null],\"sub\":\"ok\"}");

    assertInstanceOf(JsonClaims.Other.class, claims.get("nested"));
    assertInstanceOf(JsonClaims.Other.class, claims.get("arr"));
    assertEquals(new JsonClaims.Text("ok"), claims.get("sub"));
  }

  @Test
  void handlesEscapesAndUnicode() {
    Map<String, JsonClaims.Value> claims =
        JsonClaims.parseObject("{\"msg\":\"a\\\"b\\\\c\\n\\u0041\"}");
    assertEquals(new JsonClaims.Text("a\"b\\c\nA"), claims.get("msg"));
  }

  @Test
  void handlesWhitespaceAndEmptyObject() {
    assertTrue(JsonClaims.parseObject(" { } ").isEmpty());
    assertTrue(JsonClaims.parseObject("{\n\t}").isEmpty());
  }

  @Test
  void rejectsMalformedInput() {
    assertThrows(PasetoException.class, () -> JsonClaims.parseObject("not json"));
    assertThrows(PasetoException.class, () -> JsonClaims.parseObject("[1,2]"));
    assertThrows(PasetoException.class, () -> JsonClaims.parseObject("{\"a\":}"));
    assertThrows(PasetoException.class, () -> JsonClaims.parseObject("{\"a\":1,}"));
    assertThrows(PasetoException.class, () -> JsonClaims.parseObject("{\"a\":\"unterminated}"));
    assertThrows(PasetoException.class, () -> JsonClaims.parseObject("{\"a\":tru}"));
    assertThrows(PasetoException.class, () -> JsonClaims.parseObject("{\"a\":01x}"));
    assertThrows(PasetoException.class, () -> JsonClaims.parseObject("{\"a\":1} trailing"));
  }
}
