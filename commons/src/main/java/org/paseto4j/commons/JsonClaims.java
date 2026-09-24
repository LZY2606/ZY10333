/*
 * SPDX-FileCopyrightText: Copyright © 2026 Nanne Baars
 * SPDX-License-Identifier: MIT
 */
package org.paseto4j.commons;

import java.math.BigDecimal;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Minimal JSON parser extracting the top-level claims of a JSON object. Keeps the library free of
 * a JSON dependency; only what claim validation needs is modelled: textual and numeric values are
 * captured, literals and nested structures are skipped but validated for well-formedness.
 */
final class JsonClaims {

  sealed interface Value permits Text, Number, Other {}

  record Text(String value) implements Value {}

  record Number(BigDecimal value) implements Value {}

  /** Literals, arrays and nested objects: syntactically valid but not a scalar claim value. */
  enum Other implements Value {
    INSTANCE
  }

  private JsonClaims() {}

  /**
   * Parses the given string as a JSON object.
   *
   * @throws PasetoException if the input is not a well-formed JSON object
   */
  static Map<String, Value> parseObject(String json) {
    Parser parser = new Parser(json);
    Map<String, Value> claims = parser.parseObject();
    parser.skipWhitespace();
    if (!parser.isAtEnd()) {
      throw invalid();
    }
    return claims;
  }

  private static PasetoException invalid() {
    return new PasetoException("Payload is not a well-formed JSON object");
  }

  private static final class Parser {

    private final String input;
    private int position;

    Parser(String input) {
      this.input = input;
    }

    boolean isAtEnd() {
      return position >= input.length();
    }

    void skipWhitespace() {
      while (!isAtEnd()) {
        char c = input.charAt(position);
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
          position++;
        } else {
          break;
        }
      }
    }

    Map<String, Value> parseObject() {
      skipWhitespace();
      expect('{');
      Map<String, Value> claims = new LinkedHashMap<>();
      skipWhitespace();
      if (peek('}')) {
        position++;
        return claims;
      }
      while (true) {
        skipWhitespace();
        String name = parseString();
        skipWhitespace();
        expect(':');
        claims.put(name, parseValue());
        skipWhitespace();
        if (peek(',')) {
          position++;
          continue;
        }
        expect('}');
        return claims;
      }
    }

    private Value parseValue() {
      skipWhitespace();
      if (isAtEnd()) {
        throw invalid();
      }
      char c = input.charAt(position);
      return switch (c) {
        case '"' -> new Text(parseString());
        case '{' -> {
          parseObject();
          yield Other.INSTANCE;
        }
        case '[' -> {
          parseArray();
          yield Other.INSTANCE;
        }
        case 't' -> {
          expectLiteral("true");
          yield Other.INSTANCE;
        }
        case 'f' -> {
          expectLiteral("false");
          yield Other.INSTANCE;
        }
        case 'n' -> {
          expectLiteral("null");
          yield Other.INSTANCE;
        }
        default -> new Number(parseNumber());
      };
    }

    private void parseArray() {
      expect('[');
      skipWhitespace();
      if (peek(']')) {
        position++;
        return;
      }
      while (true) {
        parseValue();
        skipWhitespace();
        if (peek(',')) {
          position++;
          continue;
        }
        expect(']');
        return;
      }
    }

    private String parseString() {
      expect('"');
      StringBuilder result = new StringBuilder();
      while (true) {
        if (isAtEnd()) {
          throw invalid();
        }
        char c = input.charAt(position++);
        if (c == '"') {
          return result.toString();
        }
        if (c == '\\') {
          result.append(parseEscape());
        } else {
          if (c < 0x20) {
            throw invalid();
          }
          result.append(c);
        }
      }
    }

    private char parseEscape() {
      if (isAtEnd()) {
        throw invalid();
      }
      char c = input.charAt(position++);
      return switch (c) {
        case '"', '\\', '/' -> c;
        case 'b' -> '\b';
        case 'f' -> '\f';
        case 'n' -> '\n';
        case 'r' -> '\r';
        case 't' -> '\t';
        case 'u' -> parseUnicodeEscape();
        default -> throw invalid();
      };
    }

    private char parseUnicodeEscape() {
      if (position + 4 > input.length()) {
        throw invalid();
      }
      int codePoint = 0;
      for (int i = 0; i < 4; i++) {
        int digit = Character.digit(input.charAt(position++), 16);
        if (digit < 0) {
          throw invalid();
        }
        codePoint = codePoint * 16 + digit;
      }
      return (char) codePoint;
    }

    private BigDecimal parseNumber() {
      int start = position;
      if (peek('-')) {
        position++;
      }
      readDigits();
      if (peek('.')) {
        position++;
        readDigits();
      }
      if (peek('e') || peek('E')) {
        position++;
        if (peek('+') || peek('-')) {
          position++;
        }
        readDigits();
      }
      if (start == position) {
        throw invalid();
      }
      try {
        return new BigDecimal(input.substring(start, position));
      } catch (NumberFormatException e) {
        throw invalid();
      }
    }

    private void readDigits() {
      int start = position;
      while (!isAtEnd() && Character.isDigit(input.charAt(position))) {
        position++;
      }
      if (start == position) {
        throw invalid();
      }
    }

    private void expectLiteral(String literal) {
      if (!input.startsWith(literal, position)) {
        throw invalid();
      }
      position += literal.length();
    }

    private boolean peek(char expected) {
      return !isAtEnd() && input.charAt(position) == expected;
    }

    private void expect(char expected) {
      if (isAtEnd() || input.charAt(position) != expected) {
        throw invalid();
      }
      position++;
    }
  }
}
