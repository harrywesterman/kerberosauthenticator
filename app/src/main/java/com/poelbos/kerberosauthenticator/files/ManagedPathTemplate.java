package com.poelbos.kerberosauthenticator.files;

/** Resolves the deliberately small template language supported by managed share paths. */
final class ManagedPathTemplate {
  private static final String USERNAME = "username";
  private static final String USERNAME_LAST_CHARACTER = "username:last:1";

  private ManagedPathTemplate() {}

  static String resolve(String template, String username) {
    String value = template == null ? "" : template;
    StringBuilder resolved = new StringBuilder();
    int offset = 0;
    while (offset < value.length()) {
      int placeholderStart = value.indexOf("${", offset);
      if (placeholderStart < 0) {
        resolved.append(value, offset, value.length());
        break;
      }
      resolved.append(value, offset, placeholderStart);
      int placeholderEnd = value.indexOf('}', placeholderStart + 2);
      if (placeholderEnd < 0) {
        throw new IllegalArgumentException(
            "The managed path contains an incomplete placeholder");
      }
      String placeholder = value.substring(placeholderStart + 2, placeholderEnd);
      resolved.append(resolvePlaceholder(placeholder, username));
      offset = placeholderEnd + 1;
    }
    return resolved.toString();
  }

  private static String resolvePlaceholder(String placeholder, String username) {
    if (!USERNAME.equals(placeholder) && !USERNAME_LAST_CHARACTER.equals(placeholder)) {
      throw new IllegalArgumentException(
          "The managed path contains an unsupported placeholder");
    }
    if (username == null || username.isEmpty()) {
      throw new IllegalArgumentException("The managed path requires a signed-in username");
    }
    if (USERNAME.equals(placeholder)) {
      return username;
    }
    char lastCharacter = username.charAt(username.length() - 1);
    if (lastCharacter < '0' || lastCharacter > '9') {
      throw new IllegalArgumentException(
          "The managed path requires a username ending in a digit");
    }
    return String.valueOf(lastCharacter);
  }
}
