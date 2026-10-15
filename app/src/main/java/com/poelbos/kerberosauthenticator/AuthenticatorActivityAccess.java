package com.poelbos.kerberosauthenticator;

import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;

/** Single-use capabilities for authenticator UI intents delivered through AccountManager. */
final class AuthenticatorActivityAccess {
  private static final String PREFS = "authenticator_activity_requests";
  private static final String EXTRA = "authenticator_activity_capability";
  private static final long TTL_MILLIS = 300_000;
  private static final SecureRandom RANDOM = new SecureRandom();

  private AuthenticatorActivityAccess() {}

  static synchronized Intent authorize(Context context, Intent intent) {
    SharedPreferences preferences = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
    long now = System.currentTimeMillis();
    SharedPreferences.Editor editor = preferences.edit();
    int pending = 0;
    for (java.util.Map.Entry<String, ?> entry : preferences.getAll().entrySet()) {
      if (!(entry.getValue() instanceof String)
          || !validTime((String) entry.getValue(), now)) editor.remove(entry.getKey());
      else pending++;
    }
    if (pending >= 32) throw new IllegalStateException("Too many pending sign-in requests");
    byte[] random = new byte[32];
    RANDOM.nextBytes(random);
    String token = android.util.Base64.encodeToString(random, android.util.Base64.NO_WRAP);
    if (!editor.putString(token, (now + TTL_MILLIS) + "|" + scope(intent)).commit())
      throw new IllegalStateException("Cannot authorize sign-in request");
    return intent.putExtra(EXTRA, token);
  }

  static synchronized boolean consume(Context context, Intent intent) {
    String token = intent.getStringExtra(EXTRA);
    if (token == null) return false;
    SharedPreferences preferences = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
    String request = preferences.getString(token, null);
    if (!preferences.edit().remove(token).commit()) return false;
    return request != null && validTime(request, System.currentTimeMillis())
        && request.substring(request.indexOf('|') + 1).equals(scope(intent));
  }

  private static boolean validTime(String request, long now) {
    try {
      long expires = Long.parseLong(request.substring(0, request.indexOf('|')));
      return expires > now && expires <= now + TTL_MILLIS;
    } catch (RuntimeException invalid) { return false; }
  }

  private static String scope(Intent intent) {
    String service = intent.getStringExtra(Constants.SERVICE_NAME);
    String fields = (service == null ? "-" : service.length() + ":" + service)
        + "|" + intent.getBooleanExtra(LoginActivity.RETURN_TO_ACCOUNT, false)
        + "|" + intent.getBooleanExtra(Constants.REFRESH_STATUS_AFTER_AUTH, false);
    try {
      return android.util.Base64.encodeToString(MessageDigest.getInstance("SHA-256")
          .digest(fields.getBytes(StandardCharsets.UTF_8)), android.util.Base64.NO_WRAP);
    } catch (java.security.NoSuchAlgorithmException impossible) {
      throw new AssertionError(impossible);
    }
  }
}
