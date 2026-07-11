package com.poelbos.kerberosauthenticator;

import android.app.KeyguardManager;
import android.content.Context;
import android.content.RestrictionsManager;
import android.os.Build;
import android.os.Bundle;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyInfo;
import android.security.keystore.KeyProperties;
import android.security.keystore.StrongBoxUnavailableException;
import android.util.Base64;
import android.util.Log;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;

/** Device-bound storage for the AD password. Plaintext is never persisted. */
public final class CredentialVault {
  private static final String ALIAS = "enterprise_ad_password_v1";
  private static final String PREFS = "encrypted_enterprise_credentials";
  private static final String IV = "iv";
  private static final String CIPHERTEXT = "ciphertext";
  private static final String IDENTITY = "identity";
  private static final String ANDROID_KEY_STORE = "AndroidKeyStore";
  private final Context context;

  public CredentialVault(Context context) {
    this.context = context.getApplicationContext();
  }

  public boolean store(String username, String realm, char[] password) {
    if (password == null || password.length == 0 || !isManagedAndDeviceSecure()) return false;
    try {
      SecretKey key = getOrCreateKey(true);
      if (!isHardwareBacked(key)) {
        delete();
        Log.w(Constants.TAG, "Persistent credentials refused: Keystore key is not hardware-backed");
        return false;
      }
      Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
      cipher.init(Cipher.ENCRYPT_MODE, key);
      String identity = identity(username, realm);
      cipher.updateAAD(identity.getBytes(StandardCharsets.UTF_8));
      byte[] plaintext = new String(password).getBytes(StandardCharsets.UTF_8);
      byte[] encrypted;
      try {
        encrypted = cipher.doFinal(plaintext);
      } finally {
        java.util.Arrays.fill(plaintext, (byte) 0);
      }
      context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
          .putString(IV, Base64.encodeToString(cipher.getIV(), Base64.NO_WRAP))
          .putString(CIPHERTEXT, Base64.encodeToString(encrypted, Base64.NO_WRAP))
          .putString(IDENTITY, identity)
          .commit();
      return true;
    } catch (Exception exception) {
      Log.w(Constants.TAG, "Unable to store device-bound credentials", exception);
      delete();
      return false;
    }
  }

  public char[] load(String username, String realm) {
    try {
      String identity = identity(username, realm);
      android.content.SharedPreferences prefs =
          context.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
      if (!identity.equals(prefs.getString(IDENTITY, null))) return null;
      String iv = prefs.getString(IV, null);
      String ciphertext = prefs.getString(CIPHERTEXT, null);
      if (iv == null || ciphertext == null) return null;
      SecretKey key = getOrCreateKey(false);
      if (key == null || !isHardwareBacked(key)) return null;
      Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
      cipher.init(Cipher.DECRYPT_MODE, key,
          new GCMParameterSpec(128, Base64.decode(iv, Base64.NO_WRAP)));
      cipher.updateAAD(identity.getBytes(StandardCharsets.UTF_8));
      byte[] clear = cipher.doFinal(Base64.decode(ciphertext, Base64.NO_WRAP));
      try {
        return new String(clear, StandardCharsets.UTF_8).toCharArray();
      } finally {
        java.util.Arrays.fill(clear, (byte) 0);
      }
    } catch (Exception exception) {
      Log.w(Constants.TAG, "Stored credentials are unavailable or invalid", exception);
      delete();
      return null;
    }
  }

  public boolean hasCredentials() {
    return context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).contains(CIPHERTEXT);
  }

  public void delete() {
    context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().clear().commit();
    try {
      KeyStore store = KeyStore.getInstance(ANDROID_KEY_STORE);
      store.load(null);
      if (store.containsAlias(ALIAS)) store.deleteEntry(ALIAS);
    } catch (Exception exception) {
      Log.w(Constants.TAG, "Unable to delete credential key", exception);
    }
  }

  private boolean isManagedAndDeviceSecure() {
    RestrictionsManager manager =
        (RestrictionsManager) context.getSystemService(Context.RESTRICTIONS_SERVICE);
    Bundle restrictions = manager == null ? null : manager.getApplicationRestrictions();
    boolean managed = restrictions != null
        && !restrictions.getString("ad_realm", "").trim().isEmpty()
        && restrictions.containsKey("shares");
    KeyguardManager keyguard = (KeyguardManager) context.getSystemService(Context.KEYGUARD_SERVICE);
    return managed && keyguard != null && keyguard.isDeviceSecure();
  }

  private SecretKey getOrCreateKey(boolean create) throws Exception {
    KeyStore store = KeyStore.getInstance(ANDROID_KEY_STORE);
    store.load(null);
    java.security.Key key = store.getKey(ALIAS, null);
    if (key instanceof SecretKey) return (SecretKey) key;
    if (!create) return null;
    if (Build.VERSION.SDK_INT >= 28) {
      try {
        return generateKey(true);
      } catch (StrongBoxUnavailableException exception) {
        Log.i(Constants.TAG, "StrongBox unavailable; using hardware-backed Android Keystore");
      }
    }
    return generateKey(false);
  }

  private static SecretKey generateKey(boolean strongBox) throws Exception {
    KeyGenerator generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES,
        ANDROID_KEY_STORE);
    KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(ALIAS,
        KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
        .setKeySize(256)
        .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
        .setRandomizedEncryptionRequired(true);
    if (Build.VERSION.SDK_INT >= 28) builder.setIsStrongBoxBacked(strongBox);
    generator.init(builder.build());
    return generator.generateKey();
  }

  private static boolean isHardwareBacked(SecretKey key) {
    try {
      SecretKeyFactory factory = SecretKeyFactory.getInstance(key.getAlgorithm(), ANDROID_KEY_STORE);
      KeyInfo info = (KeyInfo) factory.getKeySpec(key, KeyInfo.class);
      return info.isInsideSecureHardware();
    } catch (Exception exception) {
      return false;
    }
  }

  private static String identity(String username, String realm) {
    return username.trim() + "@" + realm.trim().toUpperCase(java.util.Locale.ROOT);
  }
}
