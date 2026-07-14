package com.poelbos.kerberosauthenticator;

import android.app.KeyguardManager;
import android.content.Context;
import android.content.RestrictionsManager;
import android.os.Bundle;
import android.os.Build;
import android.os.UserManager;
import androidx.annotation.VisibleForTesting;

/** Determines whether long-lived enterprise credentials may exist in the current Android user. */
public final class ManagedEnvironmentPolicy {
  private ManagedEnvironmentPolicy() {}

  public static boolean allowsPersistentCredentials(Context context, boolean hardwareBackedKey) {
    Context appContext = context.getApplicationContext();
    boolean managedRealm = hasManagedRealm(appContext);
    if (!managedRealm || !isDeviceSecure(appContext) || !hardwareBackedKey) return false;
    // A work-profile user is directly observable. On a fully managed primary user Android does not
    // expose another package's device-owner status through the public SDK; application restrictions
    // delivered by RestrictionsManager are the authoritative administrator-controlled signal.
    return isManagedProfile(appContext) || managedRealm;
  }

  private static boolean isDeviceSecure(Context context) {
    KeyguardManager keyguard =
        (KeyguardManager) context.getSystemService(Context.KEYGUARD_SERVICE);
    return keyguard != null && keyguard.isDeviceSecure();
  }

  static boolean hasManagedRealm(Context context) {
    RestrictionsManager manager =
        (RestrictionsManager) context.getSystemService(Context.RESTRICTIONS_SERVICE);
    if (manager == null) return false;
    Bundle restrictions = manager.getApplicationRestrictions();
    if (restrictions == null) return false;
    String realm = restrictions.getString("ad_realm");
    return realm != null && !realm.trim().isEmpty();
  }

  private static boolean isManagedProfile(Context context) {
    try {
      if (Build.VERSION.SDK_INT < 30) return false;
      UserManager users = (UserManager) context.getSystemService(Context.USER_SERVICE);
      return users != null && users.isManagedProfile();
    } catch (RuntimeException unavailable) {
      return false;
    }
  }

  @VisibleForTesting
  static boolean evaluate(
      boolean hasManagedRealm,
      boolean managedProfile,
      boolean deviceManaged,
      boolean deviceSecure,
      boolean hardwareBackedKey) {
    return hasManagedRealm && (managedProfile || deviceManaged) && deviceSecure && hardwareBackedKey;
  }
}
