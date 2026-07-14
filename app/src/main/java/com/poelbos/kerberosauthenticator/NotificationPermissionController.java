package com.poelbos.kerberosauthenticator;

import android.Manifest;
import android.app.Activity;
import android.content.Context;
import android.content.pm.PackageManager;
import android.os.Build;

/** Requests sign-in alert permission once from a visible activity and exposes its current state. */
public final class NotificationPermissionController {
  private static final String PREFS = "notification_permission_state";
  private static final String ASKED = "asked";
  private static final int REQUEST_CODE = 7002;

  private NotificationPermissionController() {}

  public static void requestIfNeeded(Activity activity) {
    if (Build.VERSION.SDK_INT < 33 || isAllowed(activity)) return;
    android.content.SharedPreferences prefs =
        activity.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
    if (prefs.getBoolean(ASKED, false)) return;
    prefs.edit().putBoolean(ASKED, true).apply();
    activity.requestPermissions(
        new String[] {Manifest.permission.POST_NOTIFICATIONS}, REQUEST_CODE);
  }

  public static boolean isAllowed(Context context) {
    return Build.VERSION.SDK_INT < 33
        || context.checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS)
            == PackageManager.PERMISSION_GRANTED;
  }
}
