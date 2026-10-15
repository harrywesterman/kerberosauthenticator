/*
 * Copyright 2019 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 */
package com.poelbos.kerberosauthenticator;

import static org.robolectric.Shadows.shadowOf;

import android.content.ContextWrapper;
import android.content.RestrictionsManager;
import androidx.test.core.app.ApplicationProvider;
import com.poelbos.kerberosauthenticator.internal.TicketRequestResult;
import com.poelbos.kerberosauthenticator.internal.TicketRequestResult.ResultCode;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.Robolectric;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.android.controller.ActivityController;
import org.robolectric.annotation.Config;

@RunWith(RobolectricTestRunner.class)
@Config(sdk = 26)
public class ServiceTicketActivityTest {
  private ContextWrapper context;
  private RestrictionsManager restrictionsManager;

  @Before
  public void setUp() {
    context = ApplicationProvider.getApplicationContext();
    restrictionsManager = (RestrictionsManager) context.getSystemService(
        context.getSystemServiceName(RestrictionsManager.class));
    shadowOf(restrictionsManager).setApplicationRestrictions(TestHelper.makeRestrictionsBundle());
  }

  @Test
  public void serviceTicketActivityCannotBeStartedByOtherApps() throws Exception {
    android.content.Context app = ApplicationProvider.getApplicationContext();
    android.content.pm.ActivityInfo info = app.getPackageManager().getActivityInfo(
        new android.content.ComponentName(app, ServiceTicketActivity.class), 0);
    org.junit.Assert.assertFalse(info.exported);
  }

  @Test
  public void disabledHttpKerberosRejectsInternalTicketActivity() {
    android.os.Bundle managed = TestHelper.makeRestrictionsBundle();
    managed.putBoolean("enable_http_kerberos", false);
    shadowOf(restrictionsManager).setApplicationRestrictions(managed);
    ServiceTicketActivity activity = Robolectric.buildActivity(ServiceTicketActivity.class)
        .create().get();
    org.junit.Assert.assertTrue(activity.isFinishing());
  }

  @Test
  public void testServiceTicketResultWithMissingAccountDoesNotCrash() {
    ActivityController<ServiceTicketActivity> controller =
        Robolectric.buildActivity(ServiceTicketActivity.class).create().start();
    ServiceTicketActivity activity = controller.get();

    activity.onServiceTicketResult(
        "test-server.example.com",
        new TicketRequestResult(ResultCode.SUCCESS, "ok"),
        "ticket");
  }
}
