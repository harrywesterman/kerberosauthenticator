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
