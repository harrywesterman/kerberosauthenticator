package com.poelbos.kerberosauthenticator;

import static org.junit.Assert.*;
import android.content.ComponentName;
import android.content.Context;
import android.content.pm.ActivityInfo;
import androidx.test.core.app.ApplicationProvider;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;

@RunWith(RobolectricTestRunner.class)
@Config(sdk=26)
public class HttpKerberosProbeReceiverTest {
 @Test public void diagnosticIsProtectedBySystemDumpPermission() throws Exception {
  Context context=ApplicationProvider.getApplicationContext();
  ActivityInfo receiver=context.getPackageManager().getReceiverInfo(
      new ComponentName(context,HttpKerberosProbeReceiver.class),0);
  assertTrue(receiver.exported);
  assertEquals("android.permission.DUMP",receiver.permission);
 }
}
