package com.poelbos.kerberosauthenticator.internal;

import static org.junit.Assert.*;
import android.content.Context;
import android.content.RestrictionsManager;
import android.os.Bundle;
import androidx.test.core.app.ApplicationProvider;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;
import static org.robolectric.Shadows.shadowOf;

@RunWith(RobolectricTestRunner.class)
@Config(sdk=26)
public class HttpSpnSettingsTest {
 @Test public void exactShellMappingIsRealmBoundAndEnablesBindingOnlyExplicitly() {
  Context context=ApplicationProvider.getApplicationContext();
  HttpSpnSettings.setForShell(context,"EXAMPLE.COM","portal.example.com","web.example.com",true);
  HttpSpnSettings.Mapping mapping=HttpSpnSettings.get(context,"EXAMPLE.COM","portal.example.com");
  assertEquals("web.example.com",mapping.host);assertTrue(mapping.tlsBinding);
  assertNull(HttpSpnSettings.get(context,"OTHER.COM","portal.example.com"));
  assertNull(HttpSpnSettings.get(context,"EXAMPLE.COM","other.example.com"));
  assertThrows(IllegalArgumentException.class,()->HttpSpnSettings.setForShell(context,"EXAMPLE.COM","portal.example.com","evil.other.com",true));
  HttpSpnSettings.clearForShell(context,"EXAMPLE.COM","portal.example.com");
  assertNull(HttpSpnSettings.get(context,"EXAMPLE.COM","portal.example.com"));
 }
 @Test public void managedConfigurationTakesPrecedenceIncludingInvalidDuplicates() {
  Context context=ApplicationProvider.getApplicationContext();
  HttpSpnSettings.setForShell(context,"EXAMPLE.COM","portal.example.com","local.example.com",true);
  Bundle item=new Bundle();item.putString("request_host","portal.example.com");item.putString("spn_host","managed.example.com");
  Bundle restrictions=new Bundle();restrictions.putParcelableArray("http_spn_mappings",new Bundle[]{item});
  RestrictionsManager rm=(RestrictionsManager)context.getSystemService(Context.RESTRICTIONS_SERVICE);
  shadowOf(rm).setApplicationRestrictions(restrictions);
  HttpSpnSettings.Mapping mapping=HttpSpnSettings.get(context,"EXAMPLE.COM","portal.example.com");
  assertEquals("managed.example.com",mapping.host);assertFalse(mapping.tlsBinding);
  item.putBoolean("tls_channel_binding",true);
  shadowOf(rm).setApplicationRestrictions(restrictions);
  assertTrue(HttpSpnSettings.get(context,"EXAMPLE.COM","portal.example.com").tlsBinding);
  restrictions.putParcelableArray("http_spn_mappings",new Bundle[]{item,item});
  shadowOf(rm).setApplicationRestrictions(restrictions);
  assertNull(HttpSpnSettings.get(context,"EXAMPLE.COM","portal.example.com"));
 }
}
