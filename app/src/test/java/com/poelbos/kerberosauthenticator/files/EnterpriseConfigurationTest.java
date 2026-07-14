package com.poelbos.kerberosauthenticator.files;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import android.os.Bundle;
import android.os.Parcelable;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;

@RunWith(RobolectricTestRunner.class)
@Config(sdk = 35)
public final class EnterpriseConfigurationTest {
  @Test public void parsesManagedShareAndSecurityPolicy() {
    Bundle share = new Bundle();
    share.putString("id", "documents");
    share.putString("display_name", "Documents");
    share.putString("host", "files.example.com");
    share.putString("share_name", "Documents");
    Bundle restrictions = new Bundle();
    restrictions.putString("ad_realm", "example.com");
    restrictions.putParcelableArray("shares", new Parcelable[] {share});
    restrictions.putBoolean("require_smb_encryption", true);

    EnterpriseConfiguration configuration = EnterpriseConfiguration.from(restrictions);

    assertTrue(configuration.isValid());
    assertEquals("EXAMPLE.COM", configuration.getRealm());
    assertEquals(1, configuration.getShares().size());
    assertEquals(445, configuration.getShares().get(0).getPort());
    assertTrue(configuration.isRequireEncryption());
    assertFalse(configuration.isAllowCache());
    assertFalse(configuration.isAllowScreenshots());
  }

  @Test public void securityDefaultsFailClosedAndExplicitOverridesRemainSupported() {
    Bundle restrictions = new Bundle();
    restrictions.putString("ad_realm", "EXAMPLE.COM");
    restrictions.putParcelableArray("shares", new Parcelable[] {share("docs", "Docs")});

    EnterpriseConfiguration secure = EnterpriseConfiguration.from(restrictions);
    assertTrue(secure.isRequireEncryption());
    assertFalse(secure.isAllowCache());

    restrictions.putBoolean("require_smb_encryption", false);
    restrictions.putBoolean("allow_local_cache", true);
    EnterpriseConfiguration legacy = EnterpriseConfiguration.from(restrictions);
    assertFalse(legacy.isRequireEncryption());
    assertTrue(legacy.isAllowCache());
  }

  @Test public void invalidConfigurationExplainsAllMissingInputs() {
    EnterpriseConfiguration configuration = EnterpriseConfiguration.from(new Bundle());
    assertFalse(configuration.isValid());
    assertEquals(2, configuration.getErrors().size());
  }

  @Test public void duplicateShareIdsFailClosed() {
    Bundle first = share("same", "First");
    Bundle second = share("same", "Second");
    Bundle restrictions = new Bundle();
    restrictions.putString("ad_realm", "EXAMPLE.COM");
    restrictions.putParcelableArray("shares", new Parcelable[] {first, second});
    EnterpriseConfiguration configuration = EnterpriseConfiguration.from(restrictions);
    assertFalse(configuration.isValid());
    assertEquals(1, configuration.getShares().size());
  }

  @Test public void preservesManagedStartPathTemplateUntilAccountIsKnown() {
    Bundle templatedShare = share("home", "Home");
    templatedShare.putString(
        "start_path", "users\\${username:last:1}\\${username}");
    Bundle restrictions = new Bundle();
    restrictions.putString("ad_realm", "EXAMPLE.COM");
    restrictions.putParcelableArray("shares", new Parcelable[] {templatedShare});

    EnterpriseConfiguration configuration = EnterpriseConfiguration.from(restrictions);

    assertTrue(configuration.isValid());
    assertEquals(
        "users\\${username:last:1}\\${username}",
        configuration.getShares().get(0).getStartPath());
  }

  private static Bundle share(String id, String name) {
    Bundle share = new Bundle();
    share.putString("id", id);
    share.putString("display_name", name);
    share.putString("host", "files.example.com");
    share.putString("share_name", "Documents");
    return share;
  }
}
