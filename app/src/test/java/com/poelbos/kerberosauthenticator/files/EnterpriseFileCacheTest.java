package com.poelbos.kerberosauthenticator.files;

import static com.google.common.truth.Truth.assertThat;

import android.content.Context;
import androidx.test.core.app.ApplicationProvider;
import java.io.File;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;

@RunWith(RobolectricTestRunner.class)
public final class EnterpriseFileCacheTest {
  @Test public void createsUniqueSafeNamesAndCleansThemUp() throws Exception {
    Context context = ApplicationProvider.getApplicationContext();
    EnterpriseFileCache cache = new EnterpriseFileCache(context);
    cache.cleanup();

    File first = cache.create("home/share", "report?.pdf");
    File second = cache.create("home/share", "report?.pdf");
    assertThat(first.getName()).isNotEqualTo(second.getName());
    assertThat(first.getName()).doesNotContain("/");
    assertThat(first.createNewFile()).isTrue();
    assertThat(second.createNewFile()).isTrue();

    cache.cleanup();
    assertThat(first.exists()).isFalse();
    assertThat(second.exists()).isFalse();
  }
}
