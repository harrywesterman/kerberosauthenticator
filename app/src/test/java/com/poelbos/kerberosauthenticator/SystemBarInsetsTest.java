package com.poelbos.kerberosauthenticator;

import static com.google.common.truth.Truth.assertThat;

import android.content.Context;
import android.view.View;
import android.view.ViewGroup;
import androidx.core.graphics.Insets;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowInsetsCompat;
import androidx.test.core.app.ApplicationProvider;
import java.lang.reflect.Method;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;

@RunWith(RobolectricTestRunner.class)
@Config(sdk = 35)
public final class SystemBarInsetsTest {
  @Test
  public void topAppBarKeepsItsHeightBelowTheStatusBar() throws Exception {
    Context context = ApplicationProvider.getApplicationContext();
    View appBar = new View(context);
    appBar.setLayoutParams(new ViewGroup.LayoutParams(300, 192));
    appBar.setPadding(4, 6, 8, 10);

    Class<?> insetsClass = Class.forName(
        "com.poelbos.kerberosauthenticator.SystemBarInsets");
    Method apply = insetsClass.getDeclaredMethod("applyToTopAppBar", View.class);
    apply.invoke(null, appBar);
    WindowInsetsCompat insets = new WindowInsetsCompat.Builder()
        .setInsets(WindowInsetsCompat.Type.statusBars(), Insets.of(0, 72, 0, 0))
        .build();

    ViewCompat.dispatchApplyWindowInsets(appBar, insets);

    assertThat(appBar.getPaddingTop()).isEqualTo(78);
    assertThat(appBar.getLayoutParams().height).isEqualTo(264);
    assertThat(appBar.getPaddingLeft()).isEqualTo(4);
    assertThat(appBar.getPaddingRight()).isEqualTo(8);
    assertThat(appBar.getPaddingBottom()).isEqualTo(10);
  }
}
