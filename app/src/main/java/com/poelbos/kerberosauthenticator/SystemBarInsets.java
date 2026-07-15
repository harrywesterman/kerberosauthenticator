package com.poelbos.kerberosauthenticator;

import android.view.View;
import android.view.ViewGroup;
import androidx.core.graphics.Insets;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowInsetsCompat;

/** Keeps app-bar content below the transparent Android 15 status bar. */
public final class SystemBarInsets {
  private SystemBarInsets() {}

  public static void applyToTopAppBar(View appBar) {
    int initialLeft = appBar.getPaddingLeft();
    int initialTop = appBar.getPaddingTop();
    int initialRight = appBar.getPaddingRight();
    int initialBottom = appBar.getPaddingBottom();
    int initialHeight = appBar.getLayoutParams().height;
    ViewCompat.setOnApplyWindowInsetsListener(appBar, (view, windowInsets) -> {
      Insets statusBars = windowInsets.getInsets(WindowInsetsCompat.Type.statusBars());
      view.setPadding(
          initialLeft,
          initialTop + statusBars.top,
          initialRight,
          initialBottom);
      if (initialHeight >= 0) {
        ViewGroup.LayoutParams layoutParams = view.getLayoutParams();
        layoutParams.height = initialHeight + statusBars.top;
        view.setLayoutParams(layoutParams);
      }
      return windowInsets;
    });
    ViewCompat.requestApplyInsets(appBar);
  }
}
