/* Copyright 2026 */
package com.poelbos.kerberosauthenticator.internal;

import static com.google.common.truth.Truth.assertThat;
import static org.robolectric.Shadows.shadowOf;

import android.content.Context;
import android.content.RestrictionsManager;
import android.os.Bundle;
import androidx.test.core.app.ApplicationProvider;
import java.util.Arrays;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;

@RunWith(RobolectricTestRunner.class)
public final class SpnResolverTest {
  private final Context context = ApplicationProvider.getApplicationContext();

  @Test
  public void resolveUsesManagedMappingThenRequestCnameAndLdap() {
    setMappings(mapping("Portal.Example.Com.", "WEB01.EXAMPLE.COM"));

    assertThat(
            SpnResolver.resolve(
                context,
                "EXAMPLE.COM",
                "Portal.Example.Com.",
                Arrays.asList("edge.example.com", "web01.example.com"),
                Arrays.asList("web02.example.com", "edge.example.com")))
        .containsExactly(
            "web01.example.com",
            "portal.example.com",
            "edge.example.com",
            "web02.example.com")
        .inOrder();
  }

  @Test
  public void normalizeRejectsUnsafeAndCrossRealmNames() {
    assertThat(SpnResolver.normalizeHost("https://portal.example.com", "EXAMPLE.COM")).isNull();
    assertThat(SpnResolver.normalizeHost("*.example.com", "EXAMPLE.COM")).isNull();
    assertThat(SpnResolver.normalizeHost("10.0.0.1", "EXAMPLE.COM")).isNull();
    assertThat(SpnResolver.normalizeHost("portal.other.com", "EXAMPLE.COM"))
        .isEqualTo("portal.other.com");
  }

  @Test
  public void normalizeConvertsInternationalHostToAscii() {
    assertThat(SpnResolver.normalizeHost("büro.example.com.", "example.com"))
        .isEqualTo("xn--bro-hoa.example.com");
  }

  @Test
  public void duplicateManagedRequestHostsAreIgnored() {
    setMappings(
        mapping("portal.example.com", "web01.example.com"),
        mapping("PORTAL.EXAMPLE.COM", "web02.example.com"));

    assertThat(
            SpnResolver.resolve(
                context, "EXAMPLE.COM", "portal.example.com", null, null))
        .containsExactly("portal.example.com");
  }

  private Bundle mapping(String request, String target) {
    Bundle result = new Bundle();
    result.putString(SpnResolver.REQUEST_HOST_KEY, request);
    result.putString(SpnResolver.SPN_HOST_KEY, target);
    return result;
  }

  private void setMappings(Bundle... mappings) {
    RestrictionsManager manager =
        (RestrictionsManager) context.getSystemService(Context.RESTRICTIONS_SERVICE);
    Bundle restrictions = new Bundle();
    restrictions.putParcelableArray(SpnResolver.MAPPINGS_KEY, mappings);
    shadowOf(manager).setApplicationRestrictions(restrictions);
  }
}
