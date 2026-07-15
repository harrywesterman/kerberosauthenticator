package com.poelbos.kerberosauthenticator.internal.spnego;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

import android.os.Bundle;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;

@RunWith(RobolectricTestRunner.class)
@Config(sdk = 26)
public final class SpnegoStateCodecTest {
  @Test
  public void kerberosStateRoundTrips() {
    SpnegoNegotiationState state =
        SpnegoNegotiationState.kerberos(
            "portal.example.com", "backend.example.com", new byte[] {1, 2, 3});

    SpnegoNegotiationState decoded =
        SpnegoStateCodec.decode(SpnegoStateCodec.encode(state), "portal.example.com");

    assertThat(decoded.getMechanism())
        .isEqualTo(SpnegoNegotiationState.Mechanism.KERBEROS);
    assertThat(decoded.getPhase())
        .isEqualTo(SpnegoNegotiationState.Phase.KERBEROS_CONTINUE);
    assertThat(decoded.getSelectedService()).isEqualTo("backend.example.com");
    assertThat(decoded.getKerberosContext()).isEqualTo(new byte[] {1, 2, 3});
  }

  @Test
  public void offeredStateCarriesOptimisticKerberosContext() {
    SpnegoNegotiationState state =
        SpnegoNegotiationState.offered(
            "portal.example.com", "backend.example.com", new byte[] {4, 5, 6}, true);

    SpnegoNegotiationState decoded =
        SpnegoStateCodec.decode(SpnegoStateCodec.encode(state), "portal.example.com");

    assertThat(decoded.getMechanism())
        .isEqualTo(SpnegoNegotiationState.Mechanism.UNSELECTED);
    assertThat(decoded.getSelectedService()).isEqualTo("backend.example.com");
    assertThat(decoded.getKerberosContext()).isEqualTo(new byte[] {4, 5, 6});
    assertThat(decoded.wasNtlmOffered()).isTrue();
  }

  @Test
  public void ntlmStateRoundTripsWithoutChallengeOrCredentials() {
    SpnegoNegotiationState state =
        SpnegoNegotiationState.ntlmType1Sent(
            "portal.example.com", new byte[] {0x4e, 0x54, 0x4c, 0x4d});

    Bundle encoded = SpnegoStateCodec.encode(state);
    SpnegoNegotiationState decoded =
        SpnegoStateCodec.decode(encoded, "portal.example.com");

    assertThat(decoded.getMechanism()).isEqualTo(SpnegoNegotiationState.Mechanism.NTLM);
    assertThat(decoded.getPhase()).isEqualTo(SpnegoNegotiationState.Phase.NTLM_TYPE1_SENT);
    assertThat(decoded.getNtlmType1()).isEqualTo(new byte[] {0x4e, 0x54, 0x4c, 0x4d});
    assertThat(encoded.keySet())
        .containsExactly("version", "host", "mechanism", "phase", "ntlmType1");
  }

  @Test
  public void stateIsBoundToRequestHost() {
    Bundle encoded =
        SpnegoStateCodec.encode(SpnegoNegotiationState.offered("one.example.com"));

    IllegalArgumentException error =
        assertThrows(
            IllegalArgumentException.class,
            () -> SpnegoStateCodec.decode(encoded, "two.example.com"));

    assertThat(error).hasMessageThat().contains("host");
  }

  @Test
  public void rejectsUnknownStateVersion() {
    Bundle encoded =
        SpnegoStateCodec.encode(SpnegoNegotiationState.offered("portal.example.com"));
    encoded.putInt("version", 2);

    assertThrows(
        IllegalArgumentException.class,
        () -> SpnegoStateCodec.decode(encoded, "portal.example.com"));
  }

  @Test
  public void rejectsImpossiblePhaseForMechanism() {
    Bundle encoded =
        SpnegoStateCodec.encode(SpnegoNegotiationState.offered("portal.example.com"));
    encoded.putString("mechanism", "NTLM");

    assertThrows(
        IllegalArgumentException.class,
        () -> SpnegoStateCodec.decode(encoded, "portal.example.com"));
  }
}
