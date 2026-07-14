package com.poelbos.kerberosauthenticator.internal.spnego;

import java.util.Arrays;

/** Result of one Chrome HTTP Negotiate token round. */
public final class HttpSpnegoResult {
  public static final int OK = 0;
  public static final int ERR_UNEXPECTED = 1;
  public static final int ERR_UNEXPECTED_SECURITY_LIBRARY_STATUS = 3;
  public static final int ERR_INVALID_RESPONSE = 4;
  public static final int ERR_INVALID_AUTH_CREDENTIALS = 5;
  public static final int ERR_UNSUPPORTED_AUTH_SCHEME = 6;
  public static final int ERR_MISSING_AUTH_CREDENTIALS = 7;
  public static final int ERR_MALFORMED_IDENTITY = 9;

  private final int status;
  private final byte[] token;
  private final SpnegoNegotiationState state;
  private final SpnegoNegotiationState.Mechanism selectedMechanism;
  private final String selectedService;
  private final String diagnostic;

  private HttpSpnegoResult(
      int status,
      byte[] token,
      SpnegoNegotiationState state,
      SpnegoNegotiationState.Mechanism selectedMechanism,
      String selectedService,
      String diagnostic) {
    this.status = status;
    this.token = token == null ? null : Arrays.copyOf(token, token.length);
    this.state = state;
    this.selectedMechanism = selectedMechanism;
    this.selectedService = selectedService;
    this.diagnostic = diagnostic;
  }

  public static HttpSpnegoResult success(byte[] token, SpnegoNegotiationState state) {
    return success(
        token,
        state,
        state == null ? null : state.getMechanism(),
        state == null ? null : state.getSelectedService());
  }

  public static HttpSpnegoResult success(
      byte[] token,
      SpnegoNegotiationState state,
      SpnegoNegotiationState.Mechanism selectedMechanism,
      String selectedService) {
    return new HttpSpnegoResult(
        OK, token, state, selectedMechanism, selectedService, null);
  }

  public static HttpSpnegoResult failure(int status, String diagnostic) {
    return new HttpSpnegoResult(status, null, null, null, null, diagnostic);
  }

  public int getStatus() { return status; }

  public byte[] getToken() { return token == null ? null : Arrays.copyOf(token, token.length); }

  public SpnegoNegotiationState getState() { return state; }

  public SpnegoNegotiationState.Mechanism getSelectedMechanism() { return selectedMechanism; }

  public String getSelectedService() { return selectedService; }

  public String getDiagnostic() { return diagnostic; }
}
