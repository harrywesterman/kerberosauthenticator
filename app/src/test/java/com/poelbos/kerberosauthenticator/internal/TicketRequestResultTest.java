package com.poelbos.kerberosauthenticator.internal;

import static com.google.common.truth.Truth.assertThat;

import com.poelbos.kerberosauthenticator.internal.TicketRequestResult.ResultCode;
import org.junit.Test;

public final class TicketRequestResultTest {
  @Test public void badPasswordAndRevokedAccountArePermanent() {
    assertThat(new TicketRequestResult(ResultCode.ERROR_BAD_PASSWORD, "bad")
        .isCredentialRejected()).isTrue();
    assertThat(new TicketRequestResult(ResultCode.ERROR_LOGIN_FAILED,
        "Client's credentials have been revoked").isCredentialRejected()).isTrue();
  }

  @Test public void networkStyleLoginFailureIsTemporary() {
    assertThat(new TicketRequestResult(ResultCode.ERROR_LOGIN_FAILED,
        "Cannot contact any KDC").isCredentialRejected()).isFalse();
  }
}
