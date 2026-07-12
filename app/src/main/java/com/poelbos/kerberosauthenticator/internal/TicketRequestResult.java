/*
 * Copyright 2019 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.poelbos.kerberosauthenticator.internal;

/**
 * The result from attempting to get a ticket (either a ticket-granting-ticket or a service
 * ticket).
 */
public class TicketRequestResult {
  /**
   * The result code of getting a ticket.
   */
  public enum ResultCode {
    SUCCESS,
    ERROR_BAD_PASSWORD,
    ERROR_LOGIN_FAILED,
    ERROR_COMMIT_FAILED,
    ERROR_DNS_FAILURE,
    ERROR_NO_SPN,
    ERROR_SPNEGO_CONTINUATION,
    ERROR_GSS_FAILURE
  };

  private final ResultCode resultCode;
  private final String message;

  public TicketRequestResult(ResultCode resultCode, String message) {
    this.resultCode = resultCode;
    this.message = message;
  }

  public boolean successful() {
    return resultCode == ResultCode.SUCCESS;
  }

  public ResultCode getResultCode() {
    return resultCode;
  }

  public boolean isPasswordBad() {
    return resultCode == ResultCode.ERROR_BAD_PASSWORD;
  }

  /** AD/KDC errors for which retrying the same stored password is unsafe or pointless. */
  public boolean isCredentialRejected() {
    if (isPasswordBad()) return true;
    String normalized = message == null ? "" : message.toLowerCase(java.util.Locale.ROOT);
    return normalized.contains("client's credentials have been revoked")
        || normalized.contains("client credentials have been revoked")
        || normalized.contains("client not found")
        || normalized.contains("account expired")
        || normalized.contains("password has expired")
        || normalized.contains("account locked")
        || normalized.contains("clients credentials have been revoked");
  }

  @Override
  public String toString() {
    if (successful()) {
      return String.format("Success: %s", message);
    }

    return String.format("Failure (%s): %s", resultCode, message);
  }
}
