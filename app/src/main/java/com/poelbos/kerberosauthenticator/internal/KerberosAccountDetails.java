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

import java.util.Arrays;

/**
 * Holds the Kerberos accounts details - should be passed around when a dependency on a more
 * complex object is undesirable.
 */
public class KerberosAccountDetails {
  private final String username;
  private final char[] password;
  private final String activeDirectoryDomain;
  private final String adDomainController;

  public KerberosAccountDetails(String username, String password,
      String activeDirectoryDomain, String adDomainController) {
    this(username, password == null ? null : password.toCharArray(),
        activeDirectoryDomain, adDomainController);
  }

  public KerberosAccountDetails(String username, char[] password,
      String activeDirectoryDomain, String adDomainController) {
    this.username = username;
    this.password = password == null ? null : Arrays.copyOf(password, password.length);
    this.activeDirectoryDomain = activeDirectoryDomain;
    this.adDomainController = adDomainController;
  }

  public String getUsername() {
    return username;
  }

  public char[] copyPassword() {
    return password == null ? null : Arrays.copyOf(password, password.length);
  }

  public String getActiveDirectoryDomain() {
    return activeDirectoryDomain;
  }

  public String getAdDomainController() {
    return adDomainController;
  }
}
