/*
 * Copyright 2026 Google LLC
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
package com.poelbos.kerberosauthenticator;

import static com.google.common.truth.Truth.assertThat;

import java.lang.reflect.Method;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.Test;

public final class OpenJdkKerberosReferralTest {

  @Test
  public void referralTicketRewritesServiceIntoReferredRealm() throws Exception {
    ClassLoader loader = openJdkKerberosClassLoader();
    Class<?> principalName = Class.forName("sun.security.krb5.PrincipalName", true, loader);
    int unknownNameType = principalName.getField("KRB_NT_UNKNOWN").getInt(null);
    int srvInstNameType = principalName.getField("KRB_NT_SRV_INST").getInt(null);
    Object requestedService =
        principalName
            .getConstructor(String.class, int.class, String.class)
            .newInstance("HTTP/portal.int.example", unknownNameType, "EXAMPLE.LOCAL");
    Object referralTicket =
        principalName
            .getConstructor(String.class, int.class, String.class)
            .newInstance("krbtgt/INT.EXAMPLE", srvInstNameType, "EXAMPLE.LOCAL");

    Class<?> credentialsUtil =
        Class.forName("sun.security.krb5.internal.CredentialsUtil", true, loader);
    Method referralRealm =
        credentialsUtil.getDeclaredMethod("getReferralRealm", principalName, principalName);
    referralRealm.setAccessible(true);
    Method withRealm = credentialsUtil.getDeclaredMethod("withRealm", principalName, String.class);
    withRealm.setAccessible(true);

    assertThat((String) referralRealm.invoke(null, referralTicket, requestedService))
        .isEqualTo("INT.EXAMPLE");
    assertThat(withRealm.invoke(null, requestedService, "INT.EXAMPLE").toString())
        .isEqualTo("HTTP/portal.int.example@INT.EXAMPLE");
  }

  @Test
  public void kdcOptionsCanRequestCanonicalize() throws Exception {
    ClassLoader loader = openJdkKerberosClassLoader();
    Class<?> kdcOptions = Class.forName("sun.security.krb5.internal.KDCOptions", true, loader);

    assertThat(kdcOptions.getField("CANONICALIZE").getInt(null)).isEqualTo(15);
  }

  private static ClassLoader openJdkKerberosClassLoader() throws Exception {
    Path classesDir = openJdkKerberosClassesDir();
    return new ChildFirstOpenJdkKerberosClassLoader(new URL[] {classesDir.toUri().toURL()});
  }

  private static Path openJdkKerberosClassesDir() {
    Path directory = Path.of(System.getProperty("user.dir")).toAbsolutePath();
    while (directory != null) {
      Path classesDir =
          directory.resolve(
              "openjdk-kerberos/build/intermediates/javac/debug/compileDebugJavaWithJavac"
                  + "/classes");
      if (Files.isDirectory(classesDir)) {
        return classesDir;
      }
      directory = directory.getParent();
    }
    throw new IllegalStateException("Could not find compiled openjdk-kerberos classes.");
  }

  private static final class ChildFirstOpenJdkKerberosClassLoader extends URLClassLoader {
    ChildFirstOpenJdkKerberosClassLoader(URL[] urls) {
      super(urls, null);
    }

    @Override
    protected Class<?> loadClass(String name, boolean resolve) throws ClassNotFoundException {
      synchronized (this) {
        Class<?> loaded = findLoadedClass(name);
        if (loaded == null) {
          if (isVendoredOpenJdkKerberosClass(name)) {
            try {
              loaded = findClass(name);
            } catch (ClassNotFoundException e) {
              loaded = super.loadClass(name, false);
            }
          } else {
            loaded = super.loadClass(name, false);
          }
        }
        if (resolve) {
          resolveClass(loaded);
        }
        return loaded;
      }
    }

    private static boolean isVendoredOpenJdkKerberosClass(String name) {
      return name.startsWith("sun.security.")
          || name.startsWith("krb.")
          || name.startsWith("com.sun.security.")
          || name.startsWith("org.ietf.jgss.")
          || name.startsWith("sun.net.");
    }
  }
}
