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

import static com.google.common.truth.Truth.assertWithMessage;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;
import org.junit.Test;

public final class OpenJdkKerberosPackagingTest {

  @Test
  public void vendoredKerberosCodeDoesNotReferencePlatformInternalPackages() throws IOException {
    Path sourceRoot = openJdkKerberosSourceRoot();
    List<String> references = new ArrayList<>();

    try (Stream<Path> paths = Files.walk(sourceRoot)) {
      paths
          .filter(path -> path.toString().endsWith(".java"))
          .forEach(
              path -> {
                try {
                  String source =
                      new String(Files.readAllBytes(path), StandardCharsets.UTF_8);
                  if (containsUnrelocatedPackageReference(source, "sun.security.util")
                      || containsUnrelocatedPackageReference(source, "sun.misc")
                      || containsUnrelocatedPackageReference(source, "sun.util.calendar")) {
                    references.add(sourceRoot.relativize(path).toString());
                  }
                } catch (IOException e) {
                  throw new RuntimeException(e);
                }
              });
    }

    assertWithMessage(
            "Android loads platform-internal packages from the bootclasspath, so vendored "
                + "OpenJDK Kerberos code must use relocated packages for internal helpers.")
        .that(references)
        .isEmpty();
  }

  private static Path openJdkKerberosSourceRoot() {
    Path directory = Path.of(System.getProperty("user.dir")).toAbsolutePath();
    while (directory != null) {
      Path sourceRoot = directory.resolve("openjdk-kerberos/src/main/java");
      if (Files.isDirectory(sourceRoot)) {
        return sourceRoot;
      }
      directory = directory.getParent();
    }
    throw new IllegalStateException("Could not find openjdk-kerberos source root.");
  }

  private static boolean containsUnrelocatedPackageReference(String source, String packageName) {
    for (String line : source.split("\\R")) {
      String trimmed = line.trim();
      if (trimmed.startsWith("//") || trimmed.startsWith("*") || trimmed.startsWith("/*")) {
        continue;
      }

      int start = -1;
      while ((start = line.indexOf(packageName, start + 1)) != -1) {
        if (start >= 4 && line.substring(start - 4, start).equals("krb.")) {
          continue;
        }
        int end = start + packageName.length();
        if (end < line.length() && (line.charAt(end) == '.' || line.charAt(end) == ';')) {
          return true;
        }
      }
    }
    return false;
  }
}
