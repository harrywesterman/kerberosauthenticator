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
import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.Test;

public final class OpenJdkKerberosCryptoTest {

  @Test
  public void aes256AuthenticatorEncryptionInteroperatesWithJdk17() throws Exception {
    ClassLoader vendored = openJdkKerberosClassLoader();
    Class<?> localKey = Class.forName("sun.security.krb5.EncryptionKey", true, vendored);
    Class<?> localData = Class.forName("sun.security.krb5.EncryptedData", true, vendored);
    Class<?> referenceKey = Class.forName("sun.security.krb5.EncryptionKey");
    Class<?> referenceData = Class.forName("sun.security.krb5.EncryptedData");
    byte[] key = hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    Object localSessionKey = localKey.getConstructor(byte[].class, int.class, Integer.class)
        .newInstance(key, 18, null);
    Object referenceSessionKey = referenceKey.getConstructor(byte[].class, int.class, Integer.class)
        .newInstance(key, 18, null);
    // Exercise both exact AES block boundaries and ciphertext stealing, using
    // AP-REQ authenticator key usage 11. A local round-trip alone could conceal
    // a matching bug in the vendored encrypt and decrypt implementations.
    for (int length : new int[] {1, 15, 16, 17, 31, 32, 33, 127, 128, 129, 255}) {
      byte[] plaintext = new byte[length];
      for (int i = 0; i < length; i++) plaintext[i] = (byte) i;
      Object encrypted = localData.getConstructor(localKey, byte[].class, int.class)
          .newInstance(localSessionKey, plaintext, 11);
      byte[] ciphertext = (byte[]) localData.getMethod("getBytes").invoke(encrypted);
      Object referenceEncrypted = referenceData
          .getConstructor(int.class, Integer.class, byte[].class)
          .newInstance(18, null, ciphertext);
      assertWithMessage("AES-256 authenticator length %s", length)
          .that((byte[]) referenceData.getMethod("decrypt", referenceKey, int.class)
              .invoke(referenceEncrypted, referenceSessionKey, 11))
          .isEqualTo(plaintext);
      Object wrongUsage = referenceData.getConstructor(int.class, Integer.class, byte[].class)
          .newInstance(18, null, ciphertext);
      assertThrows(InvocationTargetException.class,
          () -> referenceData.getMethod("decrypt", referenceKey, int.class)
              .invoke(wrongUsage, referenceSessionKey, 7));
    }
  }

  @Test
  public void aesStringToKeyMatchesRfc3962Vectors() throws Exception {
    assertThat(
            stringToAesKey(
                128,
                "password".toCharArray(),
                "ATHENA.MIT.EDUraeburn",
                new byte[] {0x00, 0x00, 0x00, 0x01}))
        .isEqualTo(hex("42263c6e89f4fc28b8df68ee09799f15"));
    assertThat(
            stringToAesKey(
                256,
                "password".toCharArray(),
                "ATHENA.MIT.EDUraeburn",
                new byte[] {0x00, 0x00, 0x00, 0x01}))
        .isEqualTo(
            hex("fe697b52bc0d3ce14432ba036a92e65bbb52280990a2fa27883998d72af30161"));
    assertThat(
            stringToAesKey(
                256,
                new String(Character.toChars(0x1d11e)).toCharArray(),
                "EXAMPLE.COMpianist",
                new byte[] {0x00, 0x00, 0x00, 0x32}))
        .isEqualTo(
            hex("4b6d9839f84406df1f09cc166db4b83c571848b784a3d6bdc346589a3e393f9e"));
  }

  @Test
  public void aesStringToKeyPropagatesCryptoFailures() {
    InvocationTargetException thrown =
        assertThrows(
            InvocationTargetException.class,
            () -> acquireAes256SecretKeyWithInvalidStringToKeyParams());

    assertWithMessage("vendored Kerberos AES string-to-key failures must stay typed")
        .that(thrown.getCause().getClass().getName())
        .isEqualTo("sun.security.krb5.KrbCryptoException");
  }

  private static void acquireAes256SecretKeyWithInvalidStringToKeyParams() throws Exception {
    ClassLoader loader = openJdkKerberosClassLoader();
    Class<?> encryptedData = Class.forName("sun.security.krb5.EncryptedData", true, loader);
    int aes256Type = encryptedData.getField("ETYPE_AES256_CTS_HMAC_SHA1_96").getInt(null);
    Class<?> encryptionKey = Class.forName("sun.security.krb5.EncryptionKey", true, loader);
    Method acquireSecretKey =
        encryptionKey.getMethod(
            "acquireSecretKey", char[].class, String.class, int.class, byte[].class);

    acquireSecretKey.invoke(
        null, "password".toCharArray(), "EXAMPLE.LOCALuser", aes256Type, new byte[] {0x00, 0x00});
  }

  private static byte[] stringToAesKey(
      int keyBits, char[] password, String salt, byte[] stringToKeyParams) throws Exception {
    ClassLoader loader = openJdkKerberosClassLoader();
    Class<?> aesDkCrypto =
        Class.forName("sun.security.krb5.internal.crypto.dk.AesDkCrypto", true, loader);
    Object crypto = aesDkCrypto.getConstructor(int.class).newInstance(keyBits);
    Method stringToKey =
        aesDkCrypto.getMethod("stringToKey", char[].class, String.class, byte[].class);

    return (byte[]) stringToKey.invoke(crypto, password, salt, stringToKeyParams);
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

  private static byte[] hex(String value) {
    byte[] bytes = new byte[value.length() / 2];
    for (int i = 0; i < bytes.length; i++) {
      bytes[i] = (byte) Integer.parseInt(value.substring(i * 2, i * 2 + 2), 16);
    }
    return bytes;
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
