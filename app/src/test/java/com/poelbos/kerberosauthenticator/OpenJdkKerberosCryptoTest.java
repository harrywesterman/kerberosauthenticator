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
  public void spnegoPropagatesTlsBindingIntoKerberosAuthenticator() throws Exception {
    ClassLoader loader = openJdkKerberosClassLoader();
    Class<?> principal = Class.forName("krb.javax.security.auth.kerberos.KerberosPrincipal", true, loader);
    Class<?> ticket = Class.forName("krb.javax.security.auth.kerberos.KerberosTicket", true, loader);
    byte[] encoded = java.util.Base64.getDecoder().decode(new String(
        getClass().getClassLoader().getResourceAsStream("kerberos-synthetic-ticket.b64").readAllBytes(),
        java.nio.charset.StandardCharsets.US_ASCII).trim());
    byte[] key = hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    Object client = principal.getConstructor(String.class).newInstance("synthetic@EXAMPLE.COM");
    javax.security.auth.Subject subject = new javax.security.auth.Subject();
    boolean[] flags = new boolean[32]; flags[9] = true;
    java.util.Date now = new java.util.Date();
    java.util.Date end = new java.util.Date(now.getTime() + 3600000);
    for (String server : new String[] {"krbtgt/EXAMPLE.COM@EXAMPLE.COM", "HTTP/synthetic.example.com@EXAMPLE.COM"}) {
      Object service = principal.getConstructor(String.class).newInstance(server);
      subject.getPrivateCredentials().add(ticket.getConstructor(byte[].class, principal, principal,
          byte[].class, int.class, boolean[].class, java.util.Date.class, java.util.Date.class,
          java.util.Date.class, java.util.Date.class, java.net.InetAddress[].class)
          .newInstance(encoded, client, service, key, 18, flags, now, now, end, null, null));
    }
    Class<?> util = Class.forName("sun.security.jgss.GSSUtil", true, loader);
    Object previous = util.getMethod("getGloballySetSubject").invoke(null);
    java.security.Provider originalProvider = java.security.Security.getProvider("SunJGSS");
    int providerPosition = java.util.Arrays.asList(java.security.Security.getProviders())
        .indexOf(originalProvider) + 1;
    String originalRealm = System.getProperty("java.security.krb5.realm");
    String originalKdc = System.getProperty("java.security.krb5.kdc");
    try {
      System.setProperty("java.security.krb5.realm", "EXAMPLE.COM");
      System.setProperty("java.security.krb5.kdc", "127.0.0.1");
      Class.forName("sun.security.krb5.Config", true, loader).getMethod("refresh").invoke(null);
      java.security.Security.removeProvider("SunJGSS");
      java.security.Security.addProvider((java.security.Provider)
          Class.forName("sun.security.jgss.SunProvider", true, loader).getConstructor().newInstance());
      util.getMethod("setGlobalSubject", javax.security.auth.Subject.class).invoke(null, subject);
      Class<?> caller = Class.forName("sun.security.jgss.GSSCaller", true, loader);
      Object manager = Class.forName("sun.security.jgss.GSSManagerImpl", true, loader)
          .getConstructor(caller, boolean.class).newInstance(caller.getField("CALLER_INITIATE").get(null), false);
      Class<?> oid = Class.forName("org.ietf.jgss.Oid", true, loader);
      Object spnego = oid.getConstructor(String.class).newInstance("1.3.6.1.5.5.2");
      Class<?> name = Class.forName("org.ietf.jgss.GSSName", true, loader);
      Object target = manager.getClass().getMethod("createName", String.class, oid, oid)
          .invoke(manager, "HTTP@synthetic.example.com", name.getField("NT_HOSTBASED_SERVICE").get(null), spnego);
      Class<?> credential = Class.forName("org.ietf.jgss.GSSCredential", true, loader);
      Object context = manager.getClass().getMethod("createContext", name, oid, credential, int.class)
          .invoke(manager, target, spnego, null, 3600);
      byte[] binding = "tls-server-end-point:synthetic-certificate-hash".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
      Object tlsBinding = Class.forName("sun.security.jgss.krb5.internal.TlsChannelBindingImpl", true, loader)
          .getConstructor(byte[].class).newInstance((Object) binding);
      Class<?> contextType = Class.forName("org.ietf.jgss.GSSContext", true, loader);
      contextType.getMethod("setChannelBinding", Class.forName("org.ietf.jgss.ChannelBinding", true, loader))
          .invoke(context, tlsBinding);
      byte[] token = (byte[]) contextType.getMethod("initSecContext", byte[].class, int.class, int.class)
          .invoke(context, new byte[0], 0, 0);
      byte[] checksum = authenticatorChecksum(token, key);
      java.nio.ByteBuffer serializedBinding = java.nio.ByteBuffer.allocate(20 + binding.length)
          .order(java.nio.ByteOrder.LITTLE_ENDIAN);
      serializedBinding.position(16); serializedBinding.putInt(binding.length); serializedBinding.put(binding);
      assertThat(java.util.Arrays.copyOfRange(checksum, 4, 20))
          .isEqualTo(java.security.MessageDigest.getInstance("MD5").digest(serializedBinding.array()));
      contextType.getMethod("dispose").invoke(context);
    } finally {
      util.getMethod("setGlobalSubject", javax.security.auth.Subject.class).invoke(null, previous);
      java.security.Security.removeProvider("SunJGSS");
      if (originalProvider != null) java.security.Security.insertProviderAt(originalProvider, providerPosition);
      if (originalRealm == null) System.clearProperty("java.security.krb5.realm");
      else System.setProperty("java.security.krb5.realm", originalRealm);
      if (originalKdc == null) System.clearProperty("java.security.krb5.kdc");
      else System.setProperty("java.security.krb5.kdc", originalKdc);
    }
  }

  private static byte[] authenticatorChecksum(byte[] token, byte[] key) throws Exception {
    Class<?> referenceData = Class.forName("sun.security.krb5.EncryptedData");
    Class<?> referenceKey = Class.forName("sun.security.krb5.EncryptionKey");
    for (int i = 0; i < token.length; i++) {
      if ((token[i] & 255) != 0x6e) continue;
      try {
        Der sequence = Der.read(token, i).inner();
        byte[] cipher = sequence.child(0xa4).inner().child(0xa2).inner().value;
        Object encrypted = referenceData.getConstructor(int.class, Integer.class, byte[].class)
            .newInstance(18, null, cipher);
        Object sessionKey = referenceKey.getConstructor(byte[].class, int.class, Integer.class)
            .newInstance(key, 18, null);
        byte[] plaintext = (byte[]) referenceData.getMethod("decrypt", referenceKey, int.class)
            .invoke(encrypted, sessionKey, 11);
        return Der.read(plaintext, 0).inner().child(0xa3).inner().child(0xa1).inner().value;
      } catch (Exception ignored) { }
    }
    throw new AssertionError("No independently decryptable AP-REQ authenticator");
  }

  /** Minimal test-fixture DER reader; the cryptographic verification uses JDK 17. */
  private static final class Der {
    final int tag, end;
    final byte[] value;
    Der(int tag, int end, byte[] value) { this.tag = tag; this.end = end; this.value = value; }
    static Der read(byte[] data, int offset) {
      int tag = data[offset++] & 255;
      int length = data[offset++] & 255;
      if ((length & 128) != 0) {
        int count = length & 127;
        if (count == 0 || count > 4) throw new IllegalArgumentException();
        length = 0;
        for (int i = 0; i < count; i++) length = (length << 8) | (data[offset++] & 255);
      }
      if (length < 0 || offset + length > data.length) throw new IllegalArgumentException();
      return new Der(tag, offset + length, java.util.Arrays.copyOfRange(data, offset, offset + length));
    }
    Der inner() { return read(value, 0); }
    Der child(int wanted) {
      for (int offset = 0; offset < value.length;) {
        Der child = read(value, offset);
        if (child.tag == wanted) return child;
        offset = child.end;
      }
      throw new IllegalArgumentException();
    }
  }

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
