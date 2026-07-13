# Directe DFS-ondersteuning Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Laat beheerde SMB-shares DFS-referrals volgen met Kerberos-only authenticatie.

**Architecture:** Centraliseer de opbouw van `SmbConfig` in `KerberosSmbClient`, zodat die unit-testbaar is. De configuratie adverteert SMBJ DFS-capability; SMBJ volgt daarna de referral en hergebruikt de bestaande GSS-authenticatiecontext bij elke DFS-doelserver. De MDM-namespace en alle bestaande Kerberos- en transportbeveiliging blijven ongewijzigd.

**Tech Stack:** Java 17, Android, SMBJ 0.14.0, JUnit 4, Gradle, GitHub Actions.

---

### Task 1: Bescherm de DFS-capability met een regressietest

**Files:**
- Create: `app/src/test/java/com/poelbos/kerberosauthenticator/files/KerberosSmbClientTest.java`
- Modify: `app/src/main/java/com/poelbos/kerberosauthenticator/files/KerberosSmbClient.java:55-64`

**Step 1: Write the failing test**

Maak een package-private test voor `KerberosSmbClient.createConfig(false)` die controleert dat:

```java
assertTrue(config.isDfsEnabled());
assertTrue(config.isSigningRequired());
assertTrue(config.getSupportedDialects().contains(SMB2Dialect.SMB_3_1_1));
assertTrue(config.getSupportedDialects().contains(SMB2Dialect.SMB_2_1));
```

Voeg een tweede test toe voor `createConfig(true)` die `config.isEncryptData()` bevestigt.

**Step 2: Run test to verify it fails**

Run:

```bash
JAVA_HOME=$(/usr/libexec/java_home -v 17) ./gradlew :app:testDebugUnitTest --tests com.poelbos.kerberosauthenticator.files.KerberosSmbClientTest
```

Expected: FAIL, omdat `createConfig` nog niet bestaat.

**Step 3: Write minimal implementation**

Extraheer de bestaande `SmbConfig.builder()`-keten naar package-private:

```java
static SmbConfig createConfig(boolean requireEncryption) {
  return SmbConfig.builder()
      .withDialects(SMB_3_1_1, SMB_3_0_2, SMB_3_0, SMB_2_1)
      .withSigningRequired(true)
      .withEncryptData(requireEncryption)
      .withDfsEnabled(true)
      .build();
}
```

Gebruik `createConfig(requireEncryption)` in `connect`. Verander geen authenticatie-, share- of padlogica.

**Step 4: Run test to verify it passes**

Run the command from step 2.

Expected: PASS.

**Step 5: Run the complete unit-test suite**

Run:

```bash
JAVA_HOME=$(/usr/libexec/java_home -v 17) ./gradlew test
```

Expected: `BUILD SUCCESSFUL`.

**Step 6: Commit**

```bash
git add app/src/main/java/com/poelbos/kerberosauthenticator/files/KerberosSmbClient.java app/src/test/java/com/poelbos/kerberosauthenticator/files/KerberosSmbClientTest.java
git commit -m "feat: enable DFS for managed SMB shares"
```

### Task 2: Documenteer en publiceer de geverifieerde release

**Files:**
- Modify: `README.md:25-36`

**Step 1: Write the failing documentation check**

Voeg geen geautomatiseerde documentatietest toe: de wijziging is uitsluitend een korte, controleerbare gebruiksnotitie.

**Step 2: Update documentation**

Voeg aan de Bedrijfsbestanden-lijst toe dat beheerde DFS-namespaces en referrals rechtstreeks worden gevolgd met Kerberos-only SMB.

**Step 3: Verify formatting and release build**

Run:

```bash
git diff --check
JAVA_HOME=$(/usr/libexec/java_home -v 17) ./gradlew assembleRelease -PreleaseVersion=1.40
```

Expected: geen witruimtefouten en `BUILD SUCCESSFUL`.

**Step 4: Commit and push main**

```bash
git add README.md docs/plans/2026-07-13-dfs-share-support.md
git commit -m "docs: describe DFS share support"
git push origin main
```

**Step 5: Verify the managed-device release**

1. Wacht tot de GitHub Actions-workflow `Build and Publish Release` voor `main` succesvol is.
2. Download de gesigneerde `kerberosauthenticator-<version>.apk` van die GitHub-release.
3. Installeer die APK als in-place update op het beheerde toestel.
4. Force-stop de app, wis logcat, open G-schijf en controleer dat de DFS-mapinhoud verschijnt.
5. Controleer alleen niet-gevoelige logs op de SMB/Kerberos-aanvraag; geen tickets, tokens of bestandsnamen vastleggen.
