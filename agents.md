# Agents Notes

- GitHub releases should publish `kerberosauthenticator-<version>.apk`.
- Release versions start at `1.0` and increment by `0.1` for each new release (`1.1`, `1.2`, etc.).
- The release workflow derives the version from the latest GitHub release tag and passes it into Gradle with `-PreleaseVersion=...`.
- Local Gradle builds on this machine need JDK 17; Temurin 26 triggers the Kotlin/Gradle Java version parsing issue.
- Always stay on `main` (MAIN) for this repository and do not continue work on other branches.
- For a change that must be tested on a managed Android device:
  1. Run the relevant unit tests and assemble the APK locally with JDK 17.
  2. Commit and push the verified change to `main`.
  3. Wait for the `Build and Publish Release` GitHub Actions workflow to finish successfully.
  4. Download the signed `kerberosauthenticator-<version>.apk` asset from that GitHub release; do not install the local debug APK as a substitute.
  5. Install the release APK with an in-place update so existing app data and stored credentials are preserved.
  6. Force-stop Chrome, clear logcat, reproduce the target URL, and verify from non-sensitive logs that Chrome requested SPNEGO and that the expected SPN candidate was selected.
