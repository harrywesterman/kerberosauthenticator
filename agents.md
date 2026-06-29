# Agents Notes

- GitHub releases should publish `kerberosauthenticator-<version>.apk`.
- Release versions start at `1.0` and increment by `0.1` for each new release (`1.1`, `1.2`, etc.).
- The release workflow derives the version from the latest GitHub release tag and passes it into Gradle with `-PreleaseVersion=...`.
- Local Gradle builds on this machine need JDK 17; Temurin 26 triggers the Kotlin/Gradle Java version parsing issue.
