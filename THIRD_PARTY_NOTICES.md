# Third-party notices

Kerberos Authenticator is based on Google's Android Kerberos Authenticator,
Copyright 2019 Google LLC, licensed under Apache License 2.0. The root LICENSE
contains that license. This fork adds managed account and credential handling,
HTTP authentication, Android DocumentsProvider integration, and a Gradle build.
Original copyright and license headers remain in the source files.

The bundled `openjdk-kerberos` module is a modified fork of
https://github.com/google/openjdk-kerberos. Its source files retain their original
Oracle, IBM, Open Group, and other attribution notices. The module is licensed
under GPL version 2 with the Classpath exception where designated in each source
header. The full text is in `openjdk-kerberos/LICENSE`. Local changes cover Android
packaging, Kerberos crypto support, referrals, peer-error parsing and SPNEGO
context handling. The corresponding source is distributed in this repository
and in the source archives for each release:
https://github.com/harrywesterman/kerberosauthenticator/releases.

Runtime dependencies include:

| Components | License |
|---|---|
| AndroidX, Material Components, Android view binding | Apache 2.0 |
| Kotlin standard library and JetBrains annotations | Apache 2.0 |
| SMBJ and ASN.1/ASN-One | Apache 2.0 |
| Guava, failureaccess, listenablefuture, Error Prone and J2ObjC annotations | Apache 2.0 |
| Bouncy Castle crypto provider | Bouncy Castle MIT-style license |
| SLF4J | MIT |
| MBassador | MIT |
| Checker Framework annotations | MIT |
| JSR305 annotations | Apache 2.0, as declared by the published Maven metadata |

Additional license texts and copyright notices are in `third_party_licenses/`.
These notices, the Apache license and the OpenJDK license are also packaged in
the APK under `assets/licenses/`. Dependency source and metadata remain available
from their Maven coordinates listed in the Gradle dependency report.
