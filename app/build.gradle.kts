plugins {
    id("com.android.application")
}

fun versionCodeFor(versionName: String): Int {
    require(Regex("^[0-9]+\\.[0-9]+$").matches(versionName)) {
        "releaseVersion must use major.minor, for example 1.61"
    }
    val parts = versionName.split(".")
    val major = parts[0].toLong()
    val minor = parts[1].toLong()
    require(minor < 100000) { "releaseVersion minor component must be below 100000" }
    val code = Math.addExact(Math.multiplyExact(major, 100000L), minor)
    require(code in 1..Int.MAX_VALUE) { "releaseVersion does not fit Android versionCode" }
    return code.toInt()
}

val releaseVersion = providers.gradleProperty("releaseVersion").orElse("1.0")
val releaseStorePassword = providers.gradleProperty("releaseStorePassword")
    .orElse(providers.environmentVariable("RELEASE_STORE_PASSWORD"))
    .orElse("")
val releaseKeyPassword = providers.gradleProperty("releaseKeyPassword")
    .orElse(providers.environmentVariable("RELEASE_KEY_PASSWORD"))
    .orElse("")
val releaseKeyAlias = providers.gradleProperty("releaseKeyAlias")
    .orElse(providers.environmentVariable("RELEASE_KEY_ALIAS"))
    .orElse("")
    .map { it.ifBlank { "kerberos" } }

val packageLicenseAssets by tasks.registering(Sync::class) {
    into(layout.buildDirectory.dir("generated/licenseAssets/licenses"))
    from(rootProject.file("LICENSE")) { rename { "Apache-2.0.txt" } }
    from(rootProject.file("openjdk-kerberos/LICENSE")) { rename { "OpenJDK-GPL-2.0-with-Classpath-exception.txt" } }
    from(rootProject.file("THIRD_PARTY_NOTICES.md"))
    from(rootProject.file("third_party_licenses"))
}

android {
    namespace = "com.poelbos.kerberosauthenticator"
    compileSdk = 35

    buildFeatures {
        buildConfig = true
        viewBinding = true
    }

    defaultConfig {
        applicationId = "com.poelbos.kerberosauthenticator"
        versionName = releaseVersion.get()
        versionCode = versionCodeFor(releaseVersion.get())
        minSdk = 26
        targetSdk = 35
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    signingConfigs {
        create("release") {
            storeFile = file("../release.keystore")
            storePassword = releaseStorePassword.get()
            keyAlias = releaseKeyAlias.get()
            keyPassword = releaseKeyPassword.get()
        }
    }

    buildTypes {
        debug {}
        release {
            isMinifyEnabled = false
            signingConfig = signingConfigs.getByName("release")
        }
    }

    testOptions {
        unitTests {
            isIncludeAndroidResources = true
        }
    }
    sourceSets.getByName("main").assets.srcDir(layout.buildDirectory.dir("generated/licenseAssets"))
}

tasks.named("preBuild").configure { dependsOn(packageLicenseAssets) }

tasks.withType<Test> {
    jvmArgs(
        "--add-exports", "java.base/sun.security.util=ALL-UNNAMED",
        "--add-exports", "java.security.jgss/sun.security.krb5=ALL-UNNAMED",
        "--add-exports", "java.security.jgss/sun.security.jgss=ALL-UNNAMED",
        "--add-opens", "java.base/sun.security.util=ALL-UNNAMED",
        "--add-opens", "java.security.jgss/sun.security.krb5=ALL-UNNAMED",
        "--add-opens", "java.security.jgss/sun.security.jgss=ALL-UNNAMED",
        "--add-opens", "java.base/java.lang=ALL-UNNAMED"
    )
}

dependencies {
    implementation(project(":openjdk-kerberos"))
    implementation("androidx.appcompat:appcompat:1.7.0")
    implementation("androidx.annotation:annotation:1.9.1")
    implementation("androidx.recyclerview:recyclerview:1.4.0")
    implementation("androidx.work:work-runtime:2.10.0")
    implementation("com.google.android.material:material:1.12.0")
    implementation("com.hierynomus:smbj:0.14.0")
    implementation("org.bouncycastle:bcprov-jdk18on:1.86") {
        version { strictly("1.86") }
        because("Replace SMBJ's vulnerable transitive crypto provider")
    }
    implementation("com.hierynomus:asn-one:0.6.0")
    implementation("com.google.guava:guava:33.4.0-android")

    testImplementation("junit:junit:4.13.2")
    testImplementation("androidx.test:core:1.6.1")
    testImplementation("androidx.localbroadcastmanager:localbroadcastmanager:1.1.0")
    testImplementation("org.robolectric:robolectric:4.16.1")
    testImplementation("com.google.truth:truth:1.4.4")
}
