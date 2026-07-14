plugins {
    id("com.android.application")
}

fun versionCodeFor(versionName: String): Int {
    val parts = versionName.split(".")
    val major = parts.getOrNull(0)?.toIntOrNull() ?: 1
    val minor = parts.getOrNull(1)?.toIntOrNull() ?: 0
    return major * 100 + minor
}

val releaseVersion = providers.gradleProperty("releaseVersion").orElse("1.0")

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
            storePassword = "android"
            keyAlias = "kerberos"
            keyPassword = "android"
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
}

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
    implementation("com.hierynomus:asn-one:0.6.0")
    implementation("com.google.guava:guava:33.4.0-android")

    testImplementation("junit:junit:4.13.2")
    testImplementation("androidx.test:core:1.6.1")
    testImplementation("androidx.localbroadcastmanager:localbroadcastmanager:1.1.0")
    testImplementation("org.robolectric:robolectric:4.16.1")
    testImplementation("com.google.truth:truth:1.4.4")
}
