plugins {
    id("com.android.application")
}

android {
    namespace = "com.poelbos.kerberosauthenticator"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.poelbos.kerberosauthenticator"
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
    implementation("com.google.guava:guava:33.4.0-android")

    testImplementation("junit:junit:4.13.2")
    testImplementation("androidx.test:core:1.6.1")
    testImplementation("androidx.localbroadcastmanager:localbroadcastmanager:1.1.0")
    testImplementation("org.robolectric:robolectric:4.16.1")
    testImplementation("com.google.truth:truth:1.4.4")
}
