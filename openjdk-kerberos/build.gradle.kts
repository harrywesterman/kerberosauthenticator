plugins {
    id("com.android.library")
}

android {
    namespace = "krb"
    compileSdk = 35

    defaultConfig {
        minSdk = 26
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    lint {
        disable += "SuspiciousIndentation"
    }
}

dependencies {
    testImplementation("junit:junit:4.13.2")
}
