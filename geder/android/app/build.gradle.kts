plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "dev.geder.app"
    compileSdk = 35

    defaultConfig {
        applicationId = "dev.geder.app"
        minSdk = 28
        targetSdk = 35
        versionCode = 1
        versionName = "0.1.0-prototype"
        ndk {
            abiFilters += listOf("arm64-v8a", "armeabi-v7a", "x86_64")
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }
}

// Compile le moteur Rust (geder-core) pour chaque ABI dans src/main/jniLibs.
// Prérequis : NDK installé, `cargo install cargo-ndk`, cibles rustup Android ajoutées.
val buildRustCore by tasks.registering(Exec::class) {
    group = "build"
    description = "Compile geder-core (Rust) en bibliothèques natives Android"
    workingDir = rootDir.resolve("..")
    commandLine(
        "cargo", "ndk",
        "-t", "arm64-v8a", "-t", "armeabi-v7a", "-t", "x86_64",
        "-o", projectDir.resolve("src/main/jniLibs").absolutePath,
        "build", "--release", "-p", "geder-core", "--features", "android",
    )
}
tasks.named("preBuild") { dependsOn(buildRustCore) }
