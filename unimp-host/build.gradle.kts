plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

/**
 * UniMP Android SDK 5.14 libs directory.
 * Resolved from, in order: unimp.sdk.libs in gradle.properties,
 * $UNIMP_SDK_LIBS, then the sibling ../SDK-Android@5.14-20260706/SDK/libs.
 * Never a hard-coded machine path, so this builds on any OS.
 */
val unimpSdkLibs: File = run {
    val fromProp = (project.findProperty("unimp.sdk.libs") as String?)?.trim().orEmpty()
    val fromEnv = System.getenv("UNIMP_SDK_LIBS")?.trim().orEmpty()
    val candidates = listOfNotNull(
        fromProp.takeIf { it.isNotEmpty() }?.let { file(it) },
        fromEnv.takeIf { it.isNotEmpty() }?.let { file(it) },
        rootProject.file("../SDK-Android@5.14-20260706/SDK/libs"),
    )
    candidates.firstOrNull { it.isDirectory }
        ?: error(
            "UniMP SDK libs not found. Set unimp.sdk.libs in gradle.properties " +
                "or UNIMP_SDK_LIBS to .../SDK-Android@5.14-20260706/SDK/libs"
        )
}

fun sdkAar(name: String): File {
    val f = File(unimpSdkLibs, name)
    require(f.isFile) { "Missing SDK aar: ${f.absolutePath}" }
    return f
}

// Minimal set required to run uni-app + Weex for protector white-screen smoke.
val requiredAars = listOf(
    "DCUniMPSDK-V2-release.aar",
    "uniapp-v8-release.aar",
    "breakpad-build-release.aar",
    "android-gif-drawable-1.2.29.aar",
    "sqlite-release.aar",
    "base_oaid_sdk.aar",
)

android {
    namespace = "com.yqsh.unimpdemo"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.yqsh.unimpdemo"
        minSdk = 21
        targetSdk = 34
        versionCode = 1
        versionName = "1.0.0"
        multiDexEnabled = true
        // DCloud FileProvider authorities placeholder
        manifestPlaceholders["apk.applicationId"] = "com.yqsh.unimpdemo"
        ndk {
            // Include x86 for older API emulators; x86_64 / arm for modern devices.
            abiFilters += listOf("armeabi-v7a", "arm64-v8a", "x86", "x86_64")
        }
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    buildTypes {
        debug {
            isMinifyEnabled = false
        }
        release {
            isMinifyEnabled = true
            signingConfig = signingConfigs.getByName("debug")
            proguardFiles(
                getDefaultProguardFile("proguard-android.txt"),
                "proguard.cfg"
            )
        }
    }

    // Required by DCloud UniMP — otherwise runtime resources fail.
    androidResources {
        additionalParameters += listOf("--auto-add-overlay")
        ignoreAssetsPattern = "!.svn:!.git:.*:!CVS:!thumbs.db:!picasa.ini:!*.scc:*~"
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }

    packaging {
        jniLibs {
            useLegacyPackaging = true
            pickFirsts += setOf(
                "**/libc++_shared.so",
                "**/libfbjni.so",
            )
        }
    }
}

dependencies {
    requiredAars.forEach { implementation(files(sdkAar(it))) }

    implementation("androidx.appcompat:appcompat:1.6.1")
    implementation("androidx.recyclerview:recyclerview:1.3.2")
    implementation("androidx.legacy:legacy-support-v4:1.0.0")
    implementation("androidx.multidex:multidex:2.0.1")
    implementation("androidx.webkit:webkit:1.5.0")
    implementation("androidx.core:core-ktx:1.12.0")

    implementation("com.alibaba:fastjson:1.2.83")
    implementation("com.facebook.fresco:fresco:3.4.0")
    implementation("com.facebook.fresco:animated-gif:3.4.0")
    implementation("com.facebook.fresco:webpsupport:3.4.0")
    implementation("com.facebook.fresco:animated-webp:3.4.0")
    implementation("com.github.bumptech.glide:glide:4.9.0")
    annotationProcessor("com.github.bumptech.glide:compiler:4.9.0")

    implementation("com.squareup.okhttp3:okhttp:3.12.13")
    implementation("com.squareup.okio:okio:1.17.5")
}

tasks.register("printUnimpSdkPath") {
    doLast {
        println("unimp.sdk.libs = ${unimpSdkLibs.absolutePath}")
        requiredAars.forEach { println("  ok $it") }
    }
}
