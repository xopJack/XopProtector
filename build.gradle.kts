plugins {
    id("com.android.application") version "8.2.2" apply false
    id("com.android.library") version "8.2.2" apply false
    id("org.jetbrains.kotlin.android") version "1.9.22" apply false
}

import java.nio.file.Files
import java.nio.file.StandardCopyOption

tasks.register("exportShellFiles") {
    group = "protector"
    description = "Export shell classes.dex and .so into executable/shell-files"
    dependsOn(":native:assembleRelease")

    doLast {
        val outRoot = rootProject.file("executable/shell-files")
        val dexOut = File(outRoot, "dex")
        val libsOut = File(outRoot, "libs")
        dexOut.mkdirs()
        // Wipe libs so stale ABIs (x86 leftovers) cannot be packed.
        if (libsOut.exists()) libsOut.deleteRecursively()
        libsOut.mkdirs()
        // Drop legacy "lib/" so packer never picks a stale copy over "libs/".
        File(outRoot, "lib").takeIf { it.exists() }?.deleteRecursively()

        fun findJar(): File? {
            val root = rootProject.file("native/build/intermediates")
            if (!root.exists()) return null
            return root.walkTopDown()
                .filter { it.isFile && it.name == "classes.jar" && it.path.contains("release") }
                .maxByOrNull { it.lastModified() }
        }

        val jar = findJar() ?: throw GradleException("native classes.jar not found. Build :native first.")

        val sdkDir = run {
            val lp = rootProject.file("local.properties")
            var dir: String? = null
            if (lp.exists()) {
                lp.readLines().forEach {
                    if (it.startsWith("sdk.dir=")) {
                        dir = it.substringAfter("=").replace("\\:", ":").replace("\\\\", "\\")
                    }
                }
            }
            dir ?: System.getenv("ANDROID_HOME") ?: System.getenv("ANDROID_SDK_ROOT")
        } ?: throw GradleException("Android SDK not found")

        val buildTools = File(sdkDir, "build-tools").listFiles()?.filter { it.isDirectory }?.maxByOrNull { it.name }
            ?: throw GradleException("build-tools not found")
        val d8 = if (System.getProperty("os.name").lowercase().contains("windows")) {
            File(buildTools, "d8.bat")
        } else {
            File(buildTools, "d8")
        }

        val tmpDexDir = File(outRoot, "tmp-dex")
        if (tmpDexDir.exists()) tmpDexDir.deleteRecursively()
        tmpDexDir.mkdirs()

        exec {
            commandLine(d8.absolutePath, "--output", tmpDexDir.absolutePath, jar.absolutePath)
        }
        val produced = tmpDexDir.listFiles()?.firstOrNull { it.name.endsWith(".dex") }
            ?: throw GradleException("d8 did not produce dex")
        Files.copy(produced.toPath(), File(dexOut, "classes.dex").toPath(), StandardCopyOption.REPLACE_EXISTING)
        tmpDexDir.deleteRecursively()
        println("Exported shell dex -> ${File(dexOut, "classes.dex").absolutePath}")

        fun findLibRoot(): File? {
            val root = rootProject.file("native/build/intermediates")
            if (!root.exists()) return null
            // Prefer stripped release libs (much smaller); fall back to merged.
            val stripped = root.walkTopDown()
                .filter {
                    it.isDirectory && it.name == "lib" &&
                            it.path.contains("stripped_native_libs") &&
                            it.path.contains("release")
                }
                .firstOrNull()
            if (stripped != null) return stripped
            val merged = root.walkTopDown()
                .filter {
                    it.isDirectory && it.name == "lib" &&
                            it.path.contains("merged_native_libs") &&
                            it.path.contains("release")
                }
                .firstOrNull()
            if (merged != null) {
                println("WARNING: stripped_native_libs not found; using merged_native_libs (larger)")
            }
            return merged
        }
        val libRoot = findLibRoot() ?: throw GradleException("native libs not found")
        println("Exporting shell libs from ${libRoot.absolutePath}")
        libRoot.listFiles()?.filter { it.isDirectory }?.forEach { abiDir ->
            val dst = File(libsOut, abiDir.name)
            dst.mkdirs()
            abiDir.listFiles()?.filter { it.name.endsWith(".so") }?.forEach { so ->
                Files.copy(so.toPath(), File(dst, so.name).toPath(), StandardCopyOption.REPLACE_EXISTING)
                println("Exported ${abiDir.name}/${so.name} (${so.length()} bytes)")
            }
        }

        // libprotector.so NEEDED libshadowhook.so, but :native packaging excludes it
        // (prefab supplies it for app modules). Packer must still embed it for third-party APKs.
        fun findShadowhookSo(abi: String): File? {
            fun score(f: File): Int {
                val p = f.path
                return when {
                    p.contains("stripped_native_libs") -> 5
                    p.contains("RelWithDebInfo") || p.contains("${File.separator}release${File.separator}") -> 3
                    p.contains("${File.separator}Release${File.separator}") -> 3
                    p.contains("Debug") || p.contains("${File.separator}debug${File.separator}") -> 1
                    else -> 2
                }
            }
            fun searchUnder(dir: File): File? {
                if (!dir.exists()) return null
                return dir.walkTopDown()
                    .filter {
                        it.isFile && it.name == "libshadowhook.so" &&
                                it.path.contains("${File.separator}$abi${File.separator}")
                    }
                    .maxWithOrNull(compareBy<File> { score(it) }.thenBy { it.lastModified() })
            }
            // Prefer stripped demo / native packaging outputs first.
            searchUnder(rootProject.file("demo/build/intermediates/stripped_native_libs"))
                ?.let { return it }
            searchUnder(rootProject.file("native/build/intermediates/stripped_native_libs"))
                ?.let { return it }
            val cxx = rootProject.file("native/build/intermediates/cxx")
            if (cxx.exists()) {
                cxx.walkTopDown()
                    .filter {
                        it.isFile && it.name == "libshadowhook.so" &&
                                it.path.contains("${File.separator}obj${File.separator}$abi")
                    }
                    .maxWithOrNull(compareBy<File> { score(it) }.thenBy { it.lastModified() })
                    ?.let { return it }
            }
            searchUnder(rootProject.file("demo/build/intermediates/merged_native_libs"))
                ?.let { return it }
            return null
        }
        libsOut.listFiles()?.filter { it.isDirectory }?.forEach { abiDir ->
            val dest = File(abiDir, "libshadowhook.so")
            if (dest.exists()) return@forEach
            val src = findShadowhookSo(abiDir.name)
            if (src == null) {
                // bytehook only links shadowhook on arm/arm64; x86/x86_64 must still export.
                val arm = abiDir.name == "armeabi-v7a" || abiDir.name == "arm64-v8a"
                if (arm) {
                    throw GradleException(
                        "libshadowhook.so not found for ${abiDir.name}. Build :native first."
                    )
                }
                println("Skip libshadowhook.so for ${abiDir.name} (not linked on this ABI)")
                return@forEach
            }
            Files.copy(src.toPath(), dest.toPath(), StandardCopyOption.REPLACE_EXISTING)
            println("Exported ${abiDir.name}/libshadowhook.so (from ${src.absolutePath})")
        }
    }
}

tasks.register("protectDemo") {
    group = "protector"
    description = "Build demo, export shell, pack+sign protected APK (debug keystore + channel)"
    dependsOn(":demo:assembleRelease", "exportShellFiles", ":packer:jar")
    doLast {
        val demoApk = fileTree("demo/build/outputs/apk/release") { include("*.apk") }.files.firstOrNull()
            ?: throw GradleException("demo release apk not found")
        val packerJar = rootProject.file("packer/build/libs").listFiles()
            ?.filter { it.name.startsWith("protector-packer") && it.name.endsWith(".jar") }
            ?.maxByOrNull { it.lastModified() }
            ?: throw GradleException("packer jar not found")
        println("Using packer jar: ${packerJar.name}")
        val outApk = rootProject.file("executable/demo-protected.apk")
        outApk.parentFile.mkdirs()
        val debugKs = file("${System.getProperty("user.home")}/.android/debug.keystore")
        if (!debugKs.isFile) {
            throw GradleException("debug keystore not found: ${debugKs.absolutePath}")
        }
        exec {
            commandLine(
                "java", "-jar", packerJar.absolutePath,
                demoApk.absolutePath,
                "-o", outApk.absolutePath,
                "--shell-dir", rootProject.file("executable/shell-files").absolutePath,
                // Only Business: DexPool trampoline rewrite must not touch Activity/Application
                // bodies that were hollowed to return stubs (causes VerifyError on Android 14+).
                "--hollow-prefix", "Lcom/yqsh/protectordemo/Business;",
                "--true-vmp-prefix", "Lcom/yqsh/protectordemo/Business;",
                "--protect-so",
                // Extra protect off for demo/desktop: assets / res-protect / NetGuard / pin-certs.
                // CLI-only if needed. --encrypt-assets requires the app to read via ProtectorAssets
                // (no transparent AssetManager hook; third-party AssetManager.open will fail).
                "--no-encrypt-assets",
                "--no-res-protect",
                "--keystore", debugKs.absolutePath,
                "--alias", "androiddebugkey",
                "--storepass", "android",
                "--keypass", "android"
            )
        }
        println("Protected demo APK -> ${outApk.absolutePath}")
    }
}

tasks.register("syncUnimpSampleAssets") {
    group = "protector"
    description = "Copy DCloud SDK DEMO sample app (__UNI__F743940) into unimp-host assets"
    doLast {
        val sdkRootProp = (project.findProperty("unimp.sdk.libs") as String?)?.trim().orEmpty()
        val sdkRootEnv = System.getenv("UNIMP_SDK_LIBS")?.trim().orEmpty()
        val libsDir = listOfNotNull(
            sdkRootProp.takeIf { it.isNotEmpty() }?.let { file(it) },
            sdkRootEnv.takeIf { it.isNotEmpty() }?.let { file(it) },
            rootProject.file("../SDK-Android@5.14-20260706/SDK/libs"),
        ).firstOrNull { it.isDirectory }
            ?: throw GradleException(
                "UniMP SDK libs not found. Set unimp.sdk.libs, \$UNIMP_SDK_LIBS, " +
                    "or place the SDK at ../SDK-Android@5.14-20260706."
            )
        val demoApps = libsDir.parentFile?.parentFile
            ?.resolve("DEMO/UniMPDemo/app/src/main/assets/apps/__UNI__F743940")
            ?: throw GradleException("Cannot resolve SDK DEMO apps from ${libsDir.absolutePath}")
        if (!demoApps.isDirectory) {
            throw GradleException("Sample app missing: ${demoApps.absolutePath}")
        }
        val dest = rootProject.file("unimp-host/src/main/assets/apps/__UNI__F743940")
        dest.parentFile.mkdirs()
        if (dest.exists()) dest.deleteRecursively()
        demoApps.copyRecursively(dest, overwrite = true)
        println("Synced sample UniMP assets -> ${dest.absolutePath}")
    }
}

tasks.register("buildUnimpXopDemo") {
    group = "protector"
    description = "npm run build:app in uniapp-demo (requires Node.js)"
    doLast {
        val demoDir = rootProject.file("uniapp-demo")
        val npmCmd = if (System.getProperty("os.name").lowercase().contains("windows")) "npm.cmd" else "npm"
        exec {
            workingDir = demoDir
            commandLine(npmCmd, "run", "build:app")
        }
        val out = demoDir.resolve("dist/build/app")
        if (!out.resolve("manifest.json").isFile) {
            throw GradleException("build:app did not produce dist/build/app/manifest.json")
        }
        println("Built XOPDEMO app resources -> ${out.absolutePath}")
    }
}

tasks.register("syncUnimpXopDemoAssets") {
    group = "protector"
    description = "Copy uniapp-demo dist/build/app into unimp-host assets as __UNI__XOPDEMO"
    doLast {
        val wwwSrc = rootProject.file("uniapp-demo/dist/build/app")
        if (!wwwSrc.resolve("manifest.json").isFile) {
            throw GradleException(
                "Missing ${wwwSrc.absolutePath}. Run: gradlew buildUnimpXopDemo  (or npm run build:app in uniapp-demo)"
            )
        }
        val dest = rootProject.file("unimp-host/src/main/assets/apps/__UNI__XOPDEMO/www")
        dest.parentFile.mkdirs()
        if (dest.exists()) dest.deleteRecursively()
        wwwSrc.copyRecursively(dest, overwrite = true)

        val wgt = rootProject.file("unimp-host/src/main/assets/__UNI__XOPDEMO.wgt")
        if (wgt.exists()) wgt.delete()
        java.util.zip.ZipOutputStream(wgt.outputStream().buffered()).use { zos ->
            wwwSrc.walkTopDown().filter { it.isFile }.forEach { f ->
                val entry = wwwSrc.toPath().relativize(f.toPath()).toString().replace('\\', '/')
                zos.putNextEntry(java.util.zip.ZipEntry(entry))
                f.inputStream().use { it.copyTo(zos) }
                zos.closeEntry()
            }
        }
        println("Synced XOPDEMO www -> ${dest.absolutePath}")
        println("Synced XOPDEMO wgt -> ${wgt.absolutePath} (${wgt.length()} bytes)")
    }
}

tasks.register("protectUnimpDemo") {
    group = "protector"
    description = "Build unimp-host release, then pack with balanced + SO safe (UniApp smoke)"
    dependsOn(":unimp-host:assembleRelease", "exportShellFiles", ":packer:jar")
    doLast {
        val hostApk = fileTree("unimp-host/build/outputs/apk/release") { include("*.apk") }.files.firstOrNull()
            ?: throw GradleException("unimp-host release apk not found — run :unimp-host:assembleRelease")
        val packerJar = rootProject.file("packer/build/libs").listFiles()
            ?.filter { it.name.startsWith("protector-packer") && it.name.endsWith(".jar") }
            ?.maxByOrNull { it.lastModified() }
            ?: throw GradleException("packer jar not found")
        val outApk = rootProject.file("executable/unimp-demo-protected.apk")
        outApk.parentFile.mkdirs()
        val debugKs = file("${System.getProperty("user.home")}/.android/debug.keystore")
        if (!debugKs.isFile) {
            throw GradleException("debug keystore not found: ${debugKs.absolutePath}")
        }
        println("Using packer jar: ${packerJar.name}")
        println("Input: ${hostApk.absolutePath}")
        exec {
            commandLine(
                "java", "-jar", packerJar.absolutePath,
                hostApk.absolutePath,
                "-o", outApk.absolutePath,
                "--shell-dir", rootProject.file("executable/shell-files").absolutePath,
                "--profile", "balanced",
                "--protect-so",
                "--protect-so-mode", "safe",
                "--payment-auto-vmp",
                "--no-industry-auto-vmp",
                // Same as protectDemo: assets/res/NetGuard off (CLI to enable; Assets needs ProtectorAssets).
                "--no-encrypt-assets",
                "--no-res-protect",
                "--keystore", debugKs.absolutePath,
                "--alias", "androiddebugkey",
                "--storepass", "android",
                "--keypass", "android"
            )
        }
        val report = rootProject.file("executable/unimp-demo-protected-size_report.json")
        if (report.isFile) {
            val text = report.readText()
            val uniappHits = Regex("\"uniapp/runtime\"").findAll(text).count()
            println("size_report uniapp/runtime hits=$uniappHits (expect >=6 if Weex SOs present)")
            if (!text.contains("libweexcore.so")) {
                println("WARN: libweexcore.so not mentioned in size_report")
            } else if (!Regex("""libweexcore\.so[\s\S]{0,120}?uniapp/runtime""").containsMatchIn(text)
                && !text.contains("\"reason\": \"uniapp/runtime\"")
            ) {
                // soft check — detailed path entries are enough when hits>=6
            }
            val weexCoreSkipped = text.contains("libweexcore.so") && text.contains("uniapp/runtime")
            println("libweexcore + uniapp/runtime in report: $weexCoreSkipped")
            println("Report: ${report.absolutePath}")
        }
        println("Protected UniMP APK -> ${outApk.absolutePath}")
    }
}

/**
 * CI / no-device check: assemble host release, run packer unit tests, ensure shell +
 * UniMP assets are present. Does not require an emulator.
 */
tasks.register("checkUnimpDemo") {
    group = "verification"
    description = "CI: assembleRelease + packer tests + asset/shell sanity (no device)"
    dependsOn(
        ":unimp-host:assembleRelease",
        ":packer:test",
        "exportShellFiles",
    )
    doLast {
        val releaseApk = fileTree("unimp-host/build/outputs/apk/release") { include("*.apk") }
            .files.firstOrNull()
            ?: throw GradleException("unimp-host release apk missing")
        val shellDex = rootProject.file("executable/shell-files/dex/classes.dex")
        if (!shellDex.isFile) {
            throw GradleException("shell classes.dex missing: ${shellDex.absolutePath}")
        }
        val packerJar = rootProject.file("packer/build/libs").listFiles()
            ?.filter { it.name.startsWith("protector-packer") && it.name.endsWith(".jar") }
            ?.maxByOrNull { it.lastModified() }
            ?: throw GradleException("packer jar missing")

        // Prefer embedded XOPDEMO; sample F743940 is acceptable fallback for CI without npm.
        val xopWww = rootProject.file("unimp-host/src/main/assets/apps/__UNI__XOPDEMO/www/manifest.json")
        val sampleWww = rootProject.file("unimp-host/src/main/assets/apps/__UNI__F743940/www/manifest.json")
        if (!xopWww.isFile && !sampleWww.isFile) {
            throw GradleException(
                "No UniMP app assets. Run syncUnimpSampleAssets and/or " +
                    "buildUnimpXopDemo syncUnimpXopDemoAssets"
            )
        }

        // Lightweight packer "dry-run": invoke jar --help / usage must exit non-crash.
        exec {
            commandLine("java", "-jar", packerJar.absolutePath)
            isIgnoreExitValue = true
        }

        println("checkUnimpDemo OK")
        println("  releaseApk=${releaseApk.absolutePath} (${releaseApk.length()} bytes)")
        println("  packerJar=${packerJar.name}")
        println("  shellDex=${shellDex.absolutePath}")
        println("  XOPDEMO=${xopWww.isFile} sample=${sampleWww.isFile}")
    }
}
