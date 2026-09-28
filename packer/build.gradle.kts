plugins {
    id("java")
}

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

tasks.jar {
    archiveBaseName.set("protector-packer")
    archiveVersion.set("0.7.1")
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE
    manifest {
        attributes["Main-Class"] = "com.yqsh.protector.packer.PackerMain"
    }
    from({
        configurations.runtimeClasspath.get().filter { it.exists() }.map {
            if (it.isDirectory) it else zipTree(it)
        }
    })
    exclude("META-INF/*.SF", "META-INF/*.DSA", "META-INF/*.RSA", "META-INF/*.MF")
}

tasks.test {
    useJUnitPlatform()
}

dependencies {
    implementation(fileTree(mapOf("dir" to "libs", "include" to listOf("*.jar"))))
    implementation("net.lingala.zip4j:zip4j:2.11.5")
    implementation("com.android.tools.smali:smali-dexlib2:3.0.9")
    implementation("com.google.guava:guava:33.0.0-jre")
    implementation("commons-io:commons-io:2.15.1")
    implementation("org.apache.commons:commons-lang3:3.14.0")
    implementation("com.linkedin.dexmaker:dexmaker:2.28.5")

    testImplementation("org.junit.jupiter:junit-jupiter:5.10.2")
}
