pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "XopProtector"
include(":native")
include(":demo")
include(":packer")

// UniMP host needs local SDK AARs; skip when missing so packer/native/desktop still build.
val unimpLibsProp = providers.gradleProperty("unimp.sdk.libs").orNull?.trim().orEmpty()
val unimpLibsEnv = System.getenv("UNIMP_SDK_LIBS")?.trim().orEmpty()
val unimpLibsCandidates = listOfNotNull(
    unimpLibsProp.takeIf { it.isNotEmpty() }?.let { file(it) },
    unimpLibsEnv.takeIf { it.isNotEmpty() }?.let { file(it) },
    file("../SDK-Android@5.14-20260706/SDK/libs"),
)
if (unimpLibsCandidates.any { it.isDirectory }) {
    include(":unimp-host")
} else {
    logger.warn(
        "Skipping :unimp-host — UniMP SDK libs not found. " +
            "Set unimp.sdk.libs in gradle.properties to enable it."
    )
}
