cmake_minimum_required(VERSION 3.22.1)
project(protector)

set(CMAKE_CXX_STANDARD 20)

include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/ProtectorObfuscation.cmake)

# bytehook as STATIC (avoid its CMakeLists which requires CMake 4 + shared build).
# On arm/arm64 it needs shadowhook prefab from Gradle.
# Exclude bh_jni.c — it defines JNI_OnLoad which would conflict with our jni_bridge.cpp.
file(GLOB BHOOK_SOURCE external/bhook/bytehook/src/main/cpp/*.c)
list(FILTER BHOOK_SOURCE EXCLUDE REGEX ".*/bh_jni\\.c$")
add_library(bytehook STATIC ${BHOOK_SOURCE})
target_include_directories(bytehook PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/external/bhook/bytehook/src/main/cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/external/bhook/bytehook/src/main/cpp/include
        ${CMAKE_CURRENT_SOURCE_DIR}/external/bhook/bytehook/src/main/cpp/third_party/bsd
        ${CMAKE_CURRENT_SOURCE_DIR}/external/bhook/bytehook/src/main/cpp/third_party/lss)
target_compile_options(bytehook PRIVATE -Wno-everything)
target_link_libraries(bytehook log)
if ((CMAKE_ANDROID_ARCH_ABI STREQUAL "arm64-v8a") OR (CMAKE_ANDROID_ARCH_ABI STREQUAL "armeabi-v7a"))
    find_package(shadowhook REQUIRED CONFIG)
    target_link_libraries(bytehook shadowhook::shadowhook)
endif()

# dobby for DefineClass/LoadClass symbol hook
if (NOT TARGET dobby)
    set(DOBBY_DIR external/Dobby)
    macro(SET_OPTION option value)
        set(${option} ${value} CACHE INTERNAL "" FORCE)
    endmacro()
    SET_OPTION(DOBBY_DEBUG OFF)
    SET_OPTION(DOBBY_GENERATE_SHARED OFF)
    add_definitions(-DLOGGING_DISABLE)
    add_subdirectory(${DOBBY_DIR} dobby)
endif()

add_library(protector SHARED
        common/runtime_state.cpp
        common/crc32.cpp
        common/elf_util.cpp
        common/sys_io.cpp
        crypto/rc4.c
        crypto/aes.cpp
        crypto/sha256.cpp
        crypto/apk_sign.cpp
        crypto/key_ladder.cpp
        crypto/section_decrypt.cpp
        crypto/assets_crypt.cpp
        codeitem/multi_dex_code.cpp
        dex/dex_file.cpp
        hook/hooks.cpp
        runtime/engine.cpp
        jni/jni_bridge.cpp
        risk/risk.cpp
        risk/so_guard.cpp
        report/threat_report.cpp
        crypto/dex_asset.cpp
        vm/vm_codec.cpp
        vm/pvm2_format.cpp
        vm/pvm2_interp.cpp
        so/business_so.cpp
)

target_include_directories(protector PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/external/Dobby/include
        ${CMAKE_CURRENT_SOURCE_DIR}/external/bhook/bytehook/src/main/cpp/include
        ${CMAKE_CURRENT_SOURCE_DIR}/external/json
)

target_compile_options(protector PRIVATE -Wall -Wextra)
# Hi-MC field tablets are often pre-ARMv8.3; paciasp/BTI → SIGILL on load.
# Keep ROP hardening off until we gate by HWCAP_AP at runtime.
if (CMAKE_ANDROID_ARCH_ABI STREQUAL "arm64-v8a")
    target_compile_options(protector PRIVATE -mbranch-protection=none)
endif()
target_link_options(protector PRIVATE "-Wl,-z,max-page-size=16384")

find_library(log-lib log)
find_library(android-lib android)
find_library(z-lib z)

target_link_libraries(protector
        ${log-lib}
        ${android-lib}
        ${z-lib}
        dobby
        bytehook
)

# Always decrypt .bitcode at load; packer encrypts libprotector.so before packaging.
target_compile_definitions(protector PRIVATE DECRYPT_BITCODE=1)

if (CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_definitions(protector PRIVATE DEBUG=1)
else()
    target_compile_definitions(protector PRIVATE NDEBUG=1)
endif()

# Phase 7 — source-level CFF/BCF (default ON) + optional LLVM passes on sensitive TUs.
if (PROTECTOR_SRC_OBF)
    target_compile_definitions(protector PRIVATE PROTECTOR_SRC_OBF=1)
    message(STATUS "PROTECTOR_SRC_OBF=ON")
else()
    target_compile_definitions(protector PRIVATE PROTECTOR_SRC_OBF=0)
    message(STATUS "PROTECTOR_SRC_OBF=OFF")
endif()
protector_apply_llvm_obf(protector)

enable_language(ASM)
