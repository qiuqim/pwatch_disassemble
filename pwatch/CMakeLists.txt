cmake_minimum_required(VERSION 3.10)

if (NOT DEFINED CMAKE_ANDROID_NDK)
    set(CMAKE_ANDROID_NDK D:/ndkollvm/android-ndk-r25c.Ollvm/android-ndk-r25c)
    set(CMAKE_TOOLCHAIN_FILE ${CMAKE_ANDROID_NDK}/build/cmake/android.toolchain.cmake)
    set(CMAKE_SYSTEM_NAME Android)
    set(CMAKE_SYSTEM_VERSION 24)
    set(CMAKE_ANDROID_ARCH_ABI arm64-v8a)
    set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
    set(ANDROID_ABI arm64-v8a)
    set(ANDROID_PLATFORM android-26)
    set(ANDROID_NDK ${CMAKE_ANDROID_NDK})
else ()
    SET(ANDROID_STUDIO_BUILD true)
endif ()


project(pwatch_c)

set(CMAKE_CXX_STANDARD 23)

#链接静态库capstone
# 指定Capstone头文件目录
include_directories(${CMAKE_SOURCE_DIR}/capstone)

# 指定Capstone静态库目录（如果静态库不在标准路径中）
link_directories(${CMAKE_SOURCE_DIR}/capstone/libs)


add_executable(pwatch_c
        main.cpp
        PerfMap.cpp disasm.cpp disasm.h)

target_link_libraries(pwatch_c libcapstone.a)