# esp-dns-sinkhole — DNS ad-blocker + Wake-on-LAN node for ESP32-C3 (ESP-IDF v6.1)
cmake_minimum_required(VERSION 3.22)

# Firmware version shown in the UI and embedded in the OTA image. CI overrides it
# from the git tag (-DPROJECT_VER=...).
if(NOT DEFINED PROJECT_VER)
    set(PROJECT_VER "0.1.0")
endif()

include($ENV{IDF_PATH}/tools/cmake/project.cmake)

project(esp-dns-sinkhole)
