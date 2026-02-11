cmake_minimum_required(VERSION 3.21)

project(vms_streamer_qt VERSION 0.1 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

find_package(Qt6 REQUIRED COMPONENTS Widgets Charts)

# Prefer Homebrew curl to avoid pulling in stray Qt headers from other bundles.
set(_curl_roots "")
if(APPLE)
    list(APPEND _curl_roots "/opt/homebrew/opt/curl" "/usr/local/opt/curl" "/usr")
endif()

find_path(CURL_INCLUDE_DIR
    NAMES curl/curl.h
    HINTS ${_curl_roots}
    PATH_SUFFIXES include
    NO_DEFAULT_PATH
)
find_library(CURL_LIBRARY
    NAMES curl libcurl
    HINTS ${_curl_roots}
    PATH_SUFFIXES lib
    NO_DEFAULT_PATH
)

if(CURL_INCLUDE_DIR AND CURL_LIBRARY)
    add_library(CURL::libcurl UNKNOWN IMPORTED)
    set_target_properties(CURL::libcurl PROPERTIES
        IMPORTED_LOCATION "${CURL_LIBRARY}"
        INTERFACE_INCLUDE_DIRECTORIES "${CURL_INCLUDE_DIR}"
    )
else()
    find_package(CURL REQUIRED)
endif()

# OpenSSL for Fernet decryption (credentials).
if(APPLE)
    if(EXISTS "/opt/homebrew/opt/openssl@3")
        set(OPENSSL_ROOT_DIR "/opt/homebrew/opt/openssl@3")
    elseif(EXISTS "/opt/homebrew/opt/openssl@1.1")
        set(OPENSSL_ROOT_DIR "/opt/homebrew/opt/openssl@1.1")
    elseif(EXISTS "/usr/local/opt/openssl@3")
        set(OPENSSL_ROOT_DIR "/usr/local/opt/openssl@3")
    elseif(EXISTS "/usr/local/opt/openssl@1.1")
        set(OPENSSL_ROOT_DIR "/usr/local/opt/openssl@1.1")
    endif()
endif()

find_package(OpenSSL REQUIRED)

add_executable(vms_streamer_qt
    src/main.cpp
    src/MainWindow.h
    src/MainWindow.cpp
)

target_link_libraries(vms_streamer_qt PRIVATE Qt6::Widgets Qt6::Charts CURL::libcurl OpenSSL::Crypto)

if(APPLE)
    set(APP_ICON "${CMAKE_CURRENT_SOURCE_DIR}/resources/vmsstreamer.icns")
    if(EXISTS "${APP_ICON}")
        set_source_files_properties("${APP_ICON}" PROPERTIES MACOSX_PACKAGE_LOCATION "Resources")
        target_sources(vms_streamer_qt PRIVATE "${APP_ICON}")
    endif()
    set_target_properties(vms_streamer_qt PROPERTIES
        MACOSX_BUNDLE TRUE
        MACOSX_BUNDLE_GUI_IDENTIFIER "com.example.vmsstreamer"
        MACOSX_BUNDLE_BUNDLE_NAME "VMSstreamerQt"
        OUTPUT_NAME "VMSstreamerQt"
        MACOSX_BUNDLE_ICON_FILE "vmsstreamer.icns"
    )
endif()

include(GNUInstallDirs)

install(TARGETS vms_streamer_qt
    BUNDLE DESTINATION .
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

# Deploy Qt runtime dependencies when installing.
if(COMMAND qt_generate_deploy_app_script)
    qt_generate_deploy_app_script(
        TARGET vms_streamer_qt
        OUTPUT_SCRIPT deploy_script
        NO_UNSUPPORTED_PLATFORM_ERROR
    )
    install(SCRIPT ${deploy_script})
endif()

# CPack (for MSI on Windows)
set(CPACK_PACKAGE_NAME "VMSstreamerQt")
set(CPACK_PACKAGE_VENDOR "adakite")
set(CPACK_PACKAGE_CONTACT "adakite")
set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})
set(CPACK_PACKAGE_INSTALL_DIRECTORY "VMSstreamerQt")
set(CPACK_PACKAGE_FILE_NAME "VMSstreamerQt-${PROJECT_VERSION}-${CMAKE_SYSTEM_NAME}")

if(WIN32)
    set(CPACK_GENERATOR "WIX")
    set(CPACK_WIX_UPGRADE_GUID "B3362418-6EF6-4F00-BDD9-0A2A83DBFE32")
    set(CPACK_WIX_PRODUCT_ICON "${CMAKE_CURRENT_SOURCE_DIR}/resources/vmsstreamer.ico")
endif()

include(CPack)
