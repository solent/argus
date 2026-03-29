cmake_minimum_required(VERSION 3.10)
project(VulnerableCurlExample)

# Find the libcurl library (required)
find_package(CURL REQUIRED)

# Create the executable
add_executable(vuln vuln.cpp)

FetchContent_Declare(
    curl
    GIT_REPOSITORY https://github.com/curl/curl.git
    GIT_TAG curl-7_18_0  # Vulnerable version
)
FetchContent_MakeAvailable(json cpr curl)

# Link against libcurl
target_link_libraries(vuln PRIVATE ${CURL_LIBRARIES})
target_include_directories(vuln PRIVATE ${CURL_INCLUDE_DIRS})

# Optional: warn if the found libcurl is not vulnerable
if(CURL_VERSION_STRING VERSION_LESS "7.24.0")
    message(STATUS "Using vulnerable version of libcurl (< 7.24.0) – this matches CVE-2012-0036.")
else()
    message(WARNING "This code is intended to demonstrate CVE-2012-0036, but your libcurl version (${CURL_VERSION_STRING}) is NOT vulnerable. The issue exists only in versions before 7.24.0.")
endif()