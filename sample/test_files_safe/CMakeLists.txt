cmake_minimum_required(VERSION 3.14)
project(MyProject VERSION 1.0.0 LANGUAGES CXX)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Include FetchContent module for downloading dependencies
include(FetchContent)

# ============================================================================
# External Dependencies
# ============================================================================

# nlohmann/json library - JSON for Modern C++
FetchContent_Declare(
    json
    GIT_REPOSITORY https://github.com/nlohmann/json.git
    GIT_TAG v3.11.3
)

# cpr library - C++ Requests: Curl for People
# Note: cpr depends on libcurl
FetchContent_Declare(
    cpr
    GIT_REPOSITORY https://github.com/libcpr/cpr.git
    GIT_TAG 1.10.5
)

# Make dependencies available
FetchContent_MakeAvailable(json cpr)

# ============================================================================
# Project Target
# ============================================================================

# Add your executable
add_executable(${PROJECT_NAME} 
    main.cpp
    # Add other source files here as needed
)

# Link libraries to the executable
target_link_libraries(${PROJECT_NAME} 
    PRIVATE 
    nlohmann_json::nlohmann_json
    cpr::cpr
)

# ============================================================================
# Compiler Settings
# ============================================================================

# Set compiler warnings
if(MSVC)
    target_compile_options(${PROJECT_NAME} PRIVATE /W4 /WX-)
else()
    target_compile_options(${PROJECT_NAME} PRIVATE 
        -Wall 
        -Wextra 
        -Wpedantic
    )
endif()

# ============================================================================
# Output Configuration
# ============================================================================

# Set output directories
set_target_properties(${PROJECT_NAME} PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)

# Print configuration summary
message(STATUS "")
message(STATUS "=== ${PROJECT_NAME} Configuration ===")
message(STATUS "Project Version: ${PROJECT_VERSION}")
message(STATUS "C++ Standard: ${CMAKE_CXX_STANDARD}")
message(STATUS "Build Type: ${CMAKE_BUILD_TYPE}")
message(STATUS "Compiler: ${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION}")
message(STATUS "Dependencies:")
message(STATUS "  - nlohmann/json: v3.11.3")
message(STATUS "  - cpr: v1.10.5 (includes libcurl)")
message(STATUS "===================================")
message(STATUS "")