cmake_minimum_required(VERSION 3.16)

# Project metadata kept minimal for portability
project(malrev VERSION 1.0.0 LANGUAGES CXX)

# Require C++20 for stronger type safety and std::span
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Enable warnings
if (MSVC)
  add_compile_options(/W4 /WX-)
else()
  add_compile_options(-Wall -Wextra -Wpedantic -Werror)
endif()

# Position independent code for potential static libs
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Sources
file(GLOB_RECURSE MALREV_SOURCES CONFIGURE_DEPENDS
  "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp"
)

add_executable(malrev ${MALREV_SOURCES})
target_include_directories(malrev PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)

# Platform defs
if (WIN32)
  target_compile_definitions(malrev PRIVATE MALREV_PLATFORM_WINDOWS=1)
elseif(UNIX)
  target_compile_definitions(malrev PRIVATE MALREV_PLATFORM_LINUX=1)
endif()

# Link libraries for Linux ptrace if needed (no extra libs required for basic usage)
# Nothing special by default.
