cmake_minimum_required(VERSION 3.14)
project(ScamShieldScanner CXX)

set(CMAKE_CXX_STANDARD 17)

# Fetch Crow C++ Microframework
include(FetchContent)
FetchContent_Declare(
    crow
    GIT_REPOSITORY https://github.com/CrowCpp/Crow.git
    GIT_TAG v1.0+5
)
FetchContent_MakeAvailable(crow)

add_executable(scam_shield_scanner main.cpp RiskEngine.hpp)
target_link_libraries(scam_shield_scanner PRIVATE Crow::Crow)
