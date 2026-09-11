cmake_minimum_required(VERSION 3.20)
project(vauth-agent-example LANGUAGES CXX)

find_package(sdbus-c++ CONFIG REQUIRED)

add_executable(vauth-agent-example agent.cpp)
target_compile_features(vauth-agent-example PRIVATE cxx_std_20)
target_link_libraries(vauth-agent-example PRIVATE SDBusCpp::sdbus-c++)
