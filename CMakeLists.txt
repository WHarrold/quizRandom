cmake_minimum_required(VERSION 3.10)

project(quizRandom)

set(CMAKE_CXX_STANDARD 11)

include_directories(${PROJECT_SOURCE_DIR})

find_package(OpenSSL REQUIRED)

find_package (SQLite3 REQUIRED)


target_include_directories(${PROJECT_NAME} PRIVATE ${SQLite3_INCLUDE_DIRS})


add_executable(${PROJECT_NAME} 
src/trial.cpp 
headers/crypto.cpp)
target_link_libraries(${PROJECT_NAME} OpenSSL::Crypto)

target_link_libraries (${PROJECT_NAME} SQLite3::SQLite3)
