project(submodule_libraries)
add_executable(${PROJECT_NAME} 
    sqlite/build/sqlite3.c
    ssl/crypto/sha/sha512.c
    )
