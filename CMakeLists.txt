cmake_minimum_required(VERSION 3.21)

project(zyrecorder LANGUAGES C)

find_package(Git)
add_custom_target(version
    ${CMAKE_COMMAND} -D SRC=${CMAKE_SOURCE_DIR}/src/zyrecorder_version.h.in
                     -D DST=${CMAKE_BINARY_DIR}/zyrecorder_version.h
                     -D GIT_EXECUTABLE=${GIT_EXECUTABLE}
                     -P ${CMAKE_SOURCE_DIR}/GenerateVersionHeader.cmake
)

find_package(SQLite3 REQUIRED)

find_package(PkgConfig REQUIRED)
pkg_check_modules(ZMQ REQUIRED libzmq)
pkg_check_modules(CZMQ REQUIRED libczmq)
pkg_check_modules(ZYRE REQUIRED libzyre)

add_executable(${CMAKE_PROJECT_NAME} src/main.c)
add_dependencies(${CMAKE_PROJECT_NAME} version)
set_property(TARGET ${CMAKE_PROJECT_NAME} PROPERTY C_STANDARD 17)
target_link_libraries(
    ${CMAKE_PROJECT_NAME}
    PRIVATE
    SQLite::SQLite3 ${ZMQ_LIBRARIES} ${CZMQ_LIBRARIES} ${ZYRE_LIBRARIES}
    )
target_include_directories(
    ${CMAKE_PROJECT_NAME}
    PRIVATE
    ${CMAKE_BINARY_DIR} ${ZMQ_INCLUDE_DIRS} ${CZMQ_INCLUDE_DIRS} ${ZYRE_INCLUDE_DIRS}
    )
target_compile_options(
    ${CMAKE_PROJECT_NAME}
    PRIVATE
    ${ZMQ_CFLAGS_OTHER} ${CZMQ_CFLAGS_OTHER} ${ZYRE_CFLAGS_OTHER}
    )
