cmake_minimum_required(VERSION 2.8)
project(risao-test)
set(risao-test PROJECT_VERSION_MAJOR 0)
set(risao-test PROJECT_VERSION_MINOR 0)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# package required
find_package(Boost COMPONENTS filesystem REQUIRED)
find_package(LLVM REQUIRED CONFIG)
find_package(GTest REQUIRED)

link_directories("/usr/lib" ${Boost_LIBRARY_DIRS})

include_directories(${Boost_INCLUDE_DIRS})
include_directories(${LLVM_INCLUDE_DIRS})
add_definitions(${LLVM_DEFINITIONS})
llvm_map_components_to_libnames(llvm_libs support core irreader)


include_directories("${PROJECT_BINARY_DIR}")
include_directories("${PROJECT_SOURCE_DIR}/include")
set(LIB_SRC_DIR "${PROJECT_SOURCE_DIR}/src")

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++1z")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -std=c++1z -O0 -g3 -ggdb")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -std=c++1z -O3")

file(GLOB LIB_SRC
  "${LIB_SRC_DIR}/*.cpp"
  "${LIB_SRC_DIR}/*.c"
)

add_library(librisao STATIC ${LIB_SRC})
add_library(librisaoso SHARED ${LIB_SRC})

target_link_libraries(librisao ${Boost_LIBRARIES})
target_link_libraries(librisao ${llvm_libs})
target_link_libraries(librisao ${PYTHON_LIBRARY})
target_link_libraries(librisao elf)

file(GLOB EXEC_SRC
  "${PROJECT_SOURCE_DIR}/exec/*.cpp"
  )

file(GLOB TEST_SRC
  "${PROJECT_SOURCE_DIR}/test/*.cpp"
  )

foreach(src_file ${EXEC_SRC})
    get_filename_component(prog_name ${src_file} NAME_WE)
    add_executable(${prog_name} ${src_file})
    target_link_libraries(${prog_name} ${llvm_libs})
    target_link_libraries(${prog_name} elf) 
    target_link_libraries(${prog_name} librisao)
    target_link_libraries(${prog_name} ${Boost_LIBRARIES})   
endforeach(src_file ${EXEC_SRC})

enable_testing()
foreach(src_file ${TEST_SRC})
    get_filename_component(prog_name ${src_file} NAME_WE)
    add_executable(${prog_name} ${src_file})
    target_link_libraries(${prog_name} ${Boost_LIBRARIES})
    target_link_libraries(${prog_name} ${llvm_libs})
    target_link_libraries(${prog_name} librisao)
    target_link_libraries(${prog_name} elf)
    target_link_libraries(${prog_name} gtest_main)
    target_link_libraries(${prog_name} gtest)
    add_test(NAME ${prog_name} COMMAND ${prog_name})
endforeach(src_file ${TEST_SRC})
