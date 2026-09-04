cmake_minimum_required(VERSION 3.10)

if(${CMAKE_VERSION} VERSION_LESS 3.10)
    cmake_policy(VERSION ${CMAKE_MAJOR_VERSION}.${CMAKE_MINOR_VERSION})
endif()

# project information
project(unit_tests
        VERSION 0.1
        DESCRIPTION "Unit tests for the QRL v2.0 Ledger application"
        LANGUAGES C)


# guard against bad build-type strings
if (NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE "Debug")
endif()

include(CTest)
ENABLE_TESTING()

# specify C standard
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED True)
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -Wall -Wextra -Werror -pedantic -g -O0 --coverage -fsanitize=address,undefined -fno-omit-frame-pointer")

set(GCC_COVERAGE_LINK_FLAGS "--coverage -lgcov")
set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} ${GCC_COVERAGE_LINK_FLAGS}")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} ${GCC_COVERAGE_LINK_FLAGS} -fsanitize=address,undefined")

# guard against in-source builds
if(${CMAKE_SOURCE_DIR} STREQUAL ${CMAKE_BINARY_DIR})
  message(FATAL_ERROR "In-source builds not allowed. Please make a new directory (called a build directory) and run CMake from there. You may need to remove CMakeCache.txt. ")
endif()

add_compile_definitions(TEST)

# stubs/ provides a host cx.h (PRINTF only) so device sources compile off-device
include_directories(stubs)
include_directories(../src)
include_directories(../src/mldsa87)
include_directories(../src/ui)

add_executable(test_rlp_decode test_rlp_decode.c)
add_executable(test_tx_format test_tx_format.c)
add_executable(test_hash_kat test_hash_kat.c)
add_executable(test_address_format test_address_format.c)

add_library(rlp_decode ../src/mldsa87/rlp_decode.c)
add_library(tx_format ../src/ui/tx_format.c)
# One shared Keccak-f permutation behind all three sponges.
add_library(hashes ../src/mldsa87/keccakf.c
                   ../src/mldsa87/keccak256.c
                   ../src/mldsa87/shake128.c
                   ../src/mldsa87/shake256.c)
add_library(address_format ../src/address_format.c)

target_link_libraries(test_rlp_decode PUBLIC
                      rlp_decode
                      cmocka
                      gcov)

add_test(test_rlp_decode test_rlp_decode)
target_link_libraries(test_tx_format PUBLIC tx_format cmocka gcov)
add_test(test_tx_format test_tx_format)

target_link_libraries(test_hash_kat PUBLIC hashes cmocka gcov)
add_test(test_hash_kat test_hash_kat)

target_link_libraries(test_address_format PUBLIC address_format hashes cmocka gcov)
add_test(test_address_format test_address_format)
