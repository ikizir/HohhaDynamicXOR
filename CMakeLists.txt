project(HohhaBench)
cmake_minimum_required(VERSION 2.8)
cmake_policy(SET CMP0002 OLD)

set(ISOLIB_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../isolib)
#YOU MUST MANUALLY ENTER TO B64_DIR and RUN make command once
#IT IS A FULL SYSTEM PATH! ON EVERY MACHINE, ON THE SAME PATH IT MUST BE INSTALLED
set(B64_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../base64)

MESSAGE( STATUS "CMAKE_SYSTEM: " ${CMAKE_SYSTEM} )
# the short system name, e.g. "Linux", "FreeBSD" or "Windows"
MESSAGE( STATUS "CMAKE_SYSTEM_NAME: " ${CMAKE_SYSTEM_NAME} )

# only the version part of CMAKE_SYSTEM 
MESSAGE( STATUS "CMAKE_SYSTEM_VERSION: " ${CMAKE_SYSTEM_VERSION} )

# the processor name (e.g. "Intel(R) Pentium(R) M processor 2.00GHz") 
MESSAGE( STATUS "CMAKE_SYSTEM_PROCESSOR: " ${CMAKE_SYSTEM_PROCESSOR} )

# is TRUE on all UNIX-like OS's, including Apple OS X and CygWin
MESSAGE( STATUS "UNIX: " ${UNIX} )

# is TRUE on Windows, including CygWin 
MESSAGE( STATUS "WIN32: " ${WIN32} )

# is TRUE on Apple OS X
MESSAGE( STATUS "APPLE: " ${APPLE} )

# the compiler used for C files 
MESSAGE( STATUS "CMAKE_C_COMPILER: " ${CMAKE_C_COMPILER} )

# the compiler used for C++ files 
MESSAGE( STATUS "CMAKE_CXX_COMPILER: " ${CMAKE_CXX_COMPILER} )

# if the compiler is a variant of gcc, this should be set to 1 
MESSAGE( STATUS "CMAKE_COMPILER_IS_GNUCC: " ${CMAKE_COMPILER_IS_GNUCC} )

# if the compiler is a variant of g++, this should be set to 1 
MESSAGE( STATUS "CMAKE_COMPILER_IS_GNUCXX : " ${CMAKE_COMPILER_IS_GNUCXX} )

include_directories(${CMAKE_CURRENT_SOURCE_DIR} ${ISOLIB_DIR} ${B64_DIR}/include/)
set(CMAKE_C_FLAGS_DEBUG "-I${CMAKE_CURRENT_SOURCE_DIR} -I${ISOLIB_DIR} -I${B64_DIR}/include/ -Wall -std=gnu99 -g -O0 -fno-inline -D_GNU_SOURCE -Wno-packed-bitfield-compat")
#-DNDEBUG disables assert commands
set(CMAKE_C_FLAGS_PRODUCTION "-I${CMAKE_CURRENT_SOURCE_DIR} -I${ISOLIB_DIR} -I${B64_DIR}/include/ -std=gnu99 -O3 -D_GNU_SOURCE -DNDEBUG -march=native -mtune=native")
set(CMAKE_C_FLAGS ${CMAKE_C_FLAGS_PRODUCTION})

set(B64_SOURCE
   ${B64_DIR}/lib/libbase64.o
)
set(B64_HEADERS
  ${B64_DIR}/include/libbase64.h
)

set(SOURCE
   ${B64_SOURCE}
   ${CMAKE_CURRENT_SOURCE_DIR}/VarInt.c
   ${CMAKE_CURRENT_SOURCE_DIR}/HohhaXor.c
   ${CMAKE_CURRENT_SOURCE_DIR}/BenchMain.c
)
set(HEADERS
   ${CMAKE_CURRENT_SOURCE_DIR}/VarInt.h
   ${CMAKE_CURRENT_SOURCE_DIR}/HohhaXor.h
   ${B64_HEADERS}
)

add_executable(${PROJECT_NAME} ${SOURCE})
set_target_properties(${PROJECT_NAME} PROPERTIES LINKER_LANGUAGE C)
target_link_libraries(${PROJECT_NAME})
