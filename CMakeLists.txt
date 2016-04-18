project(CFGRecon)
cmake_minimum_required(VERSION 2.8)

set(CMAKE_BUILD_TYPE "None")

if(NOT PIN_ROOT_DIR)
  message(FATAL_ERROR
    "\nPin not found!\n"
    "Please set the environment variable PIN_ROOT_DIR to the base directory"
    " of the pin library.\n"
  )
endif(NOT PIN_ROOT_DIR)
message(STATUS "PIN_ROOT_DIR: ${PIN_ROOT_DIR}")

if(DEFINED ARCH)
  if (ARCH STREQUAL "intel64")
    set(PIN_CPU_ARCH "intel64")
    set(PIN_CPU_ARCH_LONG "intel64")
  else()
    set(PIN_CPU_ARCH "ia32")
    set(PIN_CPU_ARCH_LONG "ia32")
  endif()
else()
  set(PIN_CPU_ARCH "ia32")
  set(PIN_CPU_ARCH_LONG "ia32")
endif()

if (PIN_CPU_ARCH STREQUAL "intel64")
  message(STATUS "64 bit build")
else()
  message(STATUS "32 bit build")
endif()

set(PIN_INCLUDE_DIRS
  ${PIN_ROOT_DIR}/extras/xed-${PIN_CPU_ARCH_LONG}/include
  ${PIN_ROOT_DIR}/source/include/pin
  ${PIN_ROOT_DIR}/source/include/pin/gen
  ${PIN_ROOT_DIR}/extras/components/include
  ${LOCAL_INCLUDE_DIR})

set(PIN_LIB_DIRS
  ${PIN_ROOT_DIR}/extras/xed-${PIN_CPU_ARCH_LONG}/lib
  ${PIN_ROOT_DIR}/${PIN_CPU_ARCH_LONG}/lib
  ${PIN_ROOT_DIR}/${PIN_CPU_ARCH_LONG}/lib-ext)

set(XED_LIB_DIRS
  ${PIN_ROOT_DIR}/extras/xed-${PIN_CPU_ARCH_LONG}/lib)

set(SRC_LIST
  src/type/trace.pb.cc
  src/type/trace.pb.h
  src/type/instruction.cpp
  src/graph/graph.cpp
  src/graph/movf.cpp
  src/graph/examiner.cpp
  src/loader/loader.cpp
  src/export.h
  src/main.cpp
)

if(${CMAKE_SYSTEM_NAME} MATCHES "Windows")

  if(NOT PROTOBUF_ROOT_DIR)
    message(FATAL_ERROR
      "\nProtobuf library not found!\n"
      "Please set the environment variable PROTOBUF_ROOT_DIR\n"
      )
  endif(NOT PROTOBUF_ROOT_DIR)
  message(STATUS "PROTOBUF_ROOT_DIR: ${PROTOBUF_ROOT_DIR}")

  set(PROTOBUF_LIB_DIRS ${PROTOBUF_ROOT_DIR}/lib)
  set(PROTOBUF_INCLUDE_DIRS ${PROTOBUF_ROOT_DIR}/include)

  if(NOT DEFINED BOOST_ROOT_DIR)
    message(FATAL_ERROR "\nBoost not found!\n"
      "Please set the environment variable BOOST_ROOT_DIR to the base directory"
      " of the Boost library.\n")
  endif(NOT DEFINED BOOST_ROOT_DIR)
  message(STATUS "BOOST_ROOT_DIR: ${BOOST_ROOT_DIR}")

  #set(PIN_LIBS pin pinvm ntdll-32)
  set(XED_LIBS libxed libcpmt libcmt)
  set(PROTOBUF_LIBS libprotobuf)

  set(LINKER_DEFS "/D _MBCS /GS- /MT /EHsc /Ob2 /nologo")
  set(PIN_DEFS "/D TARGET_IA32 /D HOST_IA32 /D TARGET_WINDOWS /D USING_XED /D_SECURE_SCL=0 /D_ITERATOR_DEBUG_LEVEL=0 /Zc:auto")
  set(PROTOBUF_DEFS "/D PROTOBUF_USE_DLLS")

  include_directories(${BOOST_ROOT_DIR} ${PIN_INCLUDE_DIRS} ${PROTOBUF_INCLUDE_DIRS})
  link_directories(${PIN_LIB_DIRS} ${PROTOBUF_LIB_DIRS})

  add_definitions(${LINKER_DEFS} ${PIN_DEFS} ${PROTOBUF_DEFS})

  #set(CMAKE_CXX_FLAGS "${FUNC_DEFS} ${OTHER_DEFS} ${PIN_DEFS}")
  set(CMAKE_SHARED_LINKER_FLAGS "/EXPORT:main /NODEFAULTLIB /MACHINE:x86")

  #set(SRC_LIST ${LOADER_FILES} ${GRAPH_FILES})
  #aux_source_directory(src SRC_LIST)

  #add_executable(${PROJECT_NAME} ${SRC_LIST})
  #target_link_libraries(${PROJECT_NAME} ${PIN_LIBS} ${PROTOBUF_LIBS})

  add_executable(cfgrecon ${SRC_LIST})
  target_link_libraries(cfgrecon ${PIN_LIBS} ${XED_LIBS} ${PROTOBUF_LIBS})

else ()
  add_executable(cfgrecon ${SRC_LIST})

  set(PIN_DEFINITIONS "")
  if (PIN_CPU_ARCH STREQUAL "intel64")
    list(APPEND PIN_DEFINITIONS
      TARGET_LINUX
      BIGARRAY_MULTIPLIER=1
      USING_XED
      TARGET_IA32E HOST_IA32E)
  else()
     list(APPEND PIN_DEFINITIONS
       TARGET_LINUX
       BIGARRAY_MULTIPLIER=1
       USING_XED
       TARGET_IA32 HOST_IA32)
  endif()

#  set(PIN_DEFINITIONS "")
#  list(APPEND PIN_DEFINITIONS
#    TARGET_LINUX
#    BIGARRAY_MULTIPLIER=1
#    USING_XED
#    TARGET_IA32 HOST_IA32)

  # set(PIN_VERSION_SCRIPT ${PIN_ROOT_DIR}/source/include/pin/pintool.ver)
#  set(PIN_COMPILE_FLAGS "-Wall -Wno-unknown-pragmas -std=c++11 -m32 -MMD -O3 -fomit-frame-pointer -fno-strict-aliasing -fno-stack-protector")
#  set(PIN_LINKER_FLAGS "-Wl,--hash-style=sysv -Wl,-Bsymbolic -Wl,--version-script=${PIN_VERSION_SCRIPT}")

#  set(PIN_LINK_LIBS pin xed dwarf elf dl protobuf)
#  set(PIN_LINK_LIBS protobuf)

#  link_directories(${PIN_LIB_DIRS})
  include_directories(${PIN_INCLUDE_DIRS})

#  # set compile and link flags
#  set_source_files_properties(${SOURCES} PROPERTIES
#    COMPILE_FLAGS "${PIN_COMPILE_FLAGS}"
#    COMPILE_DEFINITIONS "${PIN_DEFINITIONS}")

if (PIN_CPU_ARCH STREQUAL "intel64")
  set_target_properties(cfgrecon PROPERTIES
    COMPILE_DEFINITIONS "${PIN_DEFINITIONS}"
    COMPILE_FLAGS "-std=c++11"
    LINK_FLAGS "-v")
else()
  set_target_properties(cfgrecon PROPERTIES
    # PREFIX ""
    # SUFFIX ".pin"
    COMPILE_DEFINITIONS "${PIN_DEFINITIONS}"
    COMPILE_FLAGS "${PIN_COMPILE_FLAGS}"
    COMPILE_FLAGS "-std=c++11 -m32"
    LINK_FLAGS "-v -m32")
endif()

  target_link_libraries(cfgrecon protobuf ${XED_LIB_DIRS}/libxed.a)
endif ()
