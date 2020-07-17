cmake_minimum_required( VERSION 3.16)

## Required software
#find_package( <<<name>>> REQUIRED )

## Sources and headers
include_directories( ${CMAKE_CURRENT_SOURCE_DIR} )

## Find all source files to be compiled into object files
file( GLOB SOURCES *.c *.cc )

## C++ compiler options
set( CMAKE_CXX_FLAGS "-Wall -Wextra" )
set( CMAKE_CXX_FLAGS_DEBUG "-g -O0" )
set( CMAKE_CXX_FLAGS_RELEASE "-O3" )
set( CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS}-lssl -lcrypto -lpthread")
## Source file containing the "main" function
set( TLSDEMO_SOURCES tlsdemo.cc)
## Specify a name for the generated executable file
set( TLSDEMO_EXE server )


## 1. Compile...
add_executable( ${TLSDEMO_EXE} ${TLSDEMO_SOURCES} ${SOURCES})

## 2. Link...
target_link_libraries( ${TLSDEMO_EXE} ${CMAKE_EXE_LINKER_FLAGS}  )

## 3. Install...
install( TARGETS ${TLSDEMO_EXE} RUNTIME DESTINATION bin )
