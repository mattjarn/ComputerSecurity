CMAKE_MINIMUM_REQUIRED (VERSION 3.2.2)

# Project - Core Settings
PROJECT (aes C)
SET (CMAKE_BUILD_TYPE Debug)

# Project - Compiler Flags
SET (CSTANDARD "-std=c11")
SET (CDEBUG    "-g")
SET (CFLAGS    "${CSTANDARD} -Wall")
SET (CMAKE_C_FLAGS   "${CFLAGS} ${CDEBUG}")

# Project - Paths
SET (BASE_PATH "${${PROJECT_NAME}_SOURCE_DIR}")
SET (INC_PATH  "${BASE_PATH}/include")
SET (SRC_PATH  "${BASE_PATH}/src")

INCLUDE_DIRECTORIES(include)

# Project - Sources
SET (LIB_SRCS "${SRC_PATH}/aes.c")
SET (BIN_SRCS "${SRC_PATH}/cli.c")

# Project - Includes
INCLUDE_DIRECTORIES (${INC_PATH})

# Project - Final executable
ADD_LIBRARY (aes SHARED ${LIB_SRCS})
ADD_EXECUTABLE (aes-cli ${BIN_SRCS})

TARGET_LINK_LIBRARIES (aes-cli aes)

# Install the shared object
INSTALL (TARGETS aes-cli aes
         RUNTIME DESTINATION bin
         LIBRARY DESTINATION lib)
INSTALL (CODE "execute_process(COMMAND ldconfig)")
