set(CMAKE_SKIP_INSTALL_RULES ON)

include(FetchContent)

FetchContent_Declare(
  cxxopts
  GIT_REPOSITORY ${PROJECT_SOURCE_DIR}/libraries/cxxopts
  GIT_TAG v3.0.0
)

FetchContent_Declare(
  magic_enum
  GIT_REPOSITORY ${PROJECT_SOURCE_DIR}/libraries/magic_enum
  GIT_TAG v0.8.1
)

FetchContent_Declare(
  replxx
  GIT_REPOSITORY ${PROJECT_SOURCE_DIR}/libraries/replxx
  GIT_TAG release-0.0.4
)

FetchContent_MakeAvailable(cxxopts magic_enum replxx)

set(CMAKE_SKIP_INSTALL_RULES OFF)