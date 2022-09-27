set(CMAKE_SKIP_INSTALL_RULES ON)

include(FetchContent)

FetchContent_Declare(
  cli
  GIT_REPOSITORY ${PROJECT_SOURCE_DIR}/libraries/cli
  # Added check for CMAKE_SKIP_INSTALL_RULES (#160)
  # https://github.com/daniele77/cli/commit/10c570db45d2209e5c6801a6a1eb8ac6cc941f7a
  GIT_TAG 10c570db45d2209e5c6801a6a1eb8ac6cc941f7a
)
FetchContent_MakeAvailable(cli)

FetchContent_Declare(
  cxxopts
  GIT_REPOSITORY ${PROJECT_SOURCE_DIR}/libraries/cxxopts
  GIT_TAG v3.0.0
)
FetchContent_MakeAvailable(cxxopts)

FetchContent_Declare(
  magic_enum
  GIT_REPOSITORY ${PROJECT_SOURCE_DIR}/libraries/magic_enum
  GIT_TAG v0.8.1
)
FetchContent_MakeAvailable(magic_enum)