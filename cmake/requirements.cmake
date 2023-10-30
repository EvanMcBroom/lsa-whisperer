include(FetchContent)

# Do not use FetchContent to pin repos to a specific version
# The git submodules they reference are already pinned to a version
FetchContent_Declare(clipp GIT_REPOSITORY ${PROJECT_SOURCE_DIR}/libraries/clipp)
FetchContent_Declare(cxxopts GIT_REPOSITORY ${PROJECT_SOURCE_DIR}/libraries/cxxopts)
FetchContent_Declare(magic_enum GIT_REPOSITORY ${PROJECT_SOURCE_DIR}/libraries/magic_enum)
FetchContent_Declare(replxx GIT_REPOSITORY ${PROJECT_SOURCE_DIR}/libraries/replxx)

# Set the build type for replxx to not output noisy messages
if(NOT DEFINED CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release) 
  set(BUILD_TYPE_SET TRUE) 
endif()
FetchContent_MakeAvailable(clipp cxxopts magic_enum replxx)
if(DEFINED BUILD_TYPE_SET)
  unset(CMAKE_BUILD_TYPE)
  unset(BUILD_TYPE_SET)
endif()