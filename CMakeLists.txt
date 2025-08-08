cmake_minimum_required(VERSION 3.10.2)
project(mavdump)

# Default to C++20
if(NOT CMAKE_CXX_STANDARD)
  set(CMAKE_CXX_STANDARD 20)
endif()

# 编译器警告设置
if(CMAKE_COMPILER_IS_GNUCXX OR CMAKE_CXX_COMPILER_ID MATCHES "Clang")
  add_compile_options(-Wall -Wextra -Wreturn-type)
endif()

# 平台检测和平台特定设置
if(APPLE)
    message(STATUS "配置 macOS 构建")
    add_definitions(-D__APPLE__)
    # macOS 特定的编译选项
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-deprecated-declarations")
elseif(UNIX AND NOT APPLE)
    message(STATUS "配置 Linux 构建")
    add_definitions(-D__linux__)
    # Linux 特定的编译选项
endif()

include(FetchContent)
FetchContent_Declare(mavlink
    GIT_REPOSITORY https://github.com/mavlink/c_library_v2.git
    GIT_TAG 878a0660666bbb7b982bad4f0d10fad88b1b82d1
)
FetchContent_MakeAvailable(mavlink)
include_directories(
    ${mavlink_SOURCE_DIR}
)

# PCAP 库依赖配置
find_package(PkgConfig REQUIRED)

if(APPLE)
    # macOS 使用 Homebrew 安装的 libpcap
    set(ENV{PKG_CONFIG_PATH} "/opt/homebrew/opt/libpcap/lib/pkgconfig:$ENV{PKG_CONFIG_PATH}")
    message(STATUS "macOS: 设置 PKG_CONFIG_PATH 为 Homebrew libpcap")
endif()

pkg_check_modules(PCAP REQUIRED libpcap)

# 创建可执行文件
add_executable(${PROJECT_NAME}
    mavdump.cpp
    mavlink_network_analyzer.cpp
)

# 包含目录
target_include_directories(${PROJECT_NAME} PRIVATE
    ${PCAP_INCLUDE_DIRS}
)

# 链接库
target_link_libraries(${PROJECT_NAME}
    ${PCAP_LIBRARIES}
)

# 编译定义
target_compile_definitions(${PROJECT_NAME} PRIVATE
    ${PCAP_CFLAGS_OTHER}
    MAVLINK_USE_MESSAGE_INFO  # 启用MAVLink消息信息功能
)