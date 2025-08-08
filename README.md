# MAVLink 网络数据包分析工具

这是一个用于捕获和解析网络中 MAVLink 数据包的工具。它可以：

1. 接受 tcpdump 的输出文件并解析其中的 MAVLink 消息
2. 直接进行网络数据包捕获，实时解析 MAVLink 消息
3. 提取网络数据包的纯 payload 部分
4. 解析 MAVLink 消息并输出详细的日志信息

## 功能特性

- **文件解析模式**: 解析已有的 tcpdump 输出文件
- **实时捕获模式**: 直接从网络接口捕获数据包
- **详细日志**: 输出源地址、目标地址、MAVLink 消息类型和内容
- **多种消息支持**: 支持常见的 MAVLink 消息类型解析
- **灵活配置**: 可配置端口号、网络接口等参数

## 跨平台支持

本工具支持以下平台：
- **macOS** (Intel 和 Apple Silicon)
- **Linux** (Ubuntu, CentOS, RHEL 等)

平台特定的网络结构体差异已通过兼容层自动处理。

## 编译

### 依赖要求

根据您的操作系统安装以下依赖：

#### macOS
```bash
# 使用 Homebrew 安装
brew install libpcap
brew install cmake
brew install pkg-config
```

#### Ubuntu/Debian
```bash
sudo apt-get update
sudo apt-get install libpcap-dev cmake build-essential pkg-config git
```

#### CentOS/RHEL/Fedora
```bash
# CentOS/RHEL 7/8
sudo yum install libpcap-devel cmake gcc-c++ make pkg-config git
# 或者 Fedora
sudo dnf install libpcap-devel cmake gcc-c++ make pkg-config git
```

### 编译步骤

该项目使用 CMake 构建系统，在所有支持的平台上编译步骤相同：

```bash
# 克隆项目（如果还没有）
git clone <repository-url>
cd mavdump

# 创建构建目录
mkdir build
cd build

# 配置并编译
cmake ..
make -j$(nproc)  # Linux
# 或者
make -j$(sysctl -n hw.ncpu)  # macOS

# 或者使用 cmake 统一命令
cmake --build . -j
```

### 在 ROS2 工作空间中编译：

```bash
cd /path/to/ros2_ws
colcon build --packages-select codevsdk
```

## 使用方法

### 1. 解析 tcpdump 文件

首先生成 tcpdump 输出文件：

```bash
# 捕获 UDP 端口 14550 的数据包并保存为文本格式
sudo tcpdump -i any -X udp port 14550 > mavlink_capture.log

# 或者保存为 pcap 格式后转换
sudo tcpdump -i any -X udp port 14550 -w capture.pcap
tcpdump -r capture.pcap -X > mavlink_capture.log
```

然后使用工具解析：

```bash
# 基本解析
./mavlink_network_analyzer -f mavlink_capture.log

# 详细模式解析
./mavlink_network_analyzer -f mavlink_capture.log -v
```

### 2. 实时数据包捕获

```bash
# 基本捕获 (需要 root 权限)
sudo ./mavlink_network_analyzer -i eth0

# 指定端口和详细模式
sudo ./mavlink_network_analyzer -i wlan0 -p 14550 -v

# 使用不同的网络接口
sudo ./mavlink_network_analyzer -i lo -p 14550 -v  # 本地回环接口
```

### 3. 命令行选项

```
用法: mavlink_network_analyzer [选项]

选项:
  -f, --file FILE         解析 tcpdump 输出文件
  -i, --interface IFACE   网络接口名称 (如: eth0, wlan0)
  -p, --port PORT         MAVLink 端口号 (默认: 14550)
  -v, --verbose           输出详细信息
  -h, --help              显示帮助信息
```

## 输出示例

### 基本输出

```
[2024-01-15 10:30:15] [INFO] 开始实时数据包捕获...
[2024-01-15 10:30:16] [MAVLINK] ====== MAVLink 消息解析 ======
时间戳: 10:30:16.123
网络信息:
  源地址: 192.168.1.100:14550
  目标地址: 192.168.1.200:14551
MAVLink 信息:
  消息ID: 0 (HEARTBEAT)
  系统ID: 1
  组件ID: 1
  序列号: 45
  消息长度: 9 字节
================================
```

### 详细输出 (-v 选项)

包含完整的消息内容解析和十六进制数据：

```
[2024-01-15 10:30:16] [MAVLINK] ====== MAVLink 消息解析 ======
时间戳: 10:30:16.123
网络信息:
  源地址: 192.168.1.100:14550
  目标地址: 192.168.1.200:14551
MAVLink 信息:
  消息ID: 0 (HEARTBEAT)
  系统ID: 1
  组件ID: 1
  序列号: 45
  消息长度: 9 字节
消息内容:
  类型: 2
  自驾仪: 3
  基础模式: 81
  自定义模式: 0
  系统状态: 4
  MAVLink版本: 3
原始数据 (十六进制):
  fe 09 2d 01 01 00 02 03 51 00 00 00 04 03 8a 3e
================================
```

## 支持的 MAVLink 消息类型

工具目前支持以下 MAVLink 消息的详细解析：

- HEARTBEAT (ID: 0)
- ATTITUDE (ID: 30)
- GLOBAL_POSITION_INT (ID: 33)
- GPS_RAW_INT (ID: 24)
- COMMAND_LONG (ID: 76)

其他消息类型会显示基本信息，但不会解析具体内容。

## 常见问题

### 1. 权限问题

实时捕获需要 root 权限：

```bash
sudo ./mavlink_network_analyzer -i eth0
```

### 2. 找不到网络接口

查看可用的网络接口：

```bash
ip link show
# 或
ifconfig -a
```

### 3. 没有捕获到数据

- 确认 MAVLink 设备正在该端口发送数据
- 检查防火墙设置
- 确认网络接口正确
- 使用 tcpdump 验证是否有数据包：

```bash
sudo tcpdump -i eth0 udp port 14550
```

## 开发说明

工具的核心类是 `MavlinkNetworkAnalyzer`，主要功能：

- `parse_tcpdump_file()`: 解析 tcpdump 文件
- `start_packet_capture()`: 开始实时捕获
- `stop_packet_capture()`: 停止捕获
- `parse_mavlink_message()`: 解析 MAVLink 消息

如需添加新的 MAVLink 消息类型支持，请修改 `format_mavlink_message_content()` 函数。