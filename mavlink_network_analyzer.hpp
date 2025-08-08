#pragma once

#include <string>
#include <vector>
#include <memory>
#include <thread>
#include <atomic>
#include <fstream>
#include <iostream>
#include <sstream>
#include <regex>
#include <iomanip>
#include <pcap.h>
#include <arpa/inet.h>

// 平台特定的网络头文件
#ifdef __APPLE__
    #include <netinet/in.h>
    #include <netinet/ip.h>
    #include <netinet/udp.h>
    #include <sys/socket.h>
#elif __linux__
    #include <linux/ip.h>
    #include <linux/udp.h>
#endif

#include <all/mavlink.h>

// 跨平台网络结构体兼容性定义
#ifdef __APPLE__
    // macOS 使用 BSD 风格的 udphdr
    #define UDP_SOURCE_PORT(udp) (udp)->uh_sport
    #define UDP_DEST_PORT(udp)   (udp)->uh_dport
    #define UDP_LENGTH(udp)      (udp)->uh_ulen
    
    // macOS 使用不同的 IP 头结构
    #define IP_HEADER_LENGTH(ip) ((ip)->ip_hl << 2)
    #define IP_PROTOCOL(ip)      (ip)->ip_p
    #define IP_SOURCE_ADDR(ip)   (ip)->ip_src.s_addr
    #define IP_DEST_ADDR(ip)     (ip)->ip_dst.s_addr
    
    typedef struct ip platform_iphdr;
    typedef struct udphdr platform_udphdr;
#else
    // Linux 使用标准的 udphdr
    #define UDP_SOURCE_PORT(udp) (udp)->source
    #define UDP_DEST_PORT(udp)   (udp)->dest
    #define UDP_LENGTH(udp)      (udp)->len
    
    // Linux IP 头结构
    #define IP_HEADER_LENGTH(ip) ((ip)->ihl << 2)
    #define IP_PROTOCOL(ip)      (ip)->protocol
    #define IP_SOURCE_ADDR(ip)   (ip)->saddr
    #define IP_DEST_ADDR(ip)     (ip)->daddr
    
    typedef struct iphdr platform_iphdr;
    typedef struct udphdr platform_udphdr;
#endif

namespace codevsdk {
namespace tools {

/**
 * @brief MAVLink 网络数据包分析器
 * 
 * 该类可以：
 * 1. 解析 tcpdump 输出文件
 * 2. 直接捕获网络数据包
 * 3. 提取网络数据包的纯 payload 部分
 * 4. 解析其中的 MAVLink 消息
 * 5. 输出详细的日志信息
 */
class MavlinkNetworkAnalyzer {
public:
    /**
     * @brief 构造函数
     */
    MavlinkNetworkAnalyzer();
    
    /**
     * @brief 析构函数
     */
    ~MavlinkNetworkAnalyzer();

    /**
     * @brief 从 tcpdump 输出文件解析 MAVLink 数据包
     * @param file_path tcpdump 输出文件路径
     * @return 解析是否成功
     */
    bool parse_tcpdump_file(const std::string& file_path);

    /**
     * @brief 开始实时网络数据包捕获
     * @param interface 网络接口名称（如 "eth0", "wlan0"）
     * @param filter_expression BPF 过滤表达式（默认为 UDP 端口 14550）
     * @return 是否成功启动捕获
     */
    bool start_packet_capture(const std::string& interface, 
                             const std::string& filter_expression = "udp port 14550");

    /**
     * @brief 停止网络数据包捕获
     */
    void stop_packet_capture();

    /**
     * @brief 设置日志输出级别
     * @param verbose 是否输出详细信息
     */
    void set_verbose(bool verbose) { verbose_ = verbose; }

    /**
     * @brief 设置需要详细显示的消息ID列表
     * @param message_ids 消息ID向量
     */
    void set_verbose_message_ids(const std::vector<uint32_t>& message_ids) { 
        verbose_message_ids_ = message_ids;
    }

    /**
     * @brief 设置是否显示十六进制内容
     * @param show_hex 是否显示十六进制内容
     */
    void set_show_hex(bool show_hex) { show_hex_ = show_hex; }

private:
    /**
     * @brief 解析单个网络数据包
     * @param packet_data 数据包数据
     * @param packet_len 数据包长度
     * @param timestamp 时间戳
     */
    void parse_packet(const uint8_t* packet_data, int packet_len, 
                     const std::string& timestamp = "");

    /**
     * @brief 从 UDP payload 中提取并解析 MAVLink 消息
     * @param udp_payload UDP 载荷数据
     * @param payload_len 载荷长度
     * @param src_ip 源 IP 地址
     * @param dst_ip 目标 IP 地址
     * @param src_port 源端口
     * @param dst_port 目标端口
     * @param timestamp 时间戳
     */
    void extract_mavlink_from_udp(const uint8_t* udp_payload, int payload_len,
                                 const std::string& src_ip, const std::string& dst_ip,
                                 uint16_t src_port, uint16_t dst_port,
                                 const std::string& timestamp);

    /**
     * @brief 解析 MAVLink 消息
     * @param mavlink_data MAVLink 消息数据
     * @param data_len 数据长度
     * @param src_ip 源 IP 地址
     * @param dst_ip 目标 IP 地址
     * @param src_port 源端口
     * @param dst_port 目标端口
     * @param timestamp 时间戳
     */
    void parse_mavlink_message(const uint8_t* mavlink_data, int data_len,
                              const std::string& src_ip, const std::string& dst_ip,
                              uint16_t src_port, uint16_t dst_port,
                              const std::string& timestamp);

    /**
     * @brief 获取 MAVLink 消息类型名称
     * @param msg_id 消息 ID
     * @return 消息类型名称
     */
    std::string get_mavlink_message_name(uint32_t msg_id);

    /**
     * @brief 格式化输出 MAVLink 消息内容
     * @param msg MAVLink 消息
     * @return 格式化的消息内容字符串
     */
    std::string format_mavlink_message_content(const mavlink_message_t& msg);

    /**
     * @brief 格式化输出简短的 MAVLink 消息内容
     * @param msg MAVLink 消息
     * @return 格式化的简短消息内容字符串
     */
    std::string format_mavlink_message_content_short(const mavlink_message_t& msg);

    /**
     * @brief 检查消息ID是否应该详细显示
     * @param msg_id 消息ID
     * @return 是否应该详细显示
     */
    bool should_show_verbose(uint32_t msg_id) const;

    /**
     * @brief 格式化十六进制输出
     * @param data 数据指针
     * @param length 数据长度
     * @return 格式化的十六进制字符串
     */
    std::string format_hex_output(const uint8_t* data, int length) const;

    /**
     * @brief 输出解析日志
     * @param level 日志级别
     * @param message 日志消息
     */
    void log(const std::string& level, const std::string& message);

    /**
     * @brief pcap 回调函数（静态）
     */
    static void packet_handler(uint8_t* user_data, const struct pcap_pkthdr* pkthdr,
                              const uint8_t* packet_data);

    // 成员变量
    bool verbose_;
    bool show_hex_;
    std::atomic<bool> capturing_;
    std::thread capture_thread_;
    pcap_t* pcap_handle_;
    
    // MAVLink 解析相关
    mavlink_status_t mavlink_status_;
    uint8_t mavlink_channel_;
    
    // 详细显示消息ID列表
    std::vector<uint32_t> verbose_message_ids_;
};

} // namespace tools
} // namespace codevsdk