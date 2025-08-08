#include "mavlink_network_analyzer.hpp"
#include <chrono>
#include <ctime>
#include <thread>
#include <iomanip>
#include <algorithm>

namespace codevsdk {
namespace tools {

MavlinkNetworkAnalyzer::MavlinkNetworkAnalyzer()
    : verbose_(false)
    , show_hex_(false)
    , capturing_(false)
    , pcap_handle_(nullptr)
    , mavlink_channel_(0)
{
    // 初始化 MAVLink 状态
    memset(&mavlink_status_, 0, sizeof(mavlink_status_));
}

MavlinkNetworkAnalyzer::~MavlinkNetworkAnalyzer() {
    stop_packet_capture();
}

bool MavlinkNetworkAnalyzer::parse_tcpdump_file(const std::string& file_path) {
    std::ifstream file(file_path);
    if (!file.is_open()) {
        log("ERROR", "无法打开文件: " + file_path);
        return false;
    }

    log("INFO", "开始解析 tcpdump 文件: " + file_path);
    
    std::string line;
    std::regex udp_regex(R"((\d{2}:\d{2}:\d{2}\.\d+)\s+IP\s+(\d+\.\d+\.\d+\.\d+)\.(\d+)\s+>\s+(\d+\.\d+\.\d+\.\d+)\.(\d+):\s+UDP.*length\s+(\d+))");
    std::regex hex_regex(R"(^\s*0x[0-9a-fA-F]+:\s+([0-9a-fA-F\s]+))");
    
    std::string current_timestamp;
    std::string current_src_ip, current_dst_ip;
    uint16_t current_src_port = 0, current_dst_port = 0;
    std::vector<uint8_t> packet_data;
    
    while (std::getline(file, line)) {
        std::smatch match;
        
        // 匹配 UDP 包头信息
        if (std::regex_search(line, match, udp_regex)) {
            // 如果有之前的包数据，先处理它
            if (!packet_data.empty()) {
                extract_mavlink_from_udp(packet_data.data(), packet_data.size(),
                                       current_src_ip, current_dst_ip,
                                       current_src_port, current_dst_port,
                                       current_timestamp);
                packet_data.clear();
            }
            
            // 保存新包的信息
            current_timestamp = match[1].str();
            current_src_ip = match[2].str();
            current_src_port = static_cast<uint16_t>(std::stoi(match[3].str()));
            current_dst_ip = match[4].str();
            current_dst_port = static_cast<uint16_t>(std::stoi(match[5].str()));
            
            if (verbose_) {
                log("DEBUG", "检测到 UDP 包: " + current_src_ip + ":" + 
                    std::to_string(current_src_port) + " -> " + 
                    current_dst_ip + ":" + std::to_string(current_dst_port));
            }
        }
        // 匹配十六进制数据行
        else if (std::regex_search(line, match, hex_regex)) {
            std::string hex_data = match[1].str();
            std::istringstream hex_stream(hex_data);
            std::string hex_byte;
            
            while (hex_stream >> hex_byte) {
                if (hex_byte.length() == 2) {
                    uint8_t byte = static_cast<uint8_t>(std::stoul(hex_byte, nullptr, 16));
                    packet_data.push_back(byte);
                } else if (hex_byte.length() == 4) {
                    // 处理两个字节连在一起的情况
                    uint8_t byte1 = static_cast<uint8_t>(std::stoul(hex_byte.substr(0, 2), nullptr, 16));
                    uint8_t byte2 = static_cast<uint8_t>(std::stoul(hex_byte.substr(2, 2), nullptr, 16));
                    packet_data.push_back(byte1);
                    packet_data.push_back(byte2);
                }
            }
        }
    }
    
    // 处理最后一个包
    if (!packet_data.empty()) {
        extract_mavlink_from_udp(packet_data.data(), packet_data.size(),
                               current_src_ip, current_dst_ip,
                               current_src_port, current_dst_port,
                               current_timestamp);
    }
    
    log("INFO", "tcpdump 文件解析完成");
    return true;
}

bool MavlinkNetworkAnalyzer::start_packet_capture(const std::string& interface,
                                                 const std::string& filter_expression) {
    if (capturing_) {
        log("WARNING", "数据包捕获已在运行中");
        return false;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    
    // 打开网络接口 - 优化参数以提高响应速度
    // 参数说明: interface, snaplen, promisc, timeout_ms, errbuf
    // snaplen: 65536 (捕获完整数据包)
    // promisc: 1 (混杂模式)  
    // timeout_ms: 1 (1毫秒超时，大大提高响应速度)
    pcap_handle_ = pcap_open_live(interface.c_str(), 65536, 1, 1, errbuf);
    if (pcap_handle_ == nullptr) {
        log("ERROR", "无法打开网络接口 " + interface + ": " + std::string(errbuf));
        return false;
    }

    // 设置非阻塞模式以进一步提高响应速度
    if (pcap_setnonblock(pcap_handle_, 1, errbuf) == -1) {
        log("WARNING", "无法设置非阻塞模式: " + std::string(errbuf));
        // 不是致命错误，继续运行
    }

    // 设置缓冲区大小 - 减小缓冲区以降低延迟
    int buffer_size = 1024; // 1MB缓冲区 (比默认的更小)
    if (pcap_set_buffer_size(pcap_handle_, buffer_size) != 0) {
        log("WARNING", "无法设置缓冲区大小");
        // 不是致命错误，继续运行
    }

    // 编译并设置过滤器
    struct bpf_program filter_program;
    if (pcap_compile(pcap_handle_, &filter_program, filter_expression.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1) {
        log("ERROR", "无法编译过滤器: " + filter_expression);
        pcap_close(pcap_handle_);
        pcap_handle_ = nullptr;
        return false;
    }

    if (pcap_setfilter(pcap_handle_, &filter_program) == -1) {
        log("ERROR", "无法设置过滤器");
        pcap_freecode(&filter_program);
        pcap_close(pcap_handle_);
        pcap_handle_ = nullptr;
        return false;
    }
    
    pcap_freecode(&filter_program);

    capturing_ = true;
    
    // 启动捕获线程
    capture_thread_ = std::thread([this]() {
        log("INFO", "开始高频数据包捕获...");
        
        // 使用高频轮询模式而不是无限阻塞
        // 每次处理少量数据包以提高响应速度
        while (capturing_) {
            // 每次只处理10个数据包，然后立即返回
            // 这样可以更快地检查 capturing_ 状态并减少延迟
            int result = pcap_dispatch(pcap_handle_, 10, packet_handler, reinterpret_cast<uint8_t*>(this));
            
            if (result == -1) {
                // 发生错误
                log("ERROR", "数据包捕获发生错误: " + std::string(pcap_geterr(pcap_handle_)));
                break;
            } else if (result == 0) {
                // 没有数据包，短暂休眠避免空转消耗CPU
                std::this_thread::sleep_for(std::chrono::microseconds(100)); // 100微秒
            }
            // result > 0 表示成功处理了数据包，继续下一轮
        }
    });

    log("INFO", "数据包捕获已启动，接口: " + interface + ", 过滤器: " + filter_expression);
    return true;
}

void MavlinkNetworkAnalyzer::stop_packet_capture() {
    if (!capturing_) {
        return;
    }

    capturing_ = false;
    
    if (pcap_handle_) {
        pcap_breakloop(pcap_handle_);
    }
    
    if (capture_thread_.joinable()) {
        capture_thread_.join();
    }
    
    if (pcap_handle_) {
        pcap_close(pcap_handle_);
        pcap_handle_ = nullptr;
    }
    
    log("INFO", "数据包捕获已停止");
}

void MavlinkNetworkAnalyzer::packet_handler(uint8_t* user_data, 
                                           const struct pcap_pkthdr* pkthdr,
                                           const uint8_t* packet_data) {
    auto* analyzer = reinterpret_cast<MavlinkNetworkAnalyzer*>(user_data);
    
    // 获取当前时间戳
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()) % 1000;
    
    std::ostringstream timestamp_stream;
    timestamp_stream << std::put_time(std::localtime(&time_t), "%H:%M:%S");
    timestamp_stream << '.' << std::setfill('0') << std::setw(3) << ms.count();
    
    analyzer->parse_packet(packet_data, pkthdr->len, timestamp_stream.str());
}

void MavlinkNetworkAnalyzer::parse_packet(const uint8_t* packet_data, int packet_len,
                                        const std::string& timestamp) {
    if (static_cast<size_t>(packet_len) < sizeof(platform_iphdr) + sizeof(platform_udphdr)) {
        return;
    }

    // 跳过以太网头部（14字节）
    const uint8_t* ip_header = packet_data + 14;
    const platform_iphdr* ip = reinterpret_cast<const platform_iphdr*>(ip_header);
    
    // 检查是否为 UDP 包
    if (IP_PROTOCOL(ip) != IPPROTO_UDP) {
        return;
    }

    // 获取 UDP 头部
    const uint8_t* udp_header = ip_header + IP_HEADER_LENGTH(ip);
    const platform_udphdr* udp = reinterpret_cast<const platform_udphdr*>(udp_header);
    
    // 获取源和目标地址
    struct in_addr src_addr, dst_addr;
    src_addr.s_addr = IP_SOURCE_ADDR(ip);
    dst_addr.s_addr = IP_DEST_ADDR(ip);
    
    std::string src_ip = inet_ntoa(src_addr);
    std::string dst_ip = inet_ntoa(dst_addr);
    uint16_t src_port = ntohs(UDP_SOURCE_PORT(udp));
    uint16_t dst_port = ntohs(UDP_DEST_PORT(udp));
    
    // 获取 UDP payload
    const uint8_t* udp_payload = udp_header + sizeof(platform_udphdr);
    int udp_payload_len = ntohs(UDP_LENGTH(udp)) - sizeof(platform_udphdr);
    
    if (udp_payload_len > 0) {
        extract_mavlink_from_udp(udp_payload, udp_payload_len,
                               src_ip, dst_ip, src_port, dst_port, timestamp);
    }
}

void MavlinkNetworkAnalyzer::extract_mavlink_from_udp(const uint8_t* udp_payload, int payload_len,
                                                     const std::string& src_ip, const std::string& dst_ip,
                                                     uint16_t src_port, uint16_t dst_port,
                                                     const std::string& timestamp) {
    // 在 UDP payload 中查找 MAVLink 消息
    for (int i = 0; i < payload_len; i++) {
        mavlink_message_t msg;
        mavlink_status_t status;
        
        if (mavlink_parse_char(mavlink_channel_, udp_payload[i], &msg, &status) == MAVLINK_FRAMING_OK) {
            parse_mavlink_message(reinterpret_cast<const uint8_t*>(&msg), sizeof(msg),
                                src_ip, dst_ip, src_port, dst_port, timestamp);
        }
    }
}

void MavlinkNetworkAnalyzer::parse_mavlink_message(const uint8_t* mavlink_data, int data_len,
                                                  const std::string& src_ip, const std::string& dst_ip,
                                                  uint16_t src_port, uint16_t dst_port,
                                                  const std::string& timestamp) {
    const mavlink_message_t* msg = reinterpret_cast<const mavlink_message_t*>(mavlink_data);
    
    std::ostringstream log_stream;
    log_stream << timestamp << " " << src_ip << ":" << src_port << " > " << dst_ip << ":" << dst_port << " ";
    log_stream << std::setw(3) << std::setfill(' ') << data_len << " "
               << std::setw(3) << std::setfill(' ') << msg->msgid << "," 
               << std::setw(3) << std::setfill(' ') << static_cast<int>(msg->sysid) << ","
               << std::setw(3) << std::setfill(' ') << static_cast<int>(msg->compid);
    log_stream << format_mavlink_message_content_short(*msg);
    
    if (should_show_verbose(msg->msgid)) {
        std::string msg_name = get_mavlink_message_name(msg->msgid);
        log_stream << "\n\t" << msg_name << "\n\t";
        // 如果启用了十六进制显示，显示原始消息数据
        if (show_hex_) {
            log_stream << format_hex_output(mavlink_data, data_len);
        } else {
            log_stream << format_mavlink_message_content(*msg);
        }
    }
    
    std::cout << log_stream.str() << std::endl;
}

std::string MavlinkNetworkAnalyzer::get_mavlink_message_name(uint32_t msg_id) {
#ifdef MAVLINK_USE_MESSAGE_INFO
    // 使用MAVLink内置的消息信息获取消息名称
    const mavlink_message_info_t* info = mavlink_get_message_info_by_id(msg_id);
    if (info && info->name) {
        return std::string(info->name);
    }
#endif
    // 如果没有找到消息信息，返回未知消息类型
    return "UNKNOWN_" + std::to_string(msg_id);
}

std::string MavlinkNetworkAnalyzer::format_mavlink_message_content(const mavlink_message_t& msg) {
    std::ostringstream content_stream;
    
#ifdef MAVLINK_USE_MESSAGE_INFO
    const mavlink_message_info_t* info = mavlink_get_message_info_by_id(msg.msgid);
    if (info) {
        const uint8_t* payload = reinterpret_cast<const uint8_t*>(&msg.payload64[0]);
        
        for (unsigned i = 0; i < info->num_fields; ++i) {
            const mavlink_field_info_t& field = info->fields[i];
            content_stream << "\n\t  " << field.name << ": ";
            
            // 根据字段类型格式化输出
            switch (field.type) {
                case MAVLINK_TYPE_CHAR:
                    if (field.array_length > 1) {
                        // char数组，作为字符串处理
                        char str_buf[256] = {0};
                        size_t copy_len = std::min(static_cast<size_t>(field.array_length), sizeof(str_buf) - 1);
                        memcpy(str_buf, payload + field.wire_offset, copy_len);
                        // 确保字符串以null结尾
                        str_buf[copy_len] = '\0';
                        content_stream << "\"" << str_buf << "\"";
                    } else {
                        // 单个char
                        char c = *reinterpret_cast<const char*>(payload + field.wire_offset);
                        content_stream << "'" << c << "'";
                    }
                    break;
                    
                case MAVLINK_TYPE_UINT8_T:
                    if (field.array_length > 1) {
                        content_stream << "[";
                        for (unsigned j = 0; j < field.array_length && j < 10; ++j) {
                            if (j > 0) content_stream << ",";
                            content_stream << static_cast<int>(*(payload + field.wire_offset + j));
                        }
                        if (field.array_length > 10) content_stream << "...";
                        content_stream << "]";
                    } else {
                        content_stream << static_cast<int>(*reinterpret_cast<const uint8_t*>(payload + field.wire_offset));
                    }
                    break;
                    
                case MAVLINK_TYPE_INT8_T:
                    if (field.array_length > 1) {
                        content_stream << "[";
                        for (unsigned j = 0; j < field.array_length && j < 10; ++j) {
                            if (j > 0) content_stream << ",";
                            content_stream << static_cast<int>(*(reinterpret_cast<const int8_t*>(payload + field.wire_offset) + j));
                        }
                        if (field.array_length > 10) content_stream << "...";
                        content_stream << "]";
                    } else {
                        content_stream << static_cast<int>(*reinterpret_cast<const int8_t*>(payload + field.wire_offset));
                    }
                    break;
                    
                case MAVLINK_TYPE_UINT16_T:
                    if (field.array_length > 1) {
                        content_stream << "[";
                        for (unsigned j = 0; j < field.array_length && j < 10; ++j) {
                            if (j > 0) content_stream << ",";
                            content_stream << *(reinterpret_cast<const uint16_t*>(payload + field.wire_offset) + j);
                        }
                        if (field.array_length > 10) content_stream << "...";
                        content_stream << "]";
                    } else {
                        content_stream << *reinterpret_cast<const uint16_t*>(payload + field.wire_offset);
                    }
                    break;
                    
                case MAVLINK_TYPE_INT16_T:
                    if (field.array_length > 1) {
                        content_stream << "[";
                        for (unsigned j = 0; j < field.array_length && j < 10; ++j) {
                            if (j > 0) content_stream << ",";
                            content_stream << *(reinterpret_cast<const int16_t*>(payload + field.wire_offset) + j);
                        }
                        if (field.array_length > 10) content_stream << "...";
                        content_stream << "]";
                    } else {
                        content_stream << *reinterpret_cast<const int16_t*>(payload + field.wire_offset);
                    }
                    break;
                    
                case MAVLINK_TYPE_UINT32_T:
                    if (field.array_length > 1) {
                        content_stream << "[";
                        for (unsigned j = 0; j < field.array_length && j < 10; ++j) {
                            if (j > 0) content_stream << ",";
                            content_stream << *(reinterpret_cast<const uint32_t*>(payload + field.wire_offset) + j);
                        }
                        if (field.array_length > 10) content_stream << "...";
                        content_stream << "]";
                    } else {
                        content_stream << *reinterpret_cast<const uint32_t*>(payload + field.wire_offset);
                    }
                    break;
                    
                case MAVLINK_TYPE_INT32_T:
                    if (field.array_length > 1) {
                        content_stream << "[";
                        for (unsigned j = 0; j < field.array_length && j < 10; ++j) {
                            if (j > 0) content_stream << ",";
                            content_stream << *(reinterpret_cast<const int32_t*>(payload + field.wire_offset) + j);
                        }
                        if (field.array_length > 10) content_stream << "...";
                        content_stream << "]";
                    } else {
                        content_stream << *reinterpret_cast<const int32_t*>(payload + field.wire_offset);
                    }
                    break;
                    
                case MAVLINK_TYPE_UINT64_T:
                    if (field.array_length > 1) {
                        content_stream << "[";
                        for (unsigned j = 0; j < field.array_length && j < 10; ++j) {
                            if (j > 0) content_stream << ",";
                            content_stream << *(reinterpret_cast<const uint64_t*>(payload + field.wire_offset) + j);
                        }
                        if (field.array_length > 10) content_stream << "...";
                        content_stream << "]";
                    } else {
                        content_stream << *reinterpret_cast<const uint64_t*>(payload + field.wire_offset);
                    }
                    break;
                    
                case MAVLINK_TYPE_INT64_T:
                    if (field.array_length > 1) {
                        content_stream << "[";
                        for (unsigned j = 0; j < field.array_length && j < 10; ++j) {
                            if (j > 0) content_stream << ",";
                            content_stream << *(reinterpret_cast<const int64_t*>(payload + field.wire_offset) + j);
                        }
                        if (field.array_length > 10) content_stream << "...";
                        content_stream << "]";
                    } else {
                        content_stream << *reinterpret_cast<const int64_t*>(payload + field.wire_offset);
                    }
                    break;
                    
                case MAVLINK_TYPE_FLOAT:
                    if (field.array_length > 1) {
                        content_stream << "[";
                        for (unsigned j = 0; j < field.array_length && j < 10; ++j) {
                            if (j > 0) content_stream << ",";
                            content_stream << std::fixed << std::setprecision(3) 
                                         << *(reinterpret_cast<const float*>(payload + field.wire_offset) + j);
                        }
                        if (field.array_length > 10) content_stream << "...";
                        content_stream << "]";
                    } else {
                        content_stream << std::fixed << std::setprecision(3) 
                                     << *reinterpret_cast<const float*>(payload + field.wire_offset);
                    }
                    break;
                    
                case MAVLINK_TYPE_DOUBLE:
                    if (field.array_length > 1) {
                        content_stream << "[";
                        for (unsigned j = 0; j < field.array_length && j < 10; ++j) {
                            if (j > 0) content_stream << ",";
                            content_stream << std::fixed << std::setprecision(6) 
                                         << *(reinterpret_cast<const double*>(payload + field.wire_offset) + j);
                        }
                        if (field.array_length > 10) content_stream << "...";
                        content_stream << "]";
                    } else {
                        content_stream << std::fixed << std::setprecision(6) 
                                     << *reinterpret_cast<const double*>(payload + field.wire_offset);
                    }
                    break;
                    
                default:
                    content_stream << "未知类型(" << static_cast<int>(field.type) << ")";
                    break;
            }
        }
    }
#endif
    return content_stream.str();
}

std::string MavlinkNetworkAnalyzer::format_mavlink_message_content_short(const mavlink_message_t& msg) {
    std::ostringstream content_stream;
    // 对于常见消息类型，添加简短的关键信息
    switch (msg.msgid) {
        case MAVLINK_MSG_ID_HEARTBEAT: {
            content_stream << " ";
            mavlink_command_ack_t cmd_ack;
            mavlink_msg_command_ack_decode(&msg, &cmd_ack);
            content_stream << ",cm=" << static_cast<int>(cmd_ack.command);
            content_stream << ",ts=" << static_cast<int>(cmd_ack.target_system);
            content_stream << ",tc=" << static_cast<int>(cmd_ack.target_component);
            content_stream << ",rs=" << static_cast<int>(cmd_ack.result);
            break;
        }
        case MAVLINK_MSG_ID_COMMAND_LONG: {
            content_stream << " ";
            mavlink_command_long_t cmd_long;
            mavlink_msg_command_long_decode(&msg, &cmd_long);
            content_stream << ",cm=" << static_cast<int>(cmd_long.command);
            content_stream << ",sq=" << static_cast<int>(msg.seq);
            break;
        }
        default:
            break;
    }
    
    return content_stream.str();
}

bool MavlinkNetworkAnalyzer::should_show_verbose(uint32_t msg_id) const {
    // 如果设置了全局verbose模式，显示所有消息的详细信息
    if (verbose_) {
        return true;
    }
    
    // 如果设置了特定的消息ID列表，只显示列表中的消息
    if (!verbose_message_ids_.empty()) {
        return std::find(verbose_message_ids_.begin(), verbose_message_ids_.end(), msg_id) 
               != verbose_message_ids_.end();
    }
    
    // 默认不显示详细信息
    return false;
}

std::string MavlinkNetworkAnalyzer::format_hex_output(const uint8_t* data, int length) const {
    std::ostringstream hex_stream;
    
    for (int i = 0; i < length; i += 16) {
        hex_stream << "\t    ";
        
        // 显示十六进制数据，每行16个字节
        for (int j = 0; j < 16 && (i + j) < length; ++j) {
            hex_stream << std::hex << std::setfill('0') << std::setw(2) 
                      << static_cast<int>(data[i + j]) << " ";
        }
        
        // 如果这一行不足16个字节，用空格补齐对齐
        for (int j = (length - i > 16) ? 16 : (length - i); j < 16; ++j) {
            hex_stream << "   ";
        }
        
        // 显示ASCII字符（可打印字符）
        hex_stream << " |";
        for (int j = 0; j < 16 && (i + j) < length; ++j) {
            char c = static_cast<char>(data[i + j]);
            if (c >= 32 && c <= 126) {
                hex_stream << c;
            } else {
                hex_stream << '.';
            }
        }
        hex_stream << "|\n";
    }
    
    hex_stream << std::dec; // 恢复十进制格式
    return hex_stream.str();
}

void MavlinkNetworkAnalyzer::log(const std::string& level, const std::string& message) {
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    
    std::cout << "[" << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S") 
              << "] [" << level << "] " << message << std::endl;
}

} // namespace tools
} // namespace codevsdk