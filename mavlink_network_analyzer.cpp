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
    // Initialize MAVLink status
    memset(&mavlink_status_, 0, sizeof(mavlink_status_));
}

MavlinkNetworkAnalyzer::~MavlinkNetworkAnalyzer() {
    stop_packet_capture();
}

bool MavlinkNetworkAnalyzer::parse_tcpdump_file(const std::string& file_path) {
    std::ifstream file(file_path);
    if (!file.is_open()) {
        log("ERROR", "Cannot open file: " + file_path);
        return false;
    }

    log("INFO", "Starting to parse tcpdump file: " + file_path);
    
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
            // If there's previous packet data, process it first
            if (!packet_data.empty()) {
                extract_mavlink_from_udp(packet_data.data(), packet_data.size(),
                                       current_src_ip, current_dst_ip,
                                       current_src_port, current_dst_port,
                                       current_timestamp);
                packet_data.clear();
            }
            
            // Save new packet information
            current_timestamp = match[1].str();
            current_src_ip = match[2].str();
            current_src_port = static_cast<uint16_t>(std::stoi(match[3].str()));
            current_dst_ip = match[4].str();
            current_dst_port = static_cast<uint16_t>(std::stoi(match[5].str()));
            
            if (verbose_) {
                log("DEBUG", "Detected UDP packet: " + current_src_ip + ":" + 
                    std::to_string(current_src_port) + " -> " + 
                    current_dst_ip + ":" + std::to_string(current_dst_port));
            }
        }
        // Match hexadecimal data lines
        else if (std::regex_search(line, match, hex_regex)) {
            std::string hex_data = match[1].str();
            std::istringstream hex_stream(hex_data);
            std::string hex_byte;
            
            while (hex_stream >> hex_byte) {
                if (hex_byte.length() == 2) {
                    uint8_t byte = static_cast<uint8_t>(std::stoul(hex_byte, nullptr, 16));
                    packet_data.push_back(byte);
                } else if (hex_byte.length() == 4) {
                    // Handle case where two bytes are concatenated
                    uint8_t byte1 = static_cast<uint8_t>(std::stoul(hex_byte.substr(0, 2), nullptr, 16));
                    uint8_t byte2 = static_cast<uint8_t>(std::stoul(hex_byte.substr(2, 2), nullptr, 16));
                    packet_data.push_back(byte1);
                    packet_data.push_back(byte2);
                }
            }
        }
    }
    
    // Process the last packet
    if (!packet_data.empty()) {
        extract_mavlink_from_udp(packet_data.data(), packet_data.size(),
                               current_src_ip, current_dst_ip,
                               current_src_port, current_dst_port,
                               current_timestamp);
    }
    
    log("INFO", "tcpdump file parsing completed");
    return true;
}

bool MavlinkNetworkAnalyzer::start_packet_capture(const std::string& interface,
                                                 const std::string& filter_expression) {
    if (capturing_) {
        log("WARNING", "Packet capture is already running");
        return false;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    
    // Open network interface - optimized parameters for better responsiveness
    // Parameters: interface, snaplen, promisc, timeout_ms, errbuf
    // snaplen: 65536 (capture complete packets)
    // promisc: 1 (promiscuous mode)  
    // timeout_ms: 1 (1ms timeout, greatly improves responsiveness)
    pcap_handle_ = pcap_open_live(interface.c_str(), 65536, 1, 1, errbuf);
    if (pcap_handle_ == nullptr) {
        log("ERROR", "Cannot open network interface " + interface + ": " + std::string(errbuf));
        return false;
    }

    // Set non-blocking mode to further improve responsiveness
    if (pcap_setnonblock(pcap_handle_, 1, errbuf) == -1) {
        log("WARNING", "Cannot set non-blocking mode: " + std::string(errbuf));
        // Not a fatal error, continue running
    }

    // Set buffer size - reduce buffer to lower latency
    int buffer_size = 1024; // 1MB buffer (smaller than default)
    if (pcap_set_buffer_size(pcap_handle_, buffer_size) != 0) {
        log("WARNING", "Cannot set buffer size");
        // Not a fatal error, continue running
    }

    // Compile and set filter
    struct bpf_program filter_program;
    if (pcap_compile(pcap_handle_, &filter_program, filter_expression.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1) {
        log("ERROR", "Cannot compile filter: " + filter_expression);
        pcap_close(pcap_handle_);
        pcap_handle_ = nullptr;
        return false;
    }

    if (pcap_setfilter(pcap_handle_, &filter_program) == -1) {
        log("ERROR", "Cannot set filter");
        pcap_freecode(&filter_program);
        pcap_close(pcap_handle_);
        pcap_handle_ = nullptr;
        return false;
    }
    
    pcap_freecode(&filter_program);

    capturing_ = true;
    
    // Start capture thread
    capture_thread_ = std::thread([this]() {
        log("INFO", "Starting high-frequency packet capture...");
        
        // Use high-frequency polling mode instead of infinite blocking
        // Process small number of packets each time to improve responsiveness
        while (capturing_) {
            // Process only 10 packets each time, then return immediately
            // This allows faster checking of capturing_ status and reduces latency
            int result = pcap_dispatch(pcap_handle_, 10, packet_handler, reinterpret_cast<uint8_t*>(this));
            
            if (result == -1) {
                // Error occurred
                log("ERROR", "Packet capture error: " + std::string(pcap_geterr(pcap_handle_)));
                break;
            } else if (result == 0) {
                // No packets, sleep briefly to avoid busy waiting
                std::this_thread::sleep_for(std::chrono::microseconds(100)); // 100 microseconds
            }
            // result > 0 means packets were successfully processed, continue next round
        }
    });

    log("INFO", "Packet capture started, interface: " + interface + ", filter: " + filter_expression);
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
    
    log("INFO", "Packet capture stopped");
}

void MavlinkNetworkAnalyzer::packet_handler(uint8_t* user_data, 
                                           const struct pcap_pkthdr* pkthdr,
                                           const uint8_t* packet_data) {
    auto* analyzer = reinterpret_cast<MavlinkNetworkAnalyzer*>(user_data);
    
    // Get current timestamp
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
    
    // Check if it's a UDP packet
    if (IP_PROTOCOL(ip) != IPPROTO_UDP) {
        return;
    }

    // Get UDP header
    const uint8_t* udp_header = ip_header + IP_HEADER_LENGTH(ip);
    const platform_udphdr* udp = reinterpret_cast<const platform_udphdr*>(udp_header);
    
    // Get source and destination addresses
    struct in_addr src_addr, dst_addr;
    src_addr.s_addr = IP_SOURCE_ADDR(ip);
    dst_addr.s_addr = IP_DEST_ADDR(ip);
    
    std::string src_ip = inet_ntoa(src_addr);
    std::string dst_ip = inet_ntoa(dst_addr);
    uint16_t src_port = ntohs(UDP_SOURCE_PORT(udp));
    uint16_t dst_port = ntohs(UDP_DEST_PORT(udp));
    
    // Get UDP payload
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
    // Check IP filtering conditions
    if (!should_process_packet(src_ip, dst_ip)) {
        return; // Skip packets that don't match IP filtering conditions
    }
    
    // Search for MAVLink messages in UDP payload
    for (int i = 0; i < payload_len; i++) {
        mavlink_message_t msg;
        mavlink_status_t status;
        
        if (mavlink_parse_char(mavlink_channel_, udp_payload[i], &msg, &status) == MAVLINK_FRAMING_OK) {
            parse_mavlink_message(reinterpret_cast<const uint8_t*>(&msg), msg.len + MAVLINK_NUM_NON_PAYLOAD_BYTES,
                                src_ip, dst_ip, src_port, dst_port, timestamp);
        }
    }
}

void MavlinkNetworkAnalyzer::parse_mavlink_message(const uint8_t* mavlink_data, int data_len,
                                                  const std::string& src_ip, const std::string& dst_ip,
                                                  uint16_t src_port, uint16_t dst_port,
                                                  const std::string& timestamp) {
    const mavlink_message_t* msg = reinterpret_cast<const mavlink_message_t*>(mavlink_data);
    
    // Check if this message should be processed (filtering check)
    if (!should_process_message(msg->msgid)) {
        return; // Skip unwanted messages
    }
    
    std::ostringstream log_stream;
    log_stream << timestamp << " " << src_ip << ":" << src_port << " > " << dst_ip << ":" << dst_port << " ";
    log_stream << std::setw(3) << std::setfill(' ') << data_len << " "
               << std::setw(3) << std::setfill(' ') << msg->msgid << "," 
               << std::setw(3) << std::setfill(' ') << static_cast<int>(msg->sysid) << ","
               << std::setw(3) << std::setfill(' ') << static_cast<int>(msg->compid);
    log_stream << format_mavlink_message_content_short(*msg);
    
    if (should_show_verbose(msg->msgid)) {
        std::string msg_name = get_mavlink_message_name(msg->msgid);
        log_stream << "\n  " << msg_name;
        // If hexadecimal display is enabled, show raw message data
        if (show_hex_) {
            log_stream << format_hex_output(mavlink_data + 2, data_len);
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
    // If no message info found, return unknown message type
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
            content_stream << "\n    " << field.name << ": ";
            
            // Format output based on field type
            switch (field.type) {
                case MAVLINK_TYPE_CHAR:
                    if (field.array_length > 1) {
                        // char array, process as string
                        char str_buf[256] = {0};
                        size_t copy_len = std::min(static_cast<size_t>(field.array_length), sizeof(str_buf) - 1);
                        memcpy(str_buf, payload + field.wire_offset, copy_len);
                        // Ensure string is null-terminated
                        str_buf[copy_len] = '\0';
                        content_stream << "\"" << str_buf << "\"";
                    } else {
                        // Single char
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
                    content_stream << "Unknown type(" << static_cast<int>(field.type) << ")";
                    break;
            }
        }
    }
#endif
    return content_stream.str();
}

std::string MavlinkNetworkAnalyzer::format_mavlink_message_content_short(const mavlink_message_t& msg) {
    std::ostringstream content_stream;
    // For common message types, add brief key information
    switch (msg.msgid) {
        case MAVLINK_MSG_ID_COMMAND_ACK: {
            content_stream << " ";
            mavlink_command_ack_t cmd_ack;
            mavlink_msg_command_ack_decode(&msg, &cmd_ack);
            content_stream << "cm=" << static_cast<int>(cmd_ack.command);
            content_stream << ",ts=" << static_cast<int>(cmd_ack.target_system);
            content_stream << ",tc=" << static_cast<int>(cmd_ack.target_component);
            content_stream << ",rs=" << static_cast<int>(cmd_ack.result);
            break;
        }
        case MAVLINK_MSG_ID_COMMAND_LONG: {
            content_stream << " ";
            mavlink_command_long_t cmd_long;
            mavlink_msg_command_long_decode(&msg, &cmd_long);
            content_stream << "cm=" << static_cast<int>(cmd_long.command);
            content_stream << ",ts=" << static_cast<int>(cmd_long.target_system);
            content_stream << ",tc=" << static_cast<int>(cmd_long.target_component);
            content_stream << ",sq=" << static_cast<int>(msg.seq);
            if(cmd_long.command == MAV_CMD_REQUEST_MESSAGE || cmd_long.command == MAV_CMD_SET_MESSAGE_INTERVAL) {
                content_stream << ",rq=" << static_cast<int>(cmd_long.param1);
            }
            break;
        }
        default:
            break;
    }
    
    return content_stream.str();
}

bool MavlinkNetworkAnalyzer::should_show_verbose(uint32_t msg_id) const {
    // If global verbose mode is set, show detailed info for all messages
    if (verbose_) {
        return true;
    }
    
    // If specific message ID list is set, only show messages in the list
    if (!verbose_message_ids_.empty()) {
        return std::find(verbose_message_ids_.begin(), verbose_message_ids_.end(), msg_id) 
               != verbose_message_ids_.end();
    }
    
    // Default: don't show detailed info
    return false;
}

bool MavlinkNetworkAnalyzer::should_process_message(uint32_t msg_id) const {
    // If no filter ID list is set, process all messages
    if (filter_message_ids_.empty()) {
        return true;
    }
    
    // If filter ID list is set, only process messages in the list
    return std::find(filter_message_ids_.begin(), filter_message_ids_.end(), msg_id) 
           != filter_message_ids_.end();
}

bool MavlinkNetworkAnalyzer::should_process_packet(const std::string& src_ip, const std::string& dst_ip) const {
    // Check source IP filter condition
    if (!filter_source_ip_.empty() && src_ip != filter_source_ip_) {
        return false;
    }
    
    // Check destination IP filter condition
    if (!filter_destination_ip_.empty() && dst_ip != filter_destination_ip_) {
        return false;
    }
    
    // If all filter conditions are met, process this packet
    return true;
}

std::string MavlinkNetworkAnalyzer::format_hex_output(const uint8_t* data, int length) const {
    std::ostringstream hex_stream;
    
    for (int i = 0; i < length; i += 16) {
        hex_stream << "\n    ";
        
        // Display hexadecimal data, 16 bytes per line
        for (int j = 0; j < 16 && (i + j) < length; ++j) {
            hex_stream << std::hex << std::setfill('0') << std::setw(2) 
                      << static_cast<int>(data[i + j]) << " ";
        }
        
        // If this line has less than 16 bytes, pad with spaces for alignment
        for (int j = (length - i > 16) ? 16 : (length - i); j < 16; ++j) {
            hex_stream << "   ";
        }
        
        // Display ASCII characters (printable characters)
        hex_stream << " |";
        for (int j = 0; j < 16 && (i + j) < length; ++j) {
            char c = static_cast<char>(data[i + j]);
            if (c >= 32 && c <= 126) {
                hex_stream << c;
            } else {
                hex_stream << '.';
            }
        }
        hex_stream << "|";
    }
    
    hex_stream << std::dec; // Restore decimal format
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