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

// Platform-specific network headers
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

// Cross-platform network structure compatibility definitions
#ifdef __APPLE__
    // macOS uses BSD-style udphdr
    #define UDP_SOURCE_PORT(udp) (udp)->uh_sport
    #define UDP_DEST_PORT(udp)   (udp)->uh_dport
    #define UDP_LENGTH(udp)      (udp)->uh_ulen
    
    // macOS uses different IP header structure
    #define IP_HEADER_LENGTH(ip) ((ip)->ip_hl << 2)
    #define IP_PROTOCOL(ip)      (ip)->ip_p
    #define IP_SOURCE_ADDR(ip)   (ip)->ip_src.s_addr
    #define IP_DEST_ADDR(ip)     (ip)->ip_dst.s_addr
    
    typedef struct ip platform_iphdr;
    typedef struct udphdr platform_udphdr;
#else
    // Linux uses standard udphdr
    #define UDP_SOURCE_PORT(udp) (udp)->source
    #define UDP_DEST_PORT(udp)   (udp)->dest
    #define UDP_LENGTH(udp)      (udp)->len
    
    // Linux IP header structure
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
 * @brief MAVLink Network Packet Analyzer
 * 
 * This class can:
 * 1. Parse tcpdump output files
 * 2. Directly capture network packets
 * 3. Extract pure payload from network packets
 * 4. Parse MAVLink messages within
 * 5. Output detailed log information
 */
class MavlinkNetworkAnalyzer {
public:
    /**
     * @brief Constructor
     */
    MavlinkNetworkAnalyzer();
    
    /**
     * @brief Destructor
     */
    ~MavlinkNetworkAnalyzer();

    /**
     * @brief Parse MAVLink packets from tcpdump output file
     * @param file_path Path to tcpdump output file
     * @return Whether parsing was successful
     */
    bool parse_tcpdump_file(const std::string& file_path);

    /**
     * @brief Start real-time network packet capture
     * @param interface Network interface name (e.g. "eth0", "wlan0")
     * @param filter_expression BPF filter expression (default: UDP port 14550)
     * @return Whether capture was started successfully
     */
    bool start_packet_capture(const std::string& interface, 
                             const std::string& filter_expression = "udp port 14550");

    /**
     * @brief Stop network packet capture
     */
    void stop_packet_capture();

    /**
     * @brief Set log output level
     * @param verbose Whether to output detailed information
     */
    void set_verbose(bool verbose) { verbose_ = verbose; }

    /**
     * @brief Set message ID list for detailed display
     * @param message_ids Vector of message IDs
     */
    void set_verbose_message_ids(const std::vector<uint32_t>& message_ids) { 
        verbose_message_ids_ = message_ids;
    }

    /**
     * @brief Set message ID list for filtering
     * @param message_ids Vector of message IDs, only these messages will be processed
     */
    void set_filter_message_ids(const std::vector<uint32_t>& message_ids) { 
        filter_message_ids_ = message_ids;
    }

    /**
     * @brief Set source IP filter
     * @param src_ip Source IP address, only process packets from this IP
     */
    void set_source_ip_filter(const std::string& src_ip) { 
        filter_source_ip_ = src_ip;
    }

    /**
     * @brief Set destination IP filter
     * @param dst_ip Destination IP address, only process packets to this IP
     */
    void set_destination_ip_filter(const std::string& dst_ip) { 
        filter_destination_ip_ = dst_ip;
    }

    /**
     * @brief Set whether to show hexadecimal content
     * @param show_hex Whether to show hexadecimal content
     */
    void set_show_hex(bool show_hex) { show_hex_ = show_hex; }

private:
    /**
     * @brief Parse a single network packet
     * @param packet_data Packet data
     * @param packet_len Packet length
     * @param timestamp Timestamp
     */
    void parse_packet(const uint8_t* packet_data, int packet_len, 
                     const std::string& timestamp = "");

    /**
     * @brief Extract and parse MAVLink messages from UDP payload
     * @param udp_payload UDP payload data
     * @param payload_len Payload length
     * @param src_ip Source IP address
     * @param dst_ip Destination IP address
     * @param src_port Source port
     * @param dst_port Destination port
     * @param timestamp Timestamp
     */
    void extract_mavlink_from_udp(const uint8_t* udp_payload, int payload_len,
                                 const std::string& src_ip, const std::string& dst_ip,
                                 uint16_t src_port, uint16_t dst_port,
                                 const std::string& timestamp);

    /**
     * @brief Parse MAVLink message
     * @param mavlink_data MAVLink message data
     * @param data_len Data length
     * @param src_ip Source IP address
     * @param dst_ip Destination IP address
     * @param src_port Source port
     * @param dst_port Destination port
     * @param timestamp Timestamp
     */
    void parse_mavlink_message(const uint8_t* mavlink_data, int data_len,
                              const std::string& src_ip, const std::string& dst_ip,
                              uint16_t src_port, uint16_t dst_port,
                              const std::string& timestamp);

    /**
     * @brief Get MAVLink message type name
     * @param msg_id Message ID
     * @return Message type name
     */
    std::string get_mavlink_message_name(uint32_t msg_id);

    /**
     * @brief Format MAVLink message content for output
     * @param msg MAVLink message
     * @return Formatted message content string
     */
    std::string format_mavlink_message_content(const mavlink_message_t& msg);

    /**
     * @brief Format short MAVLink message content for output
     * @param msg MAVLink message
     * @return Formatted short message content string
     */
    std::string format_mavlink_message_content_short(const mavlink_message_t& msg);

    /**
     * @brief Check if message ID should be displayed in detail
     * @param msg_id Message ID
     * @return Whether to display in detail
     */
    bool should_show_verbose(uint32_t msg_id) const;

    /**
     * @brief Check if message ID should be processed (filter check)
     * @param msg_id Message ID
     * @return Whether to process this message
     */
    bool should_process_message(uint32_t msg_id) const;

    /**
     * @brief Check if IP addresses should be processed (IP filter check)
     * @param src_ip Source IP address
     * @param dst_ip Destination IP address
     * @return Whether to process this packet
     */
    bool should_process_packet(const std::string& src_ip, const std::string& dst_ip) const;

    /**
     * @brief Format hexadecimal output
     * @param data Data pointer
     * @param length Data length
     * @return Formatted hexadecimal string
     */
    std::string format_hex_output(const uint8_t* data, int length) const;

    /**
     * @brief Output parsing log
     * @param level Log level
     * @param message Log message
     */
    void log(const std::string& level, const std::string& message);

    /**
     * @brief pcap callback function (static)
     */
    static void packet_handler(uint8_t* user_data, const struct pcap_pkthdr* pkthdr,
                              const uint8_t* packet_data);

    // Member variables
    bool verbose_;
    bool show_hex_;
    std::atomic<bool> capturing_;
    std::thread capture_thread_;
    pcap_t* pcap_handle_;
    
    // MAVLink parsing related
    mavlink_status_t mavlink_status_;
    uint8_t mavlink_channel_;
    
    // Detailed display message ID list
    std::vector<uint32_t> verbose_message_ids_;
    
    // Filter message ID list (only process these IDs)
    std::vector<uint32_t> filter_message_ids_;
    
    // IP filtering conditions
    std::string filter_source_ip_;      // Source IP filter (empty string means no filter)
    std::string filter_destination_ip_; // Destination IP filter (empty string means no filter)
};

} // namespace tools
} // namespace codevsdk