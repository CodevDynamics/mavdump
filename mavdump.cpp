#include "mavlink_network_analyzer.hpp"
#include <iostream>
#include <csignal>
#include <getopt.h>
#include <memory>
#include <thread>
#include <chrono>
#include <sstream>
#include <vector>

std::unique_ptr<codevsdk::tools::MavlinkNetworkAnalyzer> analyzer;

void signal_handler(int signum) {
    std::cout << "\nReceived signal " << signum << ", stopping packet capture..." << std::endl;
    if (analyzer) {
        analyzer->stop_packet_capture();
    }
    exit(signum);
}

void print_usage(const char* program_name) {
    std::cout << "Usage: " << program_name << " [options]\n\n";
    std::cout << "MAVLink Network Packet Analyzer Tool\n\n";
    std::cout << "Options:\n";
    std::cout << "  -f, --file FILE         Parse tcpdump output file\n";
    std::cout << "  -i, --interface IFACE   Network interface name (e.g. eth0, wlan0)\n";
    std::cout << "  -p, --port PORT         MAVLink port number (default: 14550)\n";
    std::cout << "  -v, --verbose           Output detailed information for all messages\n";
    std::cout << "      --vids IDS          Show detailed info for specified message IDs (comma-separated, e.g. 0,1,33)\n";
    std::cout << "      --ids IDS           Only capture specified message IDs (comma-separated, e.g. 0,1,33)\n";
    std::cout << "      --src IP            Only parse packets from specified source IP\n";
    std::cout << "      --dst IP            Only parse packets to specified destination IP\n";
    std::cout << "  -H, --hex               Show hexadecimal content of messages in verbose mode\n";
    std::cout << "  -h, --help              Show this help information\n\n";
    std::cout << "Examples:\n";
    std::cout << "  " << program_name << " -f /path/to/tcpdump.log -v\n";
    std::cout << "  " << program_name << " -i eth0 -p 14550 --vids 0,1,33\n";
    std::cout << "  " << program_name << " -i wlan0 --verbose -H\n";
    std::cout << "  " << program_name << " -f capture.log --vids 0,30,33,76 --hex\n";
    std::cout << "  " << program_name << " -i eth0 --ids 0,1,30 -v\n";
    std::cout << "  " << program_name << " -f capture.log --src 192.168.1.100\n";
    std::cout << "  " << program_name << " -i eth0 --dst 192.168.1.200 --ids 0,1\n\n";
    std::cout << "Description:\n";
    std::cout << "  1. Use -f option to parse existing tcpdump output files\n";
    std::cout << "  2. Use -i option for real-time packet capture\n";
    std::cout << "  3. -v shows detailed field information for all messages\n";
    std::cout << "  4. --vids shows detailed info only for specified message IDs, others are brief\n";
    std::cout << "  5. --ids only captures and displays specified message IDs, filtering out others\n";
    std::cout << "  6. --src only parses packets from specified source IP address\n";
    std::cout << "  7. --dst only parses packets to specified destination IP address\n";
    std::cout << "  8. -H shows hexadecimal content of messages in verbose mode (16 bytes per line)\n";
    std::cout << "  9. Output includes source address, destination address, message type and content\n\n";
    std::cout << "Example commands to generate tcpdump files:\n";
    std::cout << "  sudo tcpdump -i any -X udp port 14550 > mavlink_capture.log\n";
    std::cout << "  sudo tcpdump -i eth0 -X 'udp and port 14550' -w capture.pcap\n";
}

int main(int argc, char* argv[]) {
    std::string file_path;
    std::string interface;
    int port = 14550;
    bool verbose = false;
    bool show_hex = false;
    std::string verbose_ids_str;
    std::string filter_ids_str;
    std::string src_ip;
    std::string dst_ip;

    // Command line options definition
    static struct option long_options[] = {
        {"file", required_argument, 0, 'f'},
        {"interface", required_argument, 0, 'i'},
        {"port", required_argument, 0, 'p'},
        {"verbose", no_argument, 0, 'v'},
        {"vids", required_argument, 0, 1000}, // 使用特殊值避免与字符冲突
        {"ids", required_argument, 0, 1001}, // 新增过滤ID选项
        {"src", required_argument, 0, 1002}, // 源IP过滤选项
        {"dst", required_argument, 0, 1003}, // 目标IP过滤选项
        {"hex", no_argument, 0, 'H'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };

    int option_index = 0;
    int c;

    while ((c = getopt_long(argc, argv, "f:i:p:vHh", long_options, &option_index)) != -1) {
        switch (c) {
            case 'f':
                file_path = optarg;
                break;
            case 'i':
                interface = optarg;
                break;
            case 'p':
                port = std::atoi(optarg);
                if (port <= 0 || port > 65535) {
                    std::cerr << "Error: Port number must be in range 1-65535" << std::endl;
                    return 1;
                }
                break;
            case 'v':
                verbose = true;
                break;
            case 1000: // --vids
                verbose_ids_str = optarg;
                break;
            case 1001: // --ids
                filter_ids_str = optarg;
                break;
            case 1002: // --src
                src_ip = optarg;
                break;
            case 1003: // --dst
                dst_ip = optarg;
                break;
            case 'H':
                show_hex = true;
                break;
            case 'h':
                print_usage(argv[0]);
                return 0;
            case '?':
                std::cerr << "Use -h or --help to see help information" << std::endl;
                return 1;
            default:
                break;
        }
    }

    // Check parameters
    if (file_path.empty() && interface.empty()) {
        std::cerr << "Error: Must specify either file path (-f) or network interface (-i)" << std::endl;
        std::cerr << "Use -h or --help to see help information" << std::endl;
        return 1;
    }

    if (!file_path.empty() && !interface.empty()) {
        std::cerr << "Error: Cannot specify both file and network interface" << std::endl;
        return 1;
    }

    // Create analyzer
    analyzer = std::make_unique<codevsdk::tools::MavlinkNetworkAnalyzer>();
    analyzer->set_verbose(verbose);
    analyzer->set_show_hex(show_hex);
    
    // Process verbose_ids option
    if (!verbose_ids_str.empty()) {
        std::vector<uint32_t> verbose_ids;
        std::stringstream ss(verbose_ids_str);
        std::string id_str;
        
        while (std::getline(ss, id_str, ',')) {
            try {
                uint32_t id = std::stoul(id_str);
                verbose_ids.push_back(id);
            } catch (const std::exception& e) {
                std::cerr << "Error: Invalid message ID '" << id_str << "'" << std::endl;
                return 1;
            }
        }
        
        if (!verbose_ids.empty()) {
            analyzer->set_verbose_message_ids(verbose_ids);
            std::cout << "Show detailed info only for message IDs: ";
            for (size_t i = 0; i < verbose_ids.size(); ++i) {
                if (i > 0) std::cout << ",";
                std::cout << verbose_ids[i];
            }
            std::cout << std::endl;
        }
    }
    
    // Process filter_ids option  
    if (!filter_ids_str.empty()) {
        std::vector<uint32_t> filter_ids;
        std::stringstream ss(filter_ids_str);
        std::string id_str;
        
        while (std::getline(ss, id_str, ',')) {
            try {
                uint32_t id = std::stoul(id_str);
                filter_ids.push_back(id);
            } catch (const std::exception& e) {
                std::cerr << "Error: Invalid message ID '" << id_str << "'" << std::endl;
                return 1;
            }
        }
        
        if (!filter_ids.empty()) {
            analyzer->set_filter_message_ids(filter_ids);
            std::cout << "Only capture message IDs: ";
            for (size_t i = 0; i < filter_ids.size(); ++i) {
                if (i > 0) std::cout << ",";
                std::cout << filter_ids[i];
            }
            std::cout << std::endl;
        }
    }
    
    // Set IP filtering
    if (!src_ip.empty()) {
        analyzer->set_source_ip_filter(src_ip);
        std::cout << "Only parse packets from source IP: " << src_ip << std::endl;
    }
    
    if (!dst_ip.empty()) {
        analyzer->set_destination_ip_filter(dst_ip);
        std::cout << "Only parse packets to destination IP: " << dst_ip << std::endl;
    }

    // Set signal handlers
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    try {
        if (!file_path.empty()) {
            // File parsing mode
            std::cout << "Parsing tcpdump file: " << file_path << std::endl;
            if (verbose) {
                std::cout << "Verbose mode enabled" << std::endl;
            }
            
            if (!analyzer->parse_tcpdump_file(file_path)) {
                std::cerr << "Failed to parse file" << std::endl;
                return 1;
            }
        } else {
            // Real-time capture mode
            std::cout << "Starting real-time packet capture..." << std::endl;
            std::cout << "Network interface: " << interface << std::endl;
            std::cout << "Target port: " << port << std::endl;
            if (verbose) {
                std::cout << "Verbose mode enabled" << std::endl;
            }
            
            std::string filter = "udp port " + std::to_string(port);
            
            if (!analyzer->start_packet_capture(interface, filter)) {
                std::cerr << "Failed to start packet capture" << std::endl;
                std::cerr << "Hint: You may need to run this program with root privileges" << std::endl;
                return 1;
            }
            
            std::cout << "Packet capture started, press Ctrl+C to stop..." << std::endl;
            
            // Wait for user interrupt
            while (true) {
                std::this_thread::sleep_for(std::chrono::seconds(1));
            }
        }
    } catch (const std::exception& e) {
        std::cerr << "Exception occurred: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}