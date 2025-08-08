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
    std::cout << "\n收到信号 " << signum << "，正在停止数据包捕获..." << std::endl;
    if (analyzer) {
        analyzer->stop_packet_capture();
    }
    exit(signum);
}

void print_usage(const char* program_name) {
    std::cout << "用法: " << program_name << " [选项]\n\n";
    std::cout << "MAVLink 网络数据包分析工具\n\n";
    std::cout << "选项:\n";
    std::cout << "  -f, --file FILE         解析 tcpdump 输出文件\n";
    std::cout << "  -i, --interface IFACE   网络接口名称 (如: eth0, wlan0)\n";
    std::cout << "  -p, --port PORT         MAVLink 端口号 (默认: 14550)\n";
    std::cout << "  -v, --verbose           输出所有消息的详细信息\n";
    std::cout << "      --vids IDS          指定消息ID列表显示详细信息 (逗号分隔，如: 0,1,33)\n";
    std::cout << "  -H, --hex               在详细模式下显示消息的十六进制内容\n";
    std::cout << "  -h, --help              显示此帮助信息\n\n";
    std::cout << "示例:\n";
    std::cout << "  " << program_name << " -f /path/to/tcpdump.log -v\n";
    std::cout << "  " << program_name << " -i eth0 -p 14550 --vids 0,1,33\n";
    std::cout << "  " << program_name << " -i wlan0 --verbose -H\n";
    std::cout << "  " << program_name << " -f capture.log --vids 0,30,33,76 --hex\n\n";
    std::cout << "说明:\n";
    std::cout << "  1. 使用 -f 选项解析已有的 tcpdump 输出文件\n";
    std::cout << "  2. 使用 -i 选项进行实时数据包捕获\n";
    std::cout << "  3. -v 显示所有消息的详细字段信息\n";
    std::cout << "  4. --vids 只对指定的消息ID显示详细信息，其他消息简洁显示\n";
    std::cout << "  5. -H 在详细模式下显示消息的十六进制内容（每行16字节）\n";
    std::cout << "  6. 输出包含源地址、目标地址、消息类型和内容等信息\n\n";
    std::cout << "生成 tcpdump 文件的命令示例:\n";
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

    // 命令行选项定义
    static struct option long_options[] = {
        {"file", required_argument, 0, 'f'},
        {"interface", required_argument, 0, 'i'},
        {"port", required_argument, 0, 'p'},
        {"verbose", no_argument, 0, 'v'},
        {"vids", required_argument, 0, 1000}, // 使用特殊值避免与字符冲突
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
                    std::cerr << "错误: 端口号必须在 1-65535 范围内" << std::endl;
                    return 1;
                }
                break;
            case 'v':
                verbose = true;
                break;
            case 1000: // --vids
                verbose_ids_str = optarg;
                break;
            case 'H':
                show_hex = true;
                break;
            case 'h':
                print_usage(argv[0]);
                return 0;
            case '?':
                std::cerr << "使用 -h 或 --help 查看帮助信息" << std::endl;
                return 1;
            default:
                break;
        }
    }

    // 检查参数
    if (file_path.empty() && interface.empty()) {
        std::cerr << "错误: 必须指定文件路径 (-f) 或网络接口 (-i)" << std::endl;
        std::cerr << "使用 -h 或 --help 查看帮助信息" << std::endl;
        return 1;
    }

    if (!file_path.empty() && !interface.empty()) {
        std::cerr << "错误: 不能同时指定文件和网络接口" << std::endl;
        return 1;
    }

    // 创建分析器
    analyzer = std::make_unique<codevsdk::tools::MavlinkNetworkAnalyzer>();
    analyzer->set_verbose(verbose);
    analyzer->set_show_hex(show_hex);
    
    // 处理verbose_ids选项
    if (!verbose_ids_str.empty()) {
        std::vector<uint32_t> verbose_ids;
        std::stringstream ss(verbose_ids_str);
        std::string id_str;
        
        while (std::getline(ss, id_str, ',')) {
            try {
                uint32_t id = std::stoul(id_str);
                verbose_ids.push_back(id);
            } catch (const std::exception& e) {
                std::cerr << "错误: 无效的消息ID '" << id_str << "'" << std::endl;
                return 1;
            }
        }
        
        if (!verbose_ids.empty()) {
            analyzer->set_verbose_message_ids(verbose_ids);
            std::cout << "仅对以下消息ID显示详细信息: ";
            for (size_t i = 0; i < verbose_ids.size(); ++i) {
                if (i > 0) std::cout << ",";
                std::cout << verbose_ids[i];
            }
            std::cout << std::endl;
        }
    }

    // 设置信号处理器
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    try {
        if (!file_path.empty()) {
            // 解析文件模式
            std::cout << "正在解析 tcpdump 文件: " << file_path << std::endl;
            if (verbose) {
                std::cout << "详细模式已启用" << std::endl;
            }
            
            if (!analyzer->parse_tcpdump_file(file_path)) {
                std::cerr << "解析文件失败" << std::endl;
                return 1;
            }
        } else {
            // 实时捕获模式
            std::cout << "正在启动实时数据包捕获..." << std::endl;
            std::cout << "网络接口: " << interface << std::endl;
            std::cout << "目标端口: " << port << std::endl;
            if (verbose) {
                std::cout << "详细模式已启用" << std::endl;
            }
            
            std::string filter = "udp port " + std::to_string(port);
            
            if (!analyzer->start_packet_capture(interface, filter)) {
                std::cerr << "启动数据包捕获失败" << std::endl;
                std::cerr << "提示: 可能需要以 root 权限运行此程序" << std::endl;
                return 1;
            }
            
            std::cout << "数据包捕获已启动，按 Ctrl+C 停止..." << std::endl;
            
            // 等待用户中断
            while (true) {
                std::this_thread::sleep_for(std::chrono::seconds(1));
            }
        }
    } catch (const std::exception& e) {
        std::cerr << "发生异常: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}