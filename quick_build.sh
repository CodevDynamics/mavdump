#!/bin/bash

# Quick build script for MAVDump
# This is a simplified version that just builds the project without creating a deb package

set -e

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if we're in the right directory
if [ ! -f "CMakeLists.txt" ] || [ ! -f "mavdump.cpp" ]; then
    print_error "Please run this script from the mavdump project root directory"
    exit 1
fi

print_info "Building MAVDump project..."

# Create build directory
mkdir -p build
cd build

# Configure and build
print_info "Configuring with CMake..."
cmake -DCMAKE_BUILD_TYPE=Release ..

print_info "Compiling..."
make -j$(nproc)

cd ..

print_success "Build completed!"
print_info "Executable location: build/mavdump"
print_info ""
print_info "Usage examples:"
print_info "  ./build/mavdump -h                    # Show help"
print_info "  ./build/mavdump -f capture.log        # Parse tcpdump file"
print_info "  sudo ./build/mavdump -i eth0          # Real-time packet capture"
print_info ""
print_info "To create a deb package, run: ./build_deb.sh"
