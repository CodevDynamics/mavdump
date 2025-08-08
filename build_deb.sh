#!/bin/bash

# MAVDump DEB Package Build Script
# Creates a deb package that can be installed on Ubuntu systems

set -e  # Exit immediately on error

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Print colored messages
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Get Ubuntu codename
get_ubuntu_codename() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        echo "$VERSION_CODENAME"
    elif [ -f /etc/lsb-release ]; then
        . /etc/lsb-release
        echo "$DISTRIB_CODENAME"
    else
        # Fallback: try lsb_release command
        if command -v lsb_release &> /dev/null; then
            lsb_release -cs
        else
            echo "unknown"
        fi
    fi
}

# Project information
PROJECT_NAME="mavdump"
VERSION="1.0.0"
ARCHITECTURE="$(dpkg --print-architecture)"
UBUNTU_CODENAME="$(get_ubuntu_codename)"
MAINTAINER="JinYan Wang <auto@auto.com>"
DESCRIPTION="MAVLink network packet analyzer tool"
LONG_DESCRIPTION="A tool for capturing and parsing MAVLink packets from network traffic, supporting both file parsing and real-time capture modes."

# Check dependencies
check_dependencies() {
    print_status "Checking build dependencies..."
    
    local missing_deps=()
    
    if ! command -v cmake &> /dev/null; then
        missing_deps+=("cmake")
    fi
    
    if ! command -v make &> /dev/null; then
        missing_deps+=("build-essential")
    fi
    
    if ! dpkg -l | grep -q libpcap-dev; then
        missing_deps+=("libpcap-dev")
    fi
    
    if ! command -v dpkg-deb &> /dev/null; then
        missing_deps+=("dpkg-dev")
    fi
    
    if [ ${#missing_deps[@]} -ne 0 ]; then
        print_error "Missing dependencies: ${missing_deps[*]}"
        print_status "Please run the following commands to install dependencies:"
        echo "sudo apt-get update"
        echo "sudo apt-get install ${missing_deps[*]}"
        exit 1
    fi
    
    print_success "All dependencies satisfied"
}

# Clean previous builds
clean_previous_builds() {
    print_status "Cleaning previous builds..."
    rm -rf build-deb
    rm -rf debian
    rm -f *.deb
    print_success "Cleanup completed"
}

# Build project
build_project() {
    print_status "Building project..."
    
    # Create build directory
    mkdir -p build-deb
    cd build-deb
    
    # Configure CMake with Release mode
    cmake -DCMAKE_BUILD_TYPE=Release \
          -DCMAKE_INSTALL_PREFIX=/usr \
          ..
    
    # Compile project
    make -j$(nproc)
    
    cd ..
    print_success "Project build completed"
}

# Create Debian package structure
create_debian_structure() {
    print_status "Creating Debian package structure..."
    
    local pkg_dir="debian/${PROJECT_NAME}"
    
    # Create package directory structure
    mkdir -p "${pkg_dir}/DEBIAN"
    mkdir -p "${pkg_dir}/usr/bin"
    mkdir -p "${pkg_dir}/usr/share/doc/${PROJECT_NAME}"
    mkdir -p "${pkg_dir}/usr/share/man/man1"
    
    # Copy executable file
    cp build-deb/${PROJECT_NAME} "${pkg_dir}/usr/bin/"
    
    # Set executable permissions
    chmod 755 "${pkg_dir}/usr/bin/${PROJECT_NAME}"
    
    # Copy documentation
    cp README.md "${pkg_dir}/usr/share/doc/${PROJECT_NAME}/"
    
    print_success "Debian package structure created"
}

# Create control file
create_control_file() {
    print_status "Creating control file..."
    
    local control_file="debian/${PROJECT_NAME}/DEBIAN/control"
    
    cat > "${control_file}" << EOF
Package: ${PROJECT_NAME}
Version: ${VERSION}
Section: net
Priority: optional
Architecture: ${ARCHITECTURE}
Depends: libpcap0.8 (>= 1.0.0), libc6 (>= 2.14), libgcc-s1 (>= 3.0), libstdc++6 (>= 5.2)
Maintainer: ${MAINTAINER}
Description: ${DESCRIPTION}
 ${LONG_DESCRIPTION}
 .
 Key features:
 - Parse tcpdump output files and extract MAVLink messages
 - Capture network packets in real-time and parse MAVLink messages
 - Extract pure payload data from network packets
 - Parse MAVLink messages and output detailed log information
 .
 Supported platforms: Ubuntu 18.04+, Debian 9+
EOF

    print_success "Control file created"
}

# Create postinst script (post-installation script)
create_postinst_script() {
    print_status "Creating post-installation script..."
    
    local postinst_file="debian/${PROJECT_NAME}/DEBIAN/postinst"
    
    cat > "${postinst_file}" << 'EOF'
#!/bin/bash

set -e

# Create symbolic link to PATH (if needed)
if [ ! -L /usr/local/bin/mavdump ]; then
    ln -sf /usr/bin/mavdump /usr/local/bin/mavdump 2>/dev/null || true
fi

# Output installation success message
echo "MAVDump installation completed!"
echo "Usage:"
echo "  mavdump -h                    # Show help"
echo "  mavdump -f capture.log        # Parse tcpdump file"
echo "  sudo mavdump -i eth0          # Real-time packet capture"
echo ""
echo "For more information see: /usr/share/doc/mavdump/README.md"

exit 0
EOF

    chmod 755 "${postinst_file}"
    print_success "Post-installation script created"
}

# Create prerm script (pre-removal script)
create_prerm_script() {
    print_status "Creating pre-removal script..."
    
    local prerm_file="debian/${PROJECT_NAME}/DEBIAN/prerm"
    
    cat > "${prerm_file}" << 'EOF'
#!/bin/bash

set -e

# Remove symbolic link
if [ -L /usr/local/bin/mavdump ]; then
    rm -f /usr/local/bin/mavdump
fi

echo "MAVDump has been uninstalled"

exit 0
EOF

    chmod 755 "${prerm_file}"
    print_success "Pre-removal script created"
}

# Create man page
create_man_page() {
    print_status "Creating man page..."
    
    local man_file="debian/${PROJECT_NAME}/usr/share/man/man1/${PROJECT_NAME}.1"
    
    cat > "${man_file}" << EOF
.TH MAVDUMP 1 "$(date '+%B %Y')" "mavdump ${VERSION}" "User Commands"
.SH NAME
mavdump \- MAVLink network packet analyzer tool
.SH SYNOPSIS
.B mavdump
[\fIOPTIONS\fR]
.SH DESCRIPTION
MAVDump is a tool for capturing and parsing MAVLink packets from network traffic. It can parse tcpdump output files or perform real-time network packet capture.
.SH OPTIONS
.TP
.BR \-f ", " \-\-file " " \fIFILE\fR
Parse tcpdump output file
.TP
.BR \-i ", " \-\-interface " " \fIIFACE\fR
Specify network interface name (e.g., eth0, wlan0)
.TP
.BR \-p ", " \-\-port " " \fIPORT\fR
Specify MAVLink port number (default: 14550)
.TP
.BR \-v ", " \-\-verbose
Output detailed information
.TP
.BR \-h ", " \-\-help
Show help information
.SH EXAMPLES
.TP
Parse tcpdump file:
.B mavdump \-f mavlink_capture.log
.TP
Real-time packet capture:
.B sudo mavdump \-i eth0 \-p 14550 \-v
.SH AUTHOR
MAVDump Team
.SH SEE ALSO
.BR tcpdump (1),
.BR wireshark (1)
EOF

    # Compress man page
    gzip -f "${man_file}"
    print_success "Man page created"
}

# Build DEB package
build_deb_package() {
    print_status "Building DEB package..."
    
    local pkg_dir="debian/${PROJECT_NAME}"
    local output_file="${PROJECT_NAME}_${VERSION}-${UBUNTU_CODENAME}_${ARCHITECTURE}.deb"
    
    # Set correct permissions
    find "${pkg_dir}" -type f -exec chmod 644 {} \;
    find "${pkg_dir}" -type d -exec chmod 755 {} \;
    chmod 755 "${pkg_dir}/usr/bin/${PROJECT_NAME}"
    chmod 755 "${pkg_dir}/DEBIAN/postinst" 2>/dev/null || true
    chmod 755 "${pkg_dir}/DEBIAN/prerm" 2>/dev/null || true
    
    # Build package
    dpkg-deb --build "${pkg_dir}" "${output_file}"
    
    print_success "DEB package build completed: ${output_file}"
}

# Verify DEB package
verify_deb_package() {
    print_status "Verifying DEB package..."
    
    local deb_file="${PROJECT_NAME}_${VERSION}-${UBUNTU_CODENAME}_${ARCHITECTURE}.deb"
    
    if [ ! -f "${deb_file}" ]; then
        print_error "DEB package file does not exist: ${deb_file}"
        exit 1
    fi
    
    # Check package information
    print_status "Package information:"
    dpkg-deb --info "${deb_file}"
    
    print_status "Package contents:"
    dpkg-deb --contents "${deb_file}"
    
    # Check if package can be parsed correctly
    if dpkg-deb --info "${deb_file}" > /dev/null 2>&1; then
        print_success "DEB package verification passed"
    else
        print_error "DEB package verification failed"
        exit 1
    fi
}

# Show installation instructions
show_installation_instructions() {
    local deb_file="${PROJECT_NAME}_${VERSION}-${UBUNTU_CODENAME}_${ARCHITECTURE}.deb"
    
    echo ""
    print_success "=================================="
    print_success "DEB package generation completed!"
    print_success "=================================="
    echo ""
    print_status "Generated package file: ${deb_file}"
    echo ""
    print_status "Installation instructions:"
    echo "1. Copy deb package to target Ubuntu system"
    echo "2. Install dependencies (if needed):"
    echo "   sudo apt-get update"
    echo "   sudo apt-get install libpcap0.8"
    echo "3. Install package:"
    echo "   sudo dpkg -i ${deb_file}"
    echo "4. If there are dependency issues, run:"
    echo "   sudo apt-get install -f"
    echo ""
    print_status "Uninstall method:"
    echo "   sudo apt-get remove ${PROJECT_NAME}"
    echo ""
    print_status "Usage:"
    echo "   mavdump -h                    # Show help"
    echo "   mavdump -f capture.log        # Parse tcpdump file"
    echo "   sudo mavdump -i eth0          # Real-time packet capture"
}

# Main function
main() {
    echo ""
    print_status "=================================="
    print_status "MAVDump DEB Package Build Script"
    print_status "=================================="
    echo ""
    
    # Check if we're in the correct directory
    if [ ! -f "CMakeLists.txt" ] || [ ! -f "mavdump.cpp" ]; then
        print_error "Please run this script from the mavdump project root directory"
        exit 1
    fi
    
    # Display build information
    print_status "Build Configuration:"
    echo "  Project Name: ${PROJECT_NAME}"
    echo "  Version: ${VERSION}"
    echo "  Architecture: ${ARCHITECTURE}"
    echo "  Ubuntu Codename: ${UBUNTU_CODENAME}"
    echo "  Package Name: ${PROJECT_NAME}_${VERSION}-${UBUNTU_CODENAME}_${ARCHITECTURE}.deb"
    echo ""
    
    # Execute build steps
    check_dependencies
    clean_previous_builds
    build_project
    create_debian_structure
    create_control_file
    create_postinst_script
    create_prerm_script
    create_man_page
    build_deb_package
    verify_deb_package
    show_installation_instructions
    
    print_success "All steps completed!"
}

# Script parameter handling
case "${1:-}" in
    --help|-h)
        echo "Usage: $0 [options]"
        echo ""
        echo "Options:"
        echo "  --help, -h     Show this help information"
        echo "  --clean        Clean build files only"
        echo ""
        echo "This script will build the mavdump project and generate an Ubuntu deb package."
        exit 0
        ;;
    --clean)
        clean_previous_builds
        print_success "Cleanup completed"
        exit 0
        ;;
    "")
        main
        ;;
    *)
        print_error "Unknown option: $1"
        echo "Use --help to see help information"
        exit 1
        ;;
esac
