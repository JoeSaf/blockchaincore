#!/bin/bash

echo "Downloading required header-only dependencies..."

# Create third-party directory
mkdir -p include/third_party/nlohmann

# Download httplib (single header)
echo "Downloading httplib.h..."
curl -L -o include/third_party/httplib.h https://raw.githubusercontent.com/yhirose/cpp-httplib/master/httplib.h

# Download nlohmann/json (single header)
echo "Downloading nlohmann/json.hpp..."
curl -L -o include/third_party/nlohmann/json.hpp https://github.com/nlohmann/json/releases/download/v3.11.2/json.hpp

# Download spdlog headers if needed
if [ ! -d "/usr/include/spdlog" ]; then
    echo "Downloading spdlog..."
    mkdir -p include/third_party/spdlog
    git clone --depth 1 https://github.com/gabime/spdlog.git temp_spdlog
    cp -r temp_spdlog/include/spdlog/* include/third_party/spdlog/
    rm -rf temp_spdlog
fi

echo "Dependencies downloaded successfully!"
echo "Update your includes to use third_party/ prefix if needed."
