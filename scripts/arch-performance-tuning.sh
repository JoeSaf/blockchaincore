#!/bin/bash
# arch-performance-tuning.sh - Arch Linux performance optimizations for blockchain nodes

set -euo pipefail

log_info() {
    echo "[INFO] $1"
}

log_warning() {
    echo "[WARNING] $1"
}

# CPU performance tuning
tune_cpu() {
    log_info "Tuning CPU performance..."
    
    # Set CPU governor to performance
    if [[ -f /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor ]]; then
        echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor >/dev/null
        log_info "CPU governor set to performance"
    fi
    
    # Enable turbo boost if available
    if [[ -f /sys/devices/system/cpu/intel_pstate/no_turbo ]]; then
        echo 0 | sudo tee /sys/devices/system/cpu/intel_pstate/no_turbo >/dev/null
        log_info "Intel turbo boost enabled"
    fi
}

# Memory tuning
tune_memory() {
    log_info "Tuning memory performance..."
    
    # Create sysctl config if it doesn't exist
    sudo mkdir -p /etc/sysctl.d
    
    # Optimize swappiness for server workloads
    echo 'vm.swappiness=10' | sudo tee /etc/sysctl.d/99-blockchain.conf >/dev/null
    
    # Increase dirty ratios for better write performance
    cat << 'EOFSYSCTL' | sudo tee -a /etc/sysctl.d/99-blockchain.conf >/dev/null
vm.dirty_ratio=40
vm.dirty_background_ratio=10
vm.dirty_expire_centisecs=3000
vm.dirty_writeback_centisecs=500

# Network buffer tuning
net.core.rmem_max=268435456
net.core.wmem_max=268435456
net.ipv4.tcp_rmem=4096 87380 268435456
net.ipv4.tcp_wmem=4096 65536 268435456
net.ipv4.tcp_congestion_control=bbr
net.core.netdev_max_backlog=5000
net.ipv4.tcp_window_scaling=1
net.ipv4.tcp_timestamps=1
net.ipv4.tcp_sack=1
net.ipv4.tcp_fack=1
net.ipv4.tcp_fastopen=3
EOFSYSCTL
    
    # Apply settings
    sudo sysctl -p /etc/sysctl.d/99-blockchain.conf
    
    log_info "Memory and network tuning applied"
}

# I/O scheduler optimization
tune_io() {
    log_info "Tuning I/O scheduler..."
    
    # Set I/O scheduler to mq-deadline for SSDs, bfq for HDDs
    for disk in /sys/block/sd*; do
        if [[ -f "$disk/queue/scheduler" ]]; then
            # Check if it's an SSD
            if [[ $(cat "$disk/queue/rotational") == "0" ]]; then
                echo mq-deadline | sudo tee "$disk/queue/scheduler" >/dev/null
                log_info "Set mq-deadline scheduler for SSD $(basename "$disk")"
            else
                echo bfq | sudo tee "$disk/queue/scheduler" >/dev/null
                log_info "Set bfq scheduler for HDD $(basename "$disk")"
            fi
        fi
    done
}

# Apply all optimizations
main() {
    echo "Arch Linux Performance Tuning for Blockchain"
    echo "============================================"
    
    tune_cpu
    tune_memory
    tune_io
    
    echo
    log_info "Performance tuning completed!"
    log_warning "Some changes require a reboot to take effect"
    log_info "Monitor performance with: htop, iotop, nethogs"
}

main "$@"
