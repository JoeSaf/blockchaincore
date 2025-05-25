# Blockchain Core - Arch Linux Optimized

High-performance C++ blockchain core with P2P networking, optimized for Arch Linux.

## Quick Start

1. **Install dependencies:**
   ```bash
   sudo pacman -S base-devel cmake ninja openssl python pybind11 nlohmann-json
   ```

2. **Build the project:**
   ```bash
   ./build_arch.sh --all
   ```

3. **Run tests:**
   ```bash
   tests/run_tests.sh
   ```

4. **Start blockchain:**
   ```bash
   python polymorphicblock_p2p.py
   ```

## System Service

Install as systemd service:
```bash
sudo scripts/setup-systemd.sh install
sudo systemctl enable --now blockchain-node.service
```

## Monitoring

Start Prometheus exporter:
```bash
python monitoring/prometheus-exporter.py --port 9090
```

View metrics: http://localhost:9090/metrics

## Performance Tuning

Apply Arch Linux optimizations:
```bash
sudo scripts/arch-performance-tuning.sh
```

## Directory Structure

- `systemd/` - Systemd service files
- `scripts/` - Setup and utility scripts  
- `monitoring/` - Prometheus and Grafana configs
- `config/` - Configuration files
- `tests/` - Test suite
- `docs/` - Documentation
