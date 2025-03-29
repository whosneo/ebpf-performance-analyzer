# eBPF性能分析工具

这是一个使用eBPF技术的性能分析工具集，可以帮助分析系统和应用程序的性能问题，并提供性能优化建议。

## 项目结构

```
ebpf-performance-analyzer/
├── src/           # eBPF程序源代码
├── tools/         # 辅助工具和脚本
└── docs/          # 文档和教程
```

## 功能特性

- CPU使用率分析：监控进程CPU使用情况
- 内存分析：跟踪内存分配和释放
- I/O性能分析：监控磁盘I/O操作
- 网络性能分析：监控网络连接和吞吐量
- 系统调用跟踪：分析系统调用模式和频率

## 环境要求

- Linux内核版本 >= 4.9（推荐5.10+）
- BCC (BPF Compiler Collection)
- LLVM和Clang
- Python 3.6+

## 安装

### 安装依赖项

```bash
# 在Ubuntu/Debian上
sudo apt-get update
sudo apt-get install -y bpfcc-tools linux-headers-$(uname -r) python3-bpfcc

# 在CentOS/RHEL上
sudo yum install -y bcc-tools kernel-devel python3-bcc
```

### 克隆仓库

```bash
git clone https://github.com/whosneo/ebpf-performance-analyzer.git
cd ebpf-performance-analyzer
```

## 使用方法

### CPU性能分析

```bash
sudo python3 tools/cpu_profiler.py [PID]
```

### 内存分析

```bash
sudo python3 tools/memory_analyzer.py [PID]
```

### I/O性能分析

```bash
sudo python3 tools/io_analyzer.py [PID]
```

### 网络性能分析

```bash
sudo python3 tools/network_profiler.py [interface]
```

## 学习资源

- [eBPF官方文档](https://ebpf.io/what-is-ebpf/)
- [BCC参考指南](https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md)
- docs/目录下的教程和示例 