# eBPF性能分析工具

这是一个使用eBPF技术的性能分析工具集，可以帮助分析系统和应用程序的性能问题，并提供性能优化建议。

## 版本

**当前版本**: v0.2.0

[查看完整变更日志](CHANGELOG.md)

## 项目结构

```
ebpf-performance-analyzer/
├── src/           # eBPF程序源代码和公共模块
├── tools/         # 辅助工具和脚本
└── docs/          # 文档和教程
```

## 功能特性

- CPU使用率分析：监控进程CPU使用情况
- 内存分析：跟踪内存分配和释放
- I/O性能分析：监控磁盘I/O操作
- 网络性能分析：监控网络连接和吞吐量
- 系统调用跟踪：分析系统调用模式和频率
- 锁分析：监控和分析系统中的锁争用情况
- 内存泄漏检测：识别未释放的内存分配和潜在的内存泄漏
- 缓存分析：监控CPU缓存命中和未命中情况
- 调度器分析：监控进程调度行为和延迟
- 文件系统分析：监控文件系统操作和性能
- 中断分析：跟踪硬件和软件中断处理
- 页面错误分析：监控内存页面错误和交换行为

## 工具列表

| 工具名称 | 描述 | 用途 |
|---------|------|------|
| cpu_profiler.py | CPU性能分析器 | 分析CPU使用情况和热点函数 |
| memory_analyzer.py | 内存分析器 | 跟踪内存分配和使用模式 |
| memory_leak_detector.py | 内存泄漏检测器 | 识别未释放的内存分配 |
| io_analyzer.py | I/O性能分析器 | 监控磁盘I/O操作和延迟 |
| network_profiler.py | 网络性能分析器 | 分析网络连接和数据传输 |
| lock_analyzer.py | 锁分析器 | 监控和分析锁争用情况 |
| syscall_analyzer.py | 系统调用分析器 | 跟踪和分析系统调用 |
| cache_analyzer.py | 缓存分析器 | 监控CPU缓存使用情况 |
| scheduler_analyzer.py | 调度器分析器 | 分析进程调度行为 |
| fs_analyzer.py | 文件系统分析器 | 监控文件系统操作 |
| irq_analyzer.py | 中断分析器 | 跟踪中断处理和延迟 |
| page_fault_analyzer.py | 页面错误分析器 | 分析内存页面错误 |

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

### 锁分析

```bash
sudo python3 tools/lock_analyzer.py [PID]
```

### 内存泄漏检测

```bash
sudo python3 tools/memory_leak_detector.py [PID]
```

### 系统调用分析

```bash
sudo python3 tools/syscall_analyzer.py [PID]
```

### 缓存分析

```bash
sudo python3 tools/cache_analyzer.py [PID]
```

### 调度器分析

```bash
sudo python3 tools/scheduler_analyzer.py [PID]
```

### 文件系统分析

```bash
sudo python3 tools/fs_analyzer.py [PID]
```

### 中断分析

```bash
sudo python3 tools/irq_analyzer.py
```

### 页面错误分析

```bash
sudo python3 tools/page_fault_analyzer.py [PID]
```

## 详细文档

更详细的使用说明和示例请参考以下文档：

- [快速入门指南](docs/quick_start.md)
- [学习资源](docs/learning_resources.md)

## 贡献

欢迎贡献代码、报告问题或提出改进建议！请查看[贡献指南](CONTRIBUTING.md)了解如何参与项目开发。

## 学习资源

- [eBPF官方文档](https://ebpf.io/what-is-ebpf/)
- [BCC参考指南](https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md)
- docs/目录下的教程和示例 