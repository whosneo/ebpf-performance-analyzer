# eBPF性能分析工具 - 快速入门指南

本指南将帮助您快速上手使用eBPF性能分析工具来诊断系统和应用程序性能问题。

## 前提条件

在开始使用前，请确保您的系统满足以下要求：

- Linux内核版本 >= 4.9（推荐5.10+）
- 已安装BCC工具集
- 已安装必要的内核头文件
- Python 3.6+

## 安装依赖

```bash
# Ubuntu/Debian系统
sudo apt-get update
sudo apt-get install -y bpfcc-tools linux-headers-$(uname -r) python3-bpfcc

# CentOS/RHEL系统
sudo yum install -y bcc-tools kernel-devel python3-bcc
```

## 工具概览

本工具集包含六个主要的性能分析工具：

1. **CPU性能分析器** (`cpu_profiler.py`) - 分析CPU使用情况和热点函数
2. **内存分析器** (`memory_analyzer.py`) - 跟踪内存分配和潜在的内存泄漏
3. **I/O性能分析器** (`io_analyzer.py`) - 监控磁盘I/O操作和延迟
4. **网络性能分析器** (`network_profiler.py`) - 分析网络连接和数据传输
5. **锁分析器** (`lock_analyzer.py`) - 监控和分析系统中的锁争用情况
6. **内存泄漏检测器** (`memory_leak_detector.py`) - 跟踪内存分配和释放，识别未释放的内存分配

## 使用方法

### 1. CPU性能分析

CPU性能分析器允许您监控进程的CPU使用情况，识别占用CPU时间最多的函数调用。

```bash
# 监控特定PID的CPU使用情况
sudo python3 tools/cpu_profiler.py [PID]

# 监控所有进程的CPU使用情况（10秒）
sudo python3 tools/cpu_profiler.py

# 自定义监控时间（30秒）
sudo python3 tools/cpu_profiler.py -d 30

# 显示前5个CPU占用最高的函数
sudo python3 tools/cpu_profiler.py -t 5
```

输出示例：
```
开始监控PID 1234 的CPU使用情况...
监控持续时间: 10秒
开始时间: 2023-06-01 10:30:00
结束时间: 2023-06-01 10:30:10
总监控时间: 10.00秒

----- CPU使用情况排名前 10 的进程和函数 -----
#1 myapp:1234 - CPU时间: 0.354321秒
用户空间堆栈:
    main+0x123 [0x5555555551a3]
    process_data+0x45 [0x555555555245]
    compute_hash+0x67 [0x555555555367]
内核空间堆栈:
    entry_SYSCALL_64_after_hwframe+0x44 [0xffffffff81063694]
    do_syscall_64+0x5b [0xffffffff8106383b]
    ...
```

### 2. 内存分析

内存分析器追踪内存分配和释放，帮助识别内存泄漏和优化内存使用。

```bash
# 监控特定PID的内存使用情况
sudo python3 tools/memory_analyzer.py [PID]

# 仅显示可能的内存泄漏
sudo python3 tools/memory_analyzer.py [PID] --leaks

# 自定义监控时间（60秒）
sudo python3 tools/memory_analyzer.py [PID] -d 60
```

输出示例：
```
开始监控PID 1234 的内存分配情况...
监控持续时间: 10秒
开始时间: 2023-06-01 10:30:00
结束时间: 2023-06-01 10:30:10
总监控时间: 10.00秒

===== 内存分配统计 =====
总分配次数: 1543
总释放次数: 1489
未释放分配次数: 54
总活跃内存: 2.35 KB

===== 内存占用前 10 的堆栈 =====
#1 [可能泄漏] 1.25 KB
    分配: 27, 释放: 0, 差值: 27
调用堆栈:
    kmalloc+0x1e7 [0xffffffff81160b67]
    alloc_buffer+0x45 [0xffffffffa0023c45]
    ...
```

### 3. I/O性能分析

I/O性能分析器监控磁盘I/O操作，帮助识别I/O瓶颈和优化存储访问。

```bash
# 监控特定PID的I/O操作
sudo python3 tools/io_analyzer.py [PID]

# 同时跟踪文件级I/O操作
sudo python3 tools/io_analyzer.py [PID] --files

# 显示I/O最多的前20个进程
sudo python3 tools/io_analyzer.py -t 20
```

输出示例：
```
开始监控PID 1234 的I/O操作...
监控持续时间: 10秒
开始时间: 2023-06-01 10:30:00

== 开始实时I/O操作监控 ==
[10:30:01.234567] myapp (1234) 读取 4,096 字节, 延迟: 0.35 μs 磁盘: sda1
[10:30:01.345678] myapp (1234) 写入 8,192 字节, 延迟: 1.25 μs 磁盘: sda1
...

结束时间: 2023-06-01 10:30:10
总监控时间: 10.00秒

===== 进程I/O统计 =====
PID     命令              I/O操作数      总字节数          总MB      平均延迟(μs)     最大延迟(μs)
-----------------------------------------------------------------------------------------
1234    myapp                   134      3,256,320        3.11            0.75           5.67
...
```

### 4. 网络性能分析

网络性能分析器跟踪网络连接和数据传输，帮助优化网络性能和诊断网络问题。

```bash
# 监控特定PID的网络活动
sudo python3 tools/network_profiler.py [PID]

# 详细显示网络事件
sudo python3 tools/network_profiler.py [PID] --verbose

# 监控30秒的网络活动
sudo python3 tools/network_profiler.py -d 30
```

输出示例：
```
开始监控PID 1234 的网络活动...
监控持续时间: 10秒
开始时间: 2023-06-01 10:30:00

== 开始实时网络活动监控 ==
[10:30:01.234567] PID 1234 连接 TCP 192.168.1.100:45678 -> 93.184.216.34:443
[10:30:01.345678] myapp (1234) 发送 TCP 192.168.1.100:45678 -> 93.184.216.34:443 1,440 字节
...

结束时间: 2023-06-01 10:30:10
总监控时间: 10.00秒

===== 进程网络统计 =====
PID     进程名           接收(MB)       发送(MB)       总流量(MB)      数据包      重传     重传率%
------------------------------------------------------------------------------------------
1234    myapp                0.35          1.25           1.60         123        2       1.63
...
```

### 5. 锁分析

锁分析器用于监控和分析系统中的锁争用情况，帮助识别性能瓶颈。

```bash
# 监控特定PID的锁争用情况
sudo python3 tools/lock_analyzer.py [PID]

# 设置争用阈值（锁等待时间超过0.5ms才记录）
sudo python3 tools/lock_analyzer.py [PID] -t 0.5

# 只监控某种类型的锁（如互斥锁）
sudo python3 tools/lock_analyzer.py [PID] -l mutex

# 监控30秒并显示前10个高争用锁
sudo python3 tools/lock_analyzer.py [PID] -d 30 -c 10
```

输出示例：
```
开始监控PID 1234 的锁争用情况...
监控持续时间: 10秒
开始时间: 2023-06-01 10:30:00

== 开始实时锁争用监控 ==
[10:30:01.234567] Thread 1235 等待互斥锁 0x7f8a1c2b3d40，持有者: Thread 1236, 等待时间: 2.35ms
[10:30:02.345678] Thread 1237 等待自旋锁 0x7f8a1c2b3e80，持有者: Thread 1238, 等待时间: 0.78ms
...

结束时间: 2023-06-01 10:30:10
总监控时间: 10.00秒

===== 锁争用统计 =====
锁地址          类型       争用次数    总等待时间(ms)   平均等待时间(ms)   最大等待时间(ms)   持有线程
---------------------------------------------------------------------------------------------
0x7f8a1c2b3d40  mutex         27           63.5              2.35              7.82          1236
0x7f8a1c2b3e80  spinlock      14           10.9              0.78              1.25          1238
...

===== 热点争用堆栈 =====
#1 互斥锁 0x7f8a1c2b3d40 (27次争用)
获取锁堆栈:
    pthread_mutex_lock+0x1e7 [0x7f8a1c1b0b67]
    database_transaction+0x45 [0x555555556c45]
    process_request+0x67 [0x555555556367]
...
```

### 6. 内存泄漏检测

内存泄漏检测器专门用于跟踪内存分配和释放，识别潜在的内存泄漏。

```bash
# 监控特定PID的内存泄漏情况
sudo python3 tools/memory_leak_detector.py [PID]

# 设置报告间隔（每60秒生成一次报告）
sudo python3 tools/memory_leak_detector.py [PID] -t 60

# 只显示大于1KB的泄漏
sudo python3 tools/memory_leak_detector.py [PID] -s 1024

# 同时监控内核空间内存泄漏
sudo python3 tools/memory_leak_detector.py [PID] -k
```

输出示例：
```
开始监控PID 1234 的内存泄漏情况...
监控持续时间: 10分钟
开始时间: 2023-06-01 10:30:00

== 生成内存泄漏报告（10:31:00）==
检测到可能的内存泄漏：
1. 5.2MB 未释放（42次分配）
   堆栈:
   load_config+0x123 [0x555555555123]
   parse_json+0x45 [0x555555555245]
   main+0x67 [0x555555555067]

2. 1.8MB 未释放（15次分配）
   堆栈:
   create_buffer+0x87 [0x555555555387]
   process_image+0xab [0x5555555553ab]
   handle_request+0xcd [0x5555555553cd]
...

== 生成内存泄漏报告（10:32:00）==
检测到可能的内存泄漏：
1. 10.5MB 未释放（84次分配，+42次）
   堆栈:
   load_config+0x123 [0x555555555123]
   parse_json+0x45 [0x555555555245]
   main+0x67 [0x555555555067]
...

结束时间: 2023-06-01 10:40:00
总监控时间: 10.00分钟

===== 内存泄漏摘要 =====
总检测到的可能泄漏: 3
总泄漏内存: 15.7MB
最大单一泄漏: 10.5MB (load_config函数)

===== 建议修复位置 =====
1. load_config函数 (源文件: src/config.c:123)
2. create_buffer函数 (源文件: src/image.c:87)
3. init_cache函数 (源文件: src/cache.c:45)
```

### 系统调用分析

系统调用分析器用于跟踪和分析进程的系统调用模式，帮助识别系统调用开销和优化机会。

```bash
# 监控特定PID的系统调用
sudo python3 tools/syscall_analyzer.py [PID]

# 显示系统调用频率分布
sudo python3 tools/syscall_analyzer.py [PID] --histogram

# 按系统调用延迟排序
sudo python3 tools/syscall_analyzer.py [PID] --sort-latency

# 监控特定的系统调用组
sudo python3 tools/syscall_analyzer.py [PID] --groups io,net,proc
```

输出示例：
```
开始监控PID 1234 的系统调用...
监控持续时间: 10秒
开始时间: 2023-06-01 10:30:00

== 开始实时系统调用监控 ==
[10:30:01.234567] read(3, 0x7f8a1c2b3d40, 4096) = 4096, 延迟: 0.12μs
[10:30:01.234599] write(1, 0x7f8a1c2b4d40, 128) = 128, 延迟: 0.08μs
[10:30:01.235023] futex(0x7f8a1c2b5d40, FUTEX_WAIT, 1, NULL) = 0, 延迟: 1.23ms
...

结束时间: 2023-06-01 10:30:10
总监控时间: 10.00秒

===== 系统调用统计 =====
系统调用名        调用次数    总时间(ms)    平均时间(μs)    最大时间(μs)
-----------------------------------------------------------------------------
read              1,234      32.56         26.38           245.67
write             987        28.45         28.82           189.34
futex             567        345.67        609.65          2,345.78
poll              345        234.56        679.88          1,567.23
...

===== 系统调用组统计 =====
组名称        调用次数    总时间(ms)    比例%
-----------------------------------------
I/O           2,345      67.89         32.5
网络          1,456      89.45         42.8
进程管理      567        23.45         11.2
同步          786        27.89         13.5
...
```

### 缓存分析

缓存分析器用于监控CPU缓存的使用情况，识别缓存命中和未命中，帮助优化内存访问模式。

```bash
# 监控特定PID的缓存事件
sudo python3 tools/cache_analyzer.py [PID]

# 指定缓存类型（L1d, L1i, LLC）
sudo python3 tools/cache_analyzer.py [PID] --type L1d

# 显示热点函数的缓存行为
sudo python3 tools/cache_analyzer.py [PID] --hotspots
```

输出示例：
```
开始监控PID 1234 的缓存行为...
监控持续时间: 10秒
开始时间: 2023-06-01 10:30:00

== 缓存事件实时监控 ==
[10:30:01.234567] L1 数据缓存未命中: 0x7f8a1c2b3d40, 堆栈: process_data+0x123
[10:30:01.234599] LLC 缓存未命中: 0x7f8a1c2b4d40, 堆栈: read_config+0x45
...

结束时间: 2023-06-01 10:30:10
总监控时间: 10.00秒

===== 缓存性能摘要 =====
L1 数据缓存:
  总访问: 1,234,567
  命中: 1,123,456 (91.0%)
  未命中: 111,111 (9.0%)
  
L1 指令缓存:
  总访问: 567,890
  命中: 555,678 (97.8%)
  未命中: 12,212 (2.2%)
  
最后级缓存(LLC):
  总访问: 123,323
  命中: 98,765 (80.1%)
  未命中: 24,558 (19.9%)
  
===== 缓存未命中热点 =====
#1 process_data() - 23,456未命中 (21.1%)
#2 read_config() - 12,345未命中 (11.1%)
#3 parse_json() - 8,765未命中 (7.9%)
...
```

### 调度器分析

调度器分析器用于监控Linux调度器的行为，分析进程调度延迟和线程切换情况。

```bash
# 监控所有进程的调度事件
sudo python3 tools/scheduler_analyzer.py

# 监控特定PID的调度事件
sudo python3 tools/scheduler_analyzer.py [PID]

# 监控调度延迟
sudo python3 tools/scheduler_analyzer.py --latency

# 跟踪实时优先级任务的调度
sudo python3 tools/scheduler_analyzer.py --rt
```

输出示例：
```
开始监控调度器事件...
监控持续时间: 10秒
开始时间: 2023-06-01 10:30:00

== 实时调度事件监控 ==
[10:30:01.234567] 切入: 线程1234 (myapp), 优先级: 20, CPU: 0
[10:30:01.235678] 切出: 线程1234 (myapp), 运行时间: 1.11ms, 原因: SCHED_NORMAL
[10:30:01.235679] 切入: 线程5678 (nginx), 优先级: 10, CPU: 0
...

结束时间: 2023-06-01 10:30:10
总监控时间: 10.00秒

===== 调度统计 =====
进程名(PID)     优先级    切换次数    平均运行时间(ms)    最长运行时间(ms)    平均等待时间(ms)
---------------------------------------------------------------------------------------
myapp(1234)     20       345         1.23                12.34                2.34
nginx(5678)     10       234         0.87                5.67                 1.45
...

===== CPU负载统计 =====
CPU   平均负载%    最大负载%    进程切换/秒    上下文切换/秒    最常运行进程
--------------------------------------------------------------------------
0     45.67        78.90        123            456             myapp(1234)
1     34.56        67.89        98             345             nginx(5678)
...

===== 调度延迟分析 =====
线程名(TID)     平均唤醒延迟(μs)    最大唤醒延迟(μs)
--------------------------------------------------
myapp(1234)     67.89               345.67
nginx(5678)     45.67               234.56
...
```

### 文件系统分析

文件系统分析器用于监控文件系统操作，分析文件访问模式和性能瓶颈。

```bash
# 监控所有文件系统操作
sudo python3 tools/fs_analyzer.py

# 监控特定PID的文件系统操作
sudo python3 tools/fs_analyzer.py [PID]

# 只显示特定文件系统的操作
sudo python3 tools/fs_analyzer.py --fs ext4

# 跟踪特定目录的文件操作
sudo python3 tools/fs_analyzer.py --path /var/log
```

输出示例：
```
开始监控文件系统操作...
监控持续时间: 10秒
开始时间: 2023-06-01 10:30:00

== 实时文件系统操作监控 ==
[10:30:01.234567] 打开: /var/log/app.log (O_WRONLY|O_APPEND), PID: 1234 (myapp)
[10:30:01.234599] 写入: /var/log/app.log, 偏移量: 1024, 大小: 128B, 延迟: 0.23ms
[10:30:01.235678] 同步: /var/log/app.log, 延迟: 5.67ms
...

结束时间: 2023-06-01 10:30:10
总监控时间: 10.00秒

===== 文件系统操作统计 =====
操作类型    次数    总大小    平均延迟(ms)    最大延迟(ms)
---------------------------------------------------------
打开        345     -         0.12            1.23
读取        567     4.5MB     0.34            3.45
写入        789     7.8MB     0.56            8.90
同步        123     -         4.56            25.67
...

===== 活跃文件统计 =====
文件路径               操作次数    读取    写入    总I/O量
------------------------------------------------------------
/var/log/app.log       234        0B      2.3MB   2.3MB
/etc/config.json       45         256KB   0B      256KB
/tmp/cache.dat         78         1.2MB   0.5MB   1.7MB
...

===== 文件系统性能建议 =====
1. "/var/log/app.log" 有频繁的小型写入操作，考虑使用缓冲I/O
2. "同步" 操作占总延迟的67%，考虑减少fsync调用频率
3. 检测到多个进程并发访问 "/tmp/cache.dat"，可能导致争用
```

### 中断分析

中断分析器用于跟踪硬件和软件中断的处理情况，分析系统中断负载和延迟。

```bash
# 监控所有中断
sudo python3 tools/irq_analyzer.py

# 只监控硬中断
sudo python3 tools/irq_analyzer.py --hard

# 只监控软中断
sudo python3 tools/irq_analyzer.py --soft

# 监控特定IRQ号
sudo python3 tools/irq_analyzer.py --irq 19
```

输出示例：
```
开始监控中断事件...
监控持续时间: 10秒
开始时间: 2023-06-01 10:30:00

== 实时中断事件监控 ==
[10:30:01.234567] 硬中断: IRQ 19 (eth0), CPU: 0, 延迟: 23μs
[10:30:01.234599] 软中断: NET_RX, CPU: 1, 延迟: 45μs
...

结束时间: 2023-06-01 10:30:10
总监控时间: 10.00秒

===== 中断统计 =====
中断类型            CPU    次数    总时间(ms)    平均时间(μs)    最大时间(μs)
-------------------------------------------------------------------------------
IRQ 19 (eth0)       0      1,234   28.38         23.00           156.78
IRQ 23 (nvme0)      1      567     11.34         20.00           98.45
TIMER (软中断)      ALL    6,789   67.89         10.00           45.67
NET_RX (软中断)     1      2,345   105.53        45.00           234.56
...

===== CPU中断负载 =====
CPU    硬中断次数    软中断次数    中断处理总时间(ms)    CPU时间占比%
--------------------------------------------------------------------
0      1,567        3,456        45.67                 4.56
1      2,345        4,567        67.89                 6.79
2      1,234        2,345        34.56                 3.46
...

===== 中断处理时间分布 =====
< 10μs:  56.7%
10-50μs: 34.5%
50-100μs: 6.7%
100-500μs: 1.9%
500μs-1ms: 0.2%
> 1ms:   0.0%
```

### 页面错误分析

页面错误分析器用于监控内存页面错误和交换活动，帮助分析内存访问效率和识别内存压力。

```bash
# 监控所有进程的页面错误
sudo python3 tools/page_fault_analyzer.py

# 监控特定PID的页面错误
sudo python3 tools/page_fault_analyzer.py [PID]

# 只跟踪主要页面错误
sudo python3 tools/page_fault_analyzer.py --major

# 显示页面错误热点
sudo python3 tools/page_fault_analyzer.py --hotspots
```

输出示例：
```
开始监控页面错误事件...
监控持续时间: 10秒
开始时间: 2023-06-01 10:30:00

== 实时页面错误监控 ==
[10:30:01.234567] 次要页面错误: 地址 0x7f8a1c2b3d40, PID: 1234 (myapp)
[10:30:01.235678] 主要页面错误: 地址 0x7f8a1c2b4e50, PID: 1234 (myapp), 延迟: 5.67ms
...

结束时间: 2023-06-01 10:30:10
总监控时间: 10.00秒

===== 页面错误统计 =====
进程名(PID)     次要错误    主要错误    交换活动    总延迟(ms)
------------------------------------------------------------------
myapp(1234)     12,345      234         45          1,234.56
nginx(5678)     6,789       123         12          567.89
...

===== 页面错误热点 =====
地址范围               错误次数    错误类型    堆栈
--------------------------------------------------------
0x7f8a1c2b3000-4000    1,234      次要        mmap_region+0x123
0x7f8a1c2b5000-6000    567        主要        load_library+0x45
...

===== 内存访问模式分析 =====
进程名(PID)     连续访问%    随机访问%    内存热点
-----------------------------------------------------
myapp(1234)     78.9         21.1         0x7f8a1c2b3000
nginx(5678)     65.4         34.6         0x7f8a1c4e6000
...

===== 页面错误性能建议 =====
1. 进程 "myapp" 有大量次要页面错误，考虑预分配和内存初始化
2. 进程 "myapp" 在地址 0x7f8a1c2b5000 有频繁的主要页面错误，可能需要优化内存访问模式
3. 系统交换活动较少，内存压力较低
```

## 性能问题排查流程

下面是一个使用这些工具进行性能问题排查的建议流程：

1. **整体性能评估**：
   - 运行 `cpu_profiler.py` 监控系统总体CPU使用情况
   - 检查哪些进程或函数占用了大量CPU资源

2. **内存问题诊断**：
   - 如果怀疑有内存泄漏或内存使用过高的问题
   - 运行 `memory_analyzer.py --leaks` 或更专门的 `memory_leak_detector.py` 进行分析

3. **I/O性能分析**：
   - 如果系统响应缓慢，可能存在I/O瓶颈
   - 运行 `io_analyzer.py --files` 查看具体的文件操作和延迟

4. **网络问题排查**：
   - 对于网络应用，分析网络延迟和吞吐量
   - 运行 `network_profiler.py --verbose` 查看详细的网络连接和数据传输

5. **锁争用分析**：
   - 如果多线程应用程序响应缓慢或CPU使用率不足
   - 运行 `lock_analyzer.py` 识别可能的锁争用瓶颈

6. **持续监控**：
   - 使用较长的监控时间（如 `-d 3600` 监控一小时）
   - 将输出重定向到文件以便后续分析：`sudo python3 tools/cpu_profiler.py > cpu_profile.log`

## 性能优化建议

根据工具的分析结果，常见的优化措施包括：

- **CPU密集型问题**：
  - 优化热点函数的算法复杂度
  - 考虑并行处理或多线程
  - 减少不必要的计算

- **内存问题**：
  - 修复内存泄漏点
  - 减少不必要的内存分配和复制
  - 考虑使用内存池或对象复用

- **I/O瓶颈**：
  - 使用异步I/O或缓冲I/O
  - 减少小文件操作，合并I/O请求
  - 考虑使用更快的存储设备

- **网络问题**：
  - 减少不必要的网络往返
  - 使用连接池和长连接
  - 考虑压缩数据或优化协议

- **锁争用问题**：
  - 减小锁的粒度，分解全局锁
  - 使用读写锁代替互斥锁（适用于读多写少的场景）
  - 考虑无锁数据结构或原子操作
  - 减少临界区代码执行时间

## 高级用法

这些工具支持多种高级用法，您可以通过组合不同的参数来满足特定需求：

```bash
# 同时监控CPU和锁争用
sudo python3 tools/cpu_profiler.py [PID] > cpu.log &
sudo python3 tools/lock_analyzer.py [PID] > lock.log &

# 创建系统性能基准测试
for i in {1..5}; do
  sudo python3 tools/cpu_profiler.py -d 60 > cpu_test_$i.log
  sleep 10
done

# 比较优化前后的性能
sudo python3 tools/lock_analyzer.py [PID] -d 60 > locks_before.log
# 应用优化措施
sudo python3 tools/lock_analyzer.py [PID] -d 60 > locks_after.log
diff locks_before.log locks_after.log
```

## 附加资源

- [Linux性能调优指南](https://www.brendangregg.com/linuxperf.html)
- [eBPF参考文档](https://ebpf.io/what-is-ebpf/)
- [BCC工具文档](https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md)

## 故障排除

如果您在运行工具时遇到问题，可以尝试以下解决方案：

1. **"Failed to load BPF program"**：
   - 确保已安装对应的内核头文件：`sudo apt-get install linux-headers-$(uname -r)`
   - 检查您的内核版本是否支持eBPF：`uname -r`（需要4.9+）

2. **权限错误**：
   - 确保使用sudo或root权限运行脚本

3. **无数据输出**：
   - 确认指定的PID是否正确且进程是否活跃
   - 尝试增加监控时间：`-d 30`（增加到30秒）

4. **"Unknown symbol"错误**：
   - 可能是内核版本差异导致，检查脚本中使用的内核函数是否在您的系统上可用

## 联系与支持

如果您有任何问题或建议，请通过以下方式联系我们：

- GitHub Issues: [提交问题](https://github.com/whosneo/ebpf-performance-analyzer/issues)
- 邮件: whosneo@qq.com 