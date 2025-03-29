#!/usr/bin/env python3
# I/O分析器 - 使用eBPF监控文件系统和磁盘I/O性能
#
# 这个程序跟踪系统的I/O操作，分析I/O延迟、吞吐量和模式
# 以帮助诊断磁盘和文件系统相关的性能问题。

import sys
import time
import argparse
from bcc import BPF
from datetime import datetime, timedelta
import ctypes as ct
from collections import defaultdict, namedtuple

# eBPF程序代码
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/blkdev.h>
#include <linux/sched.h>
#include <linux/fs.h>

// 定义I/O操作类型
enum io_type {
    IO_READ,            // 读操作
    IO_WRITE,           // 写操作
    IO_SYNC,            // 同步操作
    IO_OPEN,            // 打开文件
    IO_CLOSE,           // 关闭文件
    IO_FSYNC            // 文件同步
};

// I/O请求结构
struct io_req_t {
    u64 ts;                   // 时间戳
    u32 pid;                  // 进程ID
    u64 bytes;                // 字节数
    enum io_type type;        // I/O类型
    char comm[TASK_COMM_LEN]; // 进程名
    char filename[64];        // 文件名
};

// I/O完成结构
struct io_completion_t {
    u64 ts;                   // 时间戳
    u32 pid;                  // 进程ID
    u64 bytes;                // 字节数
    u64 delta_us;             // 延迟(微秒)
    enum io_type type;        // I/O类型
    char comm[TASK_COMM_LEN]; // 进程名
    char filename[64];        // 文件名
};

// 性能输出缓冲区
BPF_PERF_OUTPUT(io_events);

// 跟踪I/O请求
BPF_HASH(io_start, struct io_req_t, u64);

// I/O统计信息
BPF_HASH(read_count, u32);
BPF_HASH(write_count, u32);
BPF_HASH(sync_count, u32);
BPF_HASH(read_bytes, u32);
BPF_HASH(write_bytes, u32);

// 按进程统计
BPF_HASH(proc_read_bytes, u32);
BPF_HASH(proc_write_bytes, u32);
BPF_HASH(proc_read_count, u32);
BPF_HASH(proc_write_count, u32);

// 按文件统计
BPF_HASH(file_read_bytes, char[64]);
BPF_HASH(file_write_bytes, char[64]);
BPF_HASH(file_read_count, char[64]);
BPF_HASH(file_write_count, char[64]);

// 延迟分布
BPF_HISTOGRAM(read_lat_us, int);
BPF_HISTOGRAM(write_lat_us, int);
BPF_HISTOGRAM(sync_lat_us, int);

// 跟踪读操作
int trace_read_entry(struct pt_regs *ctx, struct file *file, char __user *buf, size_t count) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    u32 tid = id;
    
    // 检查目标PID
    u32 target_pid = PID_FILTER;
    if (target_pid > 0 && pid != target_pid) {
        return 0;
    }

    // 创建I/O请求信息
    struct io_req_t req = {};
    req.ts = bpf_ktime_get_ns();
    req.pid = pid;
    req.bytes = count;
    req.type = IO_READ;
    
    bpf_get_current_comm(&req.comm, sizeof(req.comm));
    
    // 提取文件名
    if (file && file->f_path.dentry) {
        bpf_probe_read_kernel(&req.filename, sizeof(req.filename), 
                        file->f_path.dentry->d_name.name);
    }
    
    // 储存开始时间
    u64 ts = req.ts;
    io_start.update(&req, &ts);
    
    // 更新统计
    u64 *read_count_val = read_count.lookup(&pid);
    if (read_count_val) {
        (*read_count_val)++;
    } else {
        u64 val = 1;
        read_count.update(&pid, &val);
    }
    
    u64 *read_bytes_val = read_bytes.lookup(&pid);
    if (read_bytes_val) {
        (*read_bytes_val) += count;
    } else {
        read_bytes.update(&pid, &count);
    }
    
    // 按进程统计
    u64 *proc_bytes = proc_read_bytes.lookup(&pid);
    if (proc_bytes) {
        (*proc_bytes) += count;
    } else {
        proc_read_bytes.update(&pid, &count);
    }
    
    u64 *proc_count = proc_read_count.lookup(&pid);
    if (proc_count) {
        (*proc_count)++;
    } else {
        u64 val = 1;
        proc_read_count.update(&pid, &val);
    }
    
    // 按文件统计
    u64 *file_bytes = file_read_bytes.lookup(&req.filename);
    if (file_bytes) {
        (*file_bytes) += count;
    } else {
        file_read_bytes.update(&req.filename, &count);
    }
    
    u64 *file_count = file_read_count.lookup(&req.filename);
    if (file_count) {
        (*file_count)++;
    } else {
        u64 val = 1;
        file_read_count.update(&req.filename, &val);
    }
    
    return 0;
}

// 跟踪读操作完成
int trace_read_return(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    u32 tid = id;
    
    // 检查目标PID
    u32 target_pid = PID_FILTER;
    if (target_pid > 0 && pid != target_pid) {
        return 0;
    }
    
    // 获取返回值
    ssize_t ret = PT_REGS_RC(ctx);
    if (ret < 0) {
        return 0;  // 读取错误
    }
    
    struct io_req_t key = {};
    key.pid = pid;
    key.type = IO_READ;
    bpf_get_current_comm(&key.comm, sizeof(key.comm));
    
    // 查找开始时间戳
    u64 *tsp = io_start.lookup(&key);
    if (tsp == 0) {
        return 0;  // 未找到对应的开始请求
    }
    
    // 计算延迟
    u64 now = bpf_ktime_get_ns();
    u64 delta_us = (now - *tsp) / 1000;
    
    // 创建完成事件
    struct io_completion_t event = {};
    event.ts = now;
    event.pid = pid;
    event.bytes = key.bytes;
    event.delta_us = delta_us;
    event.type = IO_READ;
    
    bpf_probe_read_kernel(&event.comm, sizeof(event.comm), key.comm);
    bpf_probe_read_kernel(&event.filename, sizeof(event.filename), key.filename);
    
    // 输出事件
    io_events.perf_submit(ctx, &event, sizeof(event));
    
    // 更新延迟分布
    int lat_key = bpf_log2l(delta_us);
    read_lat_us.increment(lat_key);
    
    // 删除开始记录
    io_start.delete(&key);
    
    return 0;
}

// 跟踪写操作
int trace_write_entry(struct pt_regs *ctx, struct file *file, const char __user *buf, size_t count) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    u32 tid = id;
    
    // 检查目标PID
    u32 target_pid = PID_FILTER;
    if (target_pid > 0 && pid != target_pid) {
        return 0;
    }
    
    // 创建I/O请求信息
    struct io_req_t req = {};
    req.ts = bpf_ktime_get_ns();
    req.pid = pid;
    req.bytes = count;
    req.type = IO_WRITE;
    
    bpf_get_current_comm(&req.comm, sizeof(req.comm));
    
    // 提取文件名
    if (file && file->f_path.dentry) {
        bpf_probe_read_kernel(&req.filename, sizeof(req.filename), 
                        file->f_path.dentry->d_name.name);
    }
    
    // 储存开始时间
    u64 ts = req.ts;
    io_start.update(&req, &ts);
    
    // 更新统计
    u64 *write_count_val = write_count.lookup(&pid);
    if (write_count_val) {
        (*write_count_val)++;
    } else {
        u64 val = 1;
        write_count.update(&pid, &val);
    }
    
    u64 *write_bytes_val = write_bytes.lookup(&pid);
    if (write_bytes_val) {
        (*write_bytes_val) += count;
    } else {
        write_bytes.update(&pid, &count);
    }
    
    // 按进程统计
    u64 *proc_bytes = proc_write_bytes.lookup(&pid);
    if (proc_bytes) {
        (*proc_bytes) += count;
    } else {
        proc_write_bytes.update(&pid, &count);
    }
    
    u64 *proc_count = proc_write_count.lookup(&pid);
    if (proc_count) {
        (*proc_count)++;
    } else {
        u64 val = 1;
        proc_write_count.update(&pid, &val);
    }
    
    // 按文件统计
    u64 *file_bytes = file_write_bytes.lookup(&req.filename);
    if (file_bytes) {
        (*file_bytes) += count;
    } else {
        file_write_bytes.update(&req.filename, &count);
    }
    
    u64 *file_count = file_write_count.lookup(&req.filename);
    if (file_count) {
        (*file_count)++;
    } else {
        u64 val = 1;
        file_write_count.update(&req.filename, &val);
    }
    
    return 0;
}

// 跟踪写操作完成
int trace_write_return(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    u32 tid = id;
    
    // 检查目标PID
    u32 target_pid = PID_FILTER;
    if (target_pid > 0 && pid != target_pid) {
        return 0;
    }
    
    // 获取返回值
    ssize_t ret = PT_REGS_RC(ctx);
    if (ret < 0) {
        return 0;  // 写入错误
    }
    
    struct io_req_t key = {};
    key.pid = pid;
    key.type = IO_WRITE;
    bpf_get_current_comm(&key.comm, sizeof(key.comm));
    
    // 查找开始时间戳
    u64 *tsp = io_start.lookup(&key);
    if (tsp == 0) {
        return 0;  // 未找到对应的开始请求
    }
    
    // 计算延迟
    u64 now = bpf_ktime_get_ns();
    u64 delta_us = (now - *tsp) / 1000;
    
    // 创建完成事件
    struct io_completion_t event = {};
    event.ts = now;
    event.pid = pid;
    event.delta_us = delta_us;
    event.type = IO_WRITE;
    
    bpf_probe_read_kernel(&event.comm, sizeof(event.comm), key.comm);
    bpf_probe_read_kernel(&event.filename, sizeof(event.filename), key.filename);
    
    // 输出事件
    io_events.perf_submit(ctx, &event, sizeof(event));
    
    // 更新延迟分布
    int lat_key = bpf_log2l(delta_us);
    write_lat_us.increment(lat_key);
    
    // 删除开始记录
    io_start.delete(&key);
    
    return 0;
}

// 跟踪fsync操作
int trace_fsync_entry(struct pt_regs *ctx, struct file *file) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    u32 tid = id;
    
    // 检查目标PID
    u32 target_pid = PID_FILTER;
    if (target_pid > 0 && pid != target_pid) {
        return 0;
    }
    
    // 创建I/O请求信息
    struct io_req_t req = {};
    req.ts = bpf_ktime_get_ns();
    req.pid = pid;
    req.type = IO_FSYNC;
    
    bpf_get_current_comm(&req.comm, sizeof(req.comm));
    
    // 提取文件名
    if (file && file->f_path.dentry) {
        bpf_probe_read_kernel(&req.filename, sizeof(req.filename), 
                        file->f_path.dentry->d_name.name);
    }
    
    // 储存开始时间
    u64 ts = req.ts;
    io_start.update(&req, &ts);
    
    // 更新统计
    u64 *sync_count_val = sync_count.lookup(&pid);
    if (sync_count_val) {
        (*sync_count_val)++;
    } else {
        u64 val = 1;
        sync_count.update(&pid, &val);
    }
    
    return 0;
}

// 跟踪fsync操作完成
int trace_fsync_return(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    u32 tid = id;
    
    // 检查目标PID
    u32 target_pid = PID_FILTER;
    if (target_pid > 0 && pid != target_pid) {
        return 0;
    }
    
    // 获取返回值
    int ret = PT_REGS_RC(ctx);
    if (ret < 0) {
        return 0;  // fsync错误
    }
    
    struct io_req_t key = {};
    key.pid = pid;
    key.type = IO_FSYNC;
    bpf_get_current_comm(&key.comm, sizeof(key.comm));
    
    // 查找开始时间戳
    u64 *tsp = io_start.lookup(&key);
    if (tsp == 0) {
        return 0;  // 未找到对应的开始请求
    }
    
    // 计算延迟
    u64 now = bpf_ktime_get_ns();
    u64 delta_us = (now - *tsp) / 1000;
    
    // 创建完成事件
    struct io_completion_t event = {};
    event.ts = now;
    event.pid = pid;
    event.delta_us = delta_us;
    event.type = IO_FSYNC;
    
    bpf_probe_read_kernel(&event.comm, sizeof(event.comm), key.comm);
    bpf_probe_read_kernel(&event.filename, sizeof(event.filename), key.filename);
    
    // 输出事件
    io_events.perf_submit(ctx, &event, sizeof(event));
    
    // 更新延迟分布
    int lat_key = bpf_log2l(delta_us);
    sync_lat_us.increment(lat_key);
    
    // 删除开始记录
    io_start.delete(&key);
    
    return 0;
}

// 跟踪文件打开
int trace_open(struct pt_regs *ctx, const char __user *filename, int flags) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    
    // 检查目标PID
    u32 target_pid = PID_FILTER;
    if (target_pid > 0 && pid != target_pid) {
        return 0;
    }
    
    // 创建I/O请求信息
    struct io_req_t req = {};
    req.ts = bpf_ktime_get_ns();
    req.pid = pid;
    req.type = IO_OPEN;
    
    bpf_get_current_comm(&req.comm, sizeof(req.comm));
    
    // 提取文件名
    bpf_probe_read_user(&req.filename, sizeof(req.filename), filename);
    
    // 创建完成事件
    struct io_completion_t event = {};
    event.ts = req.ts;
    event.pid = pid;
    event.type = IO_OPEN;
    
    bpf_probe_read_kernel(&event.comm, sizeof(event.comm), req.comm);
    bpf_probe_read_kernel(&event.filename, sizeof(event.filename), req.filename);
    
    // 输出事件
    io_events.perf_submit(ctx, &event, sizeof(event));
    
    return 0;
}
"""

# I/O类型常量
IO_READ = 0
IO_WRITE = 1
IO_SYNC = 2
IO_OPEN = 3
IO_CLOSE = 4
IO_FSYNC = 5

# I/O类型名称
IO_TYPE_NAMES = {
    IO_READ: "读取",
    IO_WRITE: "写入",
    IO_SYNC: "同步",
    IO_OPEN: "打开",
    IO_CLOSE: "关闭",
    IO_FSYNC: "文件同步"
}

# I/O完成事件结构
class IOCompletion(ct.Structure):
    _fields_ = [
        ("ts", ct.c_ulonglong),
        ("pid", ct.c_uint),
        ("bytes", ct.c_ulonglong),
        ("delta_us", ct.c_ulonglong),
        ("type", ct.c_uint),
        ("comm", ct.c_char * 16),
        ("filename", ct.c_char * 64)
    ]

def human_readable_size(size_bytes):
    """将字节数转换为人类可读的大小表示"""
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.2f} KB"
    elif size_bytes < 1024 * 1024 * 1024:
        return f"{size_bytes / (1024 * 1024):.2f} MB"
    else:
        return f"{size_bytes / (1024 * 1024 * 1024):.2f} GB"

def parse_args():
    """解析命令行参数"""
    parser = argparse.ArgumentParser(
        description="I/O分析工具 - 监控文件系统和磁盘I/O性能")
    parser.add_argument("pid", type=int, nargs="?", default=0,
        help="要监控的进程ID (0表示所有进程)")
    parser.add_argument("-d", "--duration", type=int, default=10,
        help="监控持续时间(秒)")
    parser.add_argument("-t", "--top", type=int, default=10,
        help="显示最活跃的前N个进程/文件")
    parser.add_argument("-l", "--latency", action="store_true",
        help="显示I/O延迟分布")
    parser.add_argument("-f", "--files", action="store_true",
        help="按文件名统计I/O")
    parser.add_argument("-p", "--processes", action="store_true", 
        help="按进程统计I/O")
    parser.add_argument("-a", "--all-events", action="store_true",
        help="显示所有I/O事件")
    parser.add_argument("-r", "--read", action="store_true",
        help="仅跟踪读操作")
    parser.add_argument("-w", "--write", action="store_true",
        help="仅跟踪写操作")
    parser.add_argument("-s", "--sync", action="store_true",
        help="仅跟踪同步操作")
    return parser.parse_args()

def compute_stats(args, b):
    """计算I/O统计信息"""
    stats = {}
    
    # 进程I/O统计
    if args.processes:
        stats["processes"] = []
        
        # 读取统计
        read_counts = {}
        read_bytes = {}
        for k, v in b["proc_read_count"].items():
            read_counts[k.value] = v.value
        for k, v in b["proc_read_bytes"].items():
            read_bytes[k.value] = v.value
            
        # 写入统计
        write_counts = {}
        write_bytes = {}
        for k, v in b["proc_write_count"].items():
            write_counts[k.value] = v.value
        for k, v in b["proc_write_bytes"].items():
            write_bytes[k.value] = v.value
            
        # 合并结果
        all_pids = set(list(read_counts.keys()) + list(write_counts.keys()))
        for pid in all_pids:
            r_count = read_counts.get(pid, 0)
            r_bytes = read_bytes.get(pid, 0)
            w_count = write_counts.get(pid, 0)
            w_bytes = write_bytes.get(pid, 0)
            stats["processes"].append({
                "pid": pid,
                "read_count": r_count,
                "read_bytes": r_bytes,
                "write_count": w_count,
                "write_bytes": w_bytes,
                "total_count": r_count + w_count,
                "total_bytes": r_bytes + w_bytes
            })
            
        # 按总I/O大小排序
        stats["processes"].sort(key=lambda x: x["total_bytes"], reverse=True)
    
    # 文件I/O统计
    if args.files:
        stats["files"] = []
        
        # 读取统计
        read_counts = {}
        read_bytes = {}
        for k, v in b["file_read_count"].items():
            filename = k.value.decode('utf-8', 'replace')
            read_counts[filename] = v.value
        for k, v in b["file_read_bytes"].items():
            filename = k.value.decode('utf-8', 'replace')
            read_bytes[filename] = v.value
            
        # 写入统计
        write_counts = {}
        write_bytes = {}
        for k, v in b["file_write_count"].items():
            filename = k.value.decode('utf-8', 'replace')
            write_counts[filename] = v.value
        for k, v in b["file_write_bytes"].items():
            filename = k.value.decode('utf-8', 'replace')
            write_bytes[filename] = v.value
            
        # 合并结果
        all_files = set(list(read_counts.keys()) + list(write_counts.keys()))
        for filename in all_files:
            if not filename:  # 跳过空文件名
                continue
                
            r_count = read_counts.get(filename, 0)
            r_bytes = read_bytes.get(filename, 0)
            w_count = write_counts.get(filename, 0)
            w_bytes = write_bytes.get(filename, 0)
            stats["files"].append({
                "filename": filename,
                "read_count": r_count,
                "read_bytes": r_bytes,
                "write_count": w_count,
                "write_bytes": w_bytes,
                "total_count": r_count + w_count,
                "total_bytes": r_bytes + w_bytes
            })
            
        # 按总I/O大小排序
        stats["files"].sort(key=lambda x: x["total_bytes"], reverse=True)
    
    # 延迟分布
    if args.latency:
        stats["latency"] = {
            "read": b["read_lat_us"],
            "write": b["write_lat_us"],
            "sync": b["sync_lat_us"]
        }
        
    return stats

def print_io_event(event):
    """打印单个I/O事件"""
    ts = datetime.fromtimestamp(event.ts / 1000000000).strftime('%H:%M:%S.%f')
    type_name = IO_TYPE_NAMES.get(event.type, f"未知({event.type})")
    comm = event.comm.decode('utf-8', 'replace')
    filename = event.filename.decode('utf-8', 'replace')
    
    if event.type in [IO_READ, IO_WRITE]:
        size = human_readable_size(event.bytes)
        latency = event.delta_us / 1000  # 转换为毫秒
        print(f"[{ts}] 进程: {comm}({event.pid}), 操作: {type_name}, "
              f"文件: {filename}, 大小: {size}, 延迟: {latency:.3f}毫秒")
    elif event.type in [IO_FSYNC, IO_SYNC]:
        latency = event.delta_us / 1000  # 转换为毫秒
        print(f"[{ts}] 进程: {comm}({event.pid}), 操作: {type_name}, "
              f"文件: {filename}, 延迟: {latency:.3f}毫秒")
    else:
        print(f"[{ts}] 进程: {comm}({event.pid}), 操作: {type_name}, "
              f"文件: {filename}")

def print_latency_distribution(dist, dist_type):
    """打印延迟分布"""
    print(f"\n{dist_type}操作延迟分布:")
    print("-" * 60)
    dist.print_log2_hist("延迟(微秒)")

def main():
    args = parse_args()
    
    # 确定要跟踪的操作
    if not (args.read or args.write or args.sync):
        # 默认跟踪所有操作
        args.read = True
        args.write = True
        args.sync = True
    
    # 创建eBPF程序
    bpf_program = bpf_text.replace('PID_FILTER', str(args.pid))
    b = BPF(text=bpf_program)
    
    # 附加到内核函数
    if args.read:
        b.attach_kprobe(event="vfs_read", fn_name="trace_read_entry")
        b.attach_kretprobe(event="vfs_read", fn_name="trace_read_return")
    
    if args.write:
        b.attach_kprobe(event="vfs_write", fn_name="trace_write_entry")
        b.attach_kretprobe(event="vfs_write", fn_name="trace_write_return")
    
    if args.sync:
        b.attach_kprobe(event="vfs_fsync", fn_name="trace_fsync_entry")
        b.attach_kretprobe(event="vfs_fsync", fn_name="trace_fsync_return")
        
        # 也可以附加到open函数来跟踪文件打开操作
        b.attach_kprobe(event="do_sys_open", fn_name="trace_open")
    
    # I/O事件计数
    event_count = 0
    
    # 定义事件回调函数
    def handle_io_event(cpu, data, size):
        nonlocal event_count
        event = ct.cast(data, ct.POINTER(IOCompletion)).contents
        
        if args.all_events:
            print_io_event(event)
            
        event_count += 1
    
    # 注册回调
    b["io_events"].open_perf_buffer(handle_io_event)
    
    # 监控指定时间
    start_time = datetime.now()
    print(f"开始监控{'PID ' + str(args.pid) if args.pid else '所有进程'} 的I/O活动...")
    print(f"持续时间: {args.duration}秒")
    print(f"监控的操作: {'读取 ' if args.read else ''}{'写入 ' if args.write else ''}{'同步 ' if args.sync else ''}")
    print(f"开始时间: {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
    
    # 周期性更新
    update_interval = min(args.duration, 1)  # 最多1秒更新一次
    seconds_passed = 0
    
    try:
        while seconds_passed < args.duration:
            b.perf_buffer_poll(timeout=1000)
            
            now = datetime.now()
            elapsed = (now - start_time).total_seconds()
            if elapsed >= seconds_passed + update_interval:
                seconds_passed = int(elapsed)
                
                # 如果显示所有事件，则不打印进度
                if not args.all_events:
                    print(f"已监控 {seconds_passed} 秒... 收集了 {event_count} 个I/O事件")
                    
    except KeyboardInterrupt:
        print("监控被用户中断")
    
    end_time = datetime.now()
    print(f"\n结束时间: {end_time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"总监控时间: {(end_time - start_time).total_seconds():.2f}秒")
    print(f"总计捕获了 {event_count} 个I/O事件")
    
    # 计算统计信息
    stats = compute_stats(args, b)
    
    # 打印进程I/O统计
    if args.processes and "processes" in stats:
        print("\n----- 进程I/O统计 (按总I/O排序) -----")
        print("%-6s %-16s %-10s %-10s %-10s %-10s %-10s" % (
            "PID", "进程名", "读取次数", "读取大小", "写入次数", "写入大小", "总I/O大小"))
        
        # 获取进程名称
        processes = stats["processes"][:args.top]
        for proc in processes:
            pid = proc["pid"]
            try:
                with open(f"/proc/{pid}/comm", "r") as f:
                    comm = f.read().strip()
            except:
                comm = f"[未知]"
                
            print("%-6d %-16s %-10d %-10s %-10d %-10s %-10s" % (
                pid,
                comm,
                proc["read_count"],
                human_readable_size(proc["read_bytes"]),
                proc["write_count"],
                human_readable_size(proc["write_bytes"]),
                human_readable_size(proc["total_bytes"])
            ))
    
    # 打印文件I/O统计
    if args.files and "files" in stats:
        print("\n----- 文件I/O统计 (按总I/O排序) -----")
        print("%-30s %-10s %-10s %-10s %-10s %-10s" % (
            "文件名", "读取次数", "读取大小", "写入次数", "写入大小", "总I/O大小"))
        
        files = stats["files"][:args.top]
        for file in files:
            filename = file["filename"]
            if len(filename) > 30:
                # 截断长文件名
                filename = "..." + filename[-27:]
                
            print("%-30s %-10d %-10s %-10d %-10s %-10s" % (
                filename,
                file["read_count"],
                human_readable_size(file["read_bytes"]),
                file["write_count"],
                human_readable_size(file["write_bytes"]),
                human_readable_size(file["total_bytes"])
            ))
    
    # 打印延迟分布
    if args.latency and "latency" in stats:
        if args.read:
            print_latency_distribution(stats["latency"]["read"], "读取")
        if args.write:
            print_latency_distribution(stats["latency"]["write"], "写入")
        if args.sync:
            print_latency_distribution(stats["latency"]["sync"], "同步")
    
    # 清理资源
    b.cleanup()

if __name__ == "__main__":
    main() 