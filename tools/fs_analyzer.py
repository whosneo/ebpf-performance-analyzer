#!/usr/bin/env python3
# 文件系统分析器 - 使用eBPF监控文件系统操作
#
# 这个程序跟踪文件系统操作，包括读写、打开关闭、同步等，
# 提供详细的文件I/O性能分析。

import sys
import time
import argparse
from bcc import BPF
from datetime import datetime
import ctypes as ct
import os
import logging

# 导入公共模块
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
from src.ebpf_common import BaseAnalyzer, validate_args, setup_logging, run_monitoring_loop

# eBPF程序代码
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/dcache.h>

// 文件操作类型
enum {
    OP_READ = 0,
    OP_WRITE,
    OP_OPEN,
    OP_CLOSE,
    OP_FSYNC,
    OP_STAT,
    OP_LSEEK
};

// 文件操作信息结构
struct file_op_t {
    u64 ts;              // 操作时间戳
    u32 pid;             // 进程ID
    enum op_type {
        READ = 0,
        WRITE,
        OPEN,
        CLOSE,
        FSYNC,
        STAT,
        LSEEK
    } op;                // 操作类型
    u64 bytes;           // 操作的字节数
    u64 latency;         // 操作延迟
    u8 failed;           // 操作是否失败
    char comm[TASK_COMM_LEN]; // 进程名称
    char filename[128];  // 文件名
};

// 存储文件操作请求的开始时间
BPF_HASH(start_time, u64, u64);

// 用于将数据传递到用户空间
BPF_PERF_OUTPUT(file_ops_events);

// 跟踪read系统调用
int trace_read_entry(struct pt_regs *ctx, int fd, void *buf, size_t count) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    
    // 检查目标PID
    u32 target_pid = PID_FILTER;
    if (target_pid > 0 && pid != target_pid) {
        return 0;
    }
    
    // 保存开始时间
    u64 ts = bpf_ktime_get_ns();
    u64 key = (id << 8) | OP_READ;
    start_time.update(&key, &ts);
    
    return 0;
}

int trace_read_return(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    u32 tid = id & 0xFFFFFFFF;
    
    // 检查目标PID
    u32 target_pid = PID_FILTER;
    if (target_pid > 0 && pid != target_pid) {
        return 0;
    }
    
    // 获取开始时间
    u64 key = (id << 8) | OP_READ;
    u64 *start_ts = start_time.lookup(&key);
    if (start_ts == 0) {
        return 0;  // 找不到开始时间
    }
    
    // 计算延迟
    u64 ts = bpf_ktime_get_ns();
    u64 latency = ts - *start_ts;
    
    // 获取返回值(读取的字节数)
    ssize_t bytes = PT_REGS_RC(ctx);
    
    // 创建文件操作事件
    struct file_op_t event = {};
    event.ts = ts;
    event.pid = pid;
    event.op = READ;
    event.bytes = bytes > 0 ? bytes : 0;
    event.latency = latency;
    event.failed = bytes < 0 ? 1 : 0;
    
    // 获取进程名称
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    // 尝试获取文件名
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (task) {
        struct files_struct *files = task->files;
        if (files) {
            struct fdtable *fdt = files->fdt;
            if (fdt) {
                struct file **fd_array = fdt->fd;
                if (fd_array) {
                    struct file *file = fd_array[0]; // 假设是标准输入
                    if (file) {
                        struct dentry *dentry = file->f_path.dentry;
                        if (dentry) {
                            bpf_probe_read_kernel_str(&event.filename, sizeof(event.filename), dentry->d_name.name);
                        }
                    }
                }
            }
        }
    }
    
    // 发送事件
    file_ops_events.perf_submit(ctx, &event, sizeof(event));
    
    // 清理
    start_time.delete(&key);
    
    return 0;
}

// 跟踪write系统调用
int trace_write_entry(struct pt_regs *ctx, int fd, const void *buf, size_t count) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    
    // 检查目标PID
    u32 target_pid = PID_FILTER;
    if (target_pid > 0 && pid != target_pid) {
        return 0;
    }
    
    // 保存开始时间
    u64 ts = bpf_ktime_get_ns();
    u64 key = (id << 8) | OP_WRITE;
    start_time.update(&key, &ts);
    
    return 0;
}

int trace_write_return(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    
    // 检查目标PID
    u32 target_pid = PID_FILTER;
    if (target_pid > 0 && pid != target_pid) {
        return 0;
    }
    
    // 获取开始时间
    u64 key = (id << 8) | OP_WRITE;
    u64 *start_ts = start_time.lookup(&key);
    if (start_ts == 0) {
        return 0;  // 找不到开始时间
    }
    
    // 计算延迟
    u64 ts = bpf_ktime_get_ns();
    u64 latency = ts - *start_ts;
    
    // 获取返回值(写入的字节数)
    ssize_t bytes = PT_REGS_RC(ctx);
    
    // 创建文件操作事件
    struct file_op_t event = {};
    event.ts = ts;
    event.pid = pid;
    event.op = WRITE;
    event.bytes = bytes > 0 ? bytes : 0;
    event.latency = latency;
    event.failed = bytes < 0 ? 1 : 0;
    
    // 获取进程名称
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    // 发送事件
    file_ops_events.perf_submit(ctx, &event, sizeof(event));
    
    // 清理
    start_time.delete(&key);
    
    return 0;
}

// 跟踪open系统调用
int trace_open_entry(struct pt_regs *ctx, const char *filename, int flags) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    
    // 检查目标PID
    u32 target_pid = PID_FILTER;
    if (target_pid > 0 && pid != target_pid) {
        return 0;
    }
    
    // 保存开始时间
    u64 ts = bpf_ktime_get_ns();
    u64 key = (id << 8) | OP_OPEN;
    start_time.update(&key, &ts);
    
    return 0;
}

int trace_open_return(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    
    // 检查目标PID
    u32 target_pid = PID_FILTER;
    if (target_pid > 0 && pid != target_pid) {
        return 0;
    }
    
    // 获取开始时间
    u64 key = (id << 8) | OP_OPEN;
    u64 *start_ts = start_time.lookup(&key);
    if (start_ts == 0) {
        return 0;  // 找不到开始时间
    }
    
    // 计算延迟
    u64 ts = bpf_ktime_get_ns();
    u64 latency = ts - *start_ts;
    
    // 获取返回值(文件描述符)
    int fd = PT_REGS_RC(ctx);
    
    // 创建文件操作事件
    struct file_op_t event = {};
    event.ts = ts;
    event.pid = pid;
    event.op = OPEN;
    event.bytes = 0;  // 打开文件没有读写字节数
    event.latency = latency;
    event.failed = fd < 0 ? 1 : 0;
    
    // 获取进程名称
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    // 发送事件
    file_ops_events.perf_submit(ctx, &event, sizeof(event));
    
    // 清理
    start_time.delete(&key);
    
    return 0;
}

// 跟踪close系统调用
int trace_close_entry(struct pt_regs *ctx, int fd) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    
    // 检查目标PID
    u32 target_pid = PID_FILTER;
    if (target_pid > 0 && pid != target_pid) {
        return 0;
    }
    
    // 保存开始时间
    u64 ts = bpf_ktime_get_ns();
    u64 key = (id << 8) | OP_CLOSE;
    start_time.update(&key, &ts);
    
    return 0;
}

int trace_close_return(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    
    // 检查目标PID
    u32 target_pid = PID_FILTER;
    if (target_pid > 0 && pid != target_pid) {
        return 0;
    }
    
    // 获取开始时间
    u64 key = (id << 8) | OP_CLOSE;
    u64 *start_ts = start_time.lookup(&key);
    if (start_ts == 0) {
        return 0;  // 找不到开始时间
    }
    
    // 计算延迟
    u64 ts = bpf_ktime_get_ns();
    u64 latency = ts - *start_ts;
    
    // 获取返回值
    int ret = PT_REGS_RC(ctx);
    
    // 创建文件操作事件
    struct file_op_t event = {};
    event.ts = ts;
    event.pid = pid;
    event.op = CLOSE;
    event.bytes = 0;  // 关闭文件没有读写字节数
    event.latency = latency;
    event.failed = ret < 0 ? 1 : 0;
    
    // 获取进程名称
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    // 发送事件
    file_ops_events.perf_submit(ctx, &event, sizeof(event));
    
    // 清理
    start_time.delete(&key);
    
    return 0;
}

// 跟踪fsync系统调用
int trace_fsync_entry(struct pt_regs *ctx, int fd) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    
    // 检查目标PID
    u32 target_pid = PID_FILTER;
    if (target_pid > 0 && pid != target_pid) {
        return 0;
    }
    
    // 保存开始时间
    u64 ts = bpf_ktime_get_ns();
    u64 key = (id << 8) | OP_FSYNC;
    start_time.update(&key, &ts);
    
    return 0;
}

int trace_fsync_return(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    
    // 检查目标PID
    u32 target_pid = PID_FILTER;
    if (target_pid > 0 && pid != target_pid) {
        return 0;
    }
    
    // 获取开始时间
    u64 key = (id << 8) | OP_FSYNC;
    u64 *start_ts = start_time.lookup(&key);
    if (start_ts == 0) {
        return 0;  // 找不到开始时间
    }
    
    // 计算延迟
    u64 ts = bpf_ktime_get_ns();
    u64 latency = ts - *start_ts;
    
    // 获取返回值
    int ret = PT_REGS_RC(ctx);
    
    // 创建文件操作事件
    struct file_op_t event = {};
    event.ts = ts;
    event.pid = pid;
    event.op = FSYNC;
    event.bytes = 0;  // 同步文件没有读写字节数
    event.latency = latency;
    event.failed = ret < 0 ? 1 : 0;
    
    // 获取进程名称
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    // 发送事件
    file_ops_events.perf_submit(ctx, &event, sizeof(event));
    
    // 清理
    start_time.delete(&key);
    
    return 0;
}
"""

# 文件操作类型
OP_READ = 0
OP_WRITE = 1
OP_OPEN = 2
OP_CLOSE = 3
OP_FSYNC = 4
OP_STAT = 5
OP_LSEEK = 6

# 操作类型名称映射
OP_NAMES = {
    OP_READ: "读取",
    OP_WRITE: "写入",
    OP_OPEN: "打开",
    OP_CLOSE: "关闭",
    OP_FSYNC: "同步",
    OP_STAT: "状态",
    OP_LSEEK: "定位"
}

# 文件操作信息结构
class FileOp(ct.Structure):
    _fields_ = [
        ("ts", ct.c_ulonglong),
        ("pid", ct.c_uint),
        ("op", ct.c_uint),
        ("bytes", ct.c_ulonglong),
        ("latency", ct.c_ulonglong),
        ("failed", ct.c_ubyte),
        ("comm", ct.c_char * 16),
        ("filename", ct.c_char * 128)
    ]

def parse_args():
    parser = argparse.ArgumentParser(
        description="文件系统分析工具 - 监控文件操作")
    parser.add_argument("pid", type=int, nargs="?", default=0,
        help="要监控的进程ID (0表示所有进程)")
    parser.add_argument("-d", "--duration", type=int, default=10,
        help="监控持续时间(秒)")
    parser.add_argument("-i", "--interval", type=int, default=5,
        help="报告间隔(秒)")
    parser.add_argument("-t", "--threshold", type=float, default=1.0,
        help="文件操作延迟阈值(毫秒)，只显示高于此阈值的操作")
    parser.add_argument("-f", "--filter", type=str, default="all",
        help="过滤器，可以是: all, read, write, open, close, fsync")
    parser.add_argument("--summary", action="store_true",
        help="输出操作统计摘要")
    parser.add_argument("-v", "--verbose", action="store_true",
        help="启用详细日志输出")
    return parser.parse_args()

def main():
    args = parse_args()
    
    # 设置日志
    setup_logging(args.verbose)
    
    # 参数校验
    if not validate_args(args):
        return 1
    
    # 设置操作过滤器
    op_filter = args.filter.lower()
    filter_map = {
        "all": [OP_READ, OP_WRITE, OP_OPEN, OP_CLOSE, OP_FSYNC],
        "read": [OP_READ],
        "write": [OP_WRITE],
        "open": [OP_OPEN],
        "close": [OP_CLOSE],
        "fsync": [OP_FSYNC]
    }
    
    if op_filter not in filter_map:
        logging.error(f"无效的过滤器: {op_filter}，有效值为: all, read, write, open, close, fsync")
        return 1
        
    ops_to_monitor = filter_map.get(op_filter, filter_map["all"])
    
    logging.info(f"开始监控{'PID ' + str(args.pid) if args.pid else '所有进程'} 的文件操作...")
    logging.info(f"监控持续时间: {args.duration}秒")
    logging.info(f"报告间隔: {args.interval}秒")
    logging.info(f"延迟阈值: {args.threshold}ms")
    logging.info(f"监控操作类型: {', '.join([OP_NAMES[op] for op in ops_to_monitor])}")
    
    try:
        # 替换eBPF程序中的PID过滤器
        bpf_program = bpf_text.replace('PID_FILTER', str(args.pid))
        
        # 加载eBPF程序
        b = BPF(text=bpf_program)
        
        # 附加到文件系统相关的系统调用
        b.attach_kprobe(event="vfs_read", fn_name="trace_read_entry")
        b.attach_kretprobe(event="vfs_read", fn_name="trace_read_return")
        
        b.attach_kprobe(event="vfs_write", fn_name="trace_write_entry")
        b.attach_kretprobe(event="vfs_write", fn_name="trace_write_return")
        
        b.attach_kprobe(event="do_sys_open", fn_name="trace_open_entry")
        b.attach_kretprobe(event="do_sys_open", fn_name="trace_open_return")
        
        b.attach_kprobe(event="__close_fd", fn_name="trace_close_entry")
        b.attach_kretprobe(event="__close_fd", fn_name="trace_close_return")
        
        b.attach_kprobe(event="vfs_fsync", fn_name="trace_fsync_entry")
        b.attach_kretprobe(event="vfs_fsync", fn_name="trace_fsync_return")
        
        # 统计变量
        stats = {
            OP_READ: {"count": 0, "bytes": 0, "latency": 0, "errors": 0},
            OP_WRITE: {"count": 0, "bytes": 0, "latency": 0, "errors": 0},
            OP_OPEN: {"count": 0, "bytes": 0, "latency": 0, "errors": 0},
            OP_CLOSE: {"count": 0, "bytes": 0, "latency": 0, "errors": 0},
            OP_FSYNC: {"count": 0, "bytes": 0, "latency": 0, "errors": 0}
        }
        
        # 定义事件回调
        def event_callback(cpu, data, size):
            try:
                event = ct.cast(data, ct.POINTER(FileOp)).contents
                
                # 根据操作类型过滤
                if event.op not in ops_to_monitor:
                    return
                
                # 根据延迟阈值过滤
                latency_ms = event.latency / 1000000
                if latency_ms < args.threshold:
                    return
                
                # 更新统计信息
                stats[event.op]["count"] += 1
                stats[event.op]["bytes"] += event.bytes
                stats[event.op]["latency"] += event.latency
                if event.failed:
                    stats[event.op]["errors"] += 1
                
                # 格式化输出
                op_name = OP_NAMES.get(event.op, f"未知({event.op})")
                status = "失败" if event.failed else "成功"
                timestamp = datetime.fromtimestamp(event.ts / 1000000000).strftime('%H:%M:%S.%f')
                
                logging.info(f"[{timestamp}] PID: {event.pid} ({event.comm.decode('utf-8', 'replace')}), "
                          f"操作: {op_name}, 文件: {event.filename.decode('utf-8', 'replace')}, "
                          f"耗时: {latency_ms:.3f}ms, 字节数: {event.bytes}, 状态: {status}")
            except Exception as e:
                logging.error(f"处理事件时出错: {str(e)}")
        
        # 注册事件回调
        b["file_ops_events"].open_perf_buffer(event_callback)
        
        # 定期报告函数
        def generate_summary():
            if not args.summary:
                return
                
            logging.info("\n----- 文件操作统计摘要 -----")
            logging.info("%-10s %-12s %-15s %-15s %-10s" % (
                "操作类型", "次数", "总字节数", "平均延迟(ms)", "错误次数"))
            
            total_count = 0
            total_bytes = 0
            total_errors = 0
            
            for op in [OP_READ, OP_WRITE, OP_OPEN, OP_CLOSE, OP_FSYNC]:
                op_stats = stats[op]
                count = op_stats["count"]
                total_count += count
                
                bytes_count = op_stats["bytes"]
                total_bytes += bytes_count
                
                avg_latency = op_stats["latency"] / count / 1000000 if count > 0 else 0
                
                errors = op_stats["errors"]
                total_errors += errors
                
                logging.info("%-10s %-12d %-15d %-15.3f %-10d" % (
                    OP_NAMES[op], count, bytes_count, avg_latency, errors))
            
            logging.info("-" * 70)
            logging.info("%-10s %-12d %-15d %-15s %-10d" % (
                "总计", total_count, total_bytes, "-", total_errors))
        
        # 监控指定的时间
        start_time = datetime.now()
        logging.info(f"开始时间: {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
        
        next_report = time.time() + args.interval
        
        try:
            while (datetime.now() - start_time).total_seconds() < args.duration:
                b.perf_buffer_poll(timeout=100)
                
                # 定期报告
                if time.time() >= next_report:
                    generate_summary()
                    next_report = time.time() + args.interval
                    
        except KeyboardInterrupt:
            logging.warning("监控被用户中断")
        
        end_time = datetime.now()
        logging.info(f"结束时间: {end_time.strftime('%Y-%m-%d %H:%M:%S')}")
        logging.info(f"总监控时间: {(end_time - start_time).total_seconds():.2f}秒")
        
        # 输出最终统计摘要
        generate_summary()
        
    except Exception as e:
        logging.exception(f"执行过程中发生错误: {str(e)}")
        return 1
    finally:
        # 清理资源
        if 'b' in locals():
            b.cleanup()
    
    return 0

if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code) 