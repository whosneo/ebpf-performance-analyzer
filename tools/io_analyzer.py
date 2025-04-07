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
import os
import logging
import signal

# 导入公共模块
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
from src.ebpf_common import setup_logging, validate_args, setup_signal_handler, human_readable_size

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

# 文件和进程统计结构
FileStats = namedtuple('FileStats', [
    'filename', 'read_count', 'write_count', 'sync_count',
    'read_bytes', 'write_bytes', 'read_latency', 'write_latency', 'sync_latency'
])

ProcStats = namedtuple('ProcStats', [
    'comm', 'pid', 'read_count', 'write_count', 'sync_count',
    'read_bytes', 'write_bytes', 'read_latency', 'write_latency', 'sync_latency'
])

# 创建新实例的工厂函数
def create_file_stats(filename):
    return FileStats(
        filename=filename,
        read_count=0, write_count=0, sync_count=0,
        read_bytes=0, write_bytes=0,
        read_latency=0, write_latency=0, sync_latency=0
    )

def create_proc_stats(comm, pid):
    return ProcStats(
        comm=comm, pid=pid,
        read_count=0, write_count=0, sync_count=0,
        read_bytes=0, write_bytes=0,
        read_latency=0, write_latency=0, sync_latency=0
    )

def parse_args():
    """解析命令行参数并校验"""
    parser = argparse.ArgumentParser(
        description="I/O分析器 - 监控文件系统和磁盘I/O性能")
    parser.add_argument("pid", type=int, nargs="?", default=0,
        help="要监控的进程ID (0表示所有进程)")
    parser.add_argument("-d", "--duration", type=int, default=60,
        help="监控持续时间(秒)")
    parser.add_argument("-i", "--interval", type=int, default=5,
        help="报告间隔(秒)")
    parser.add_argument("-t", "--top", type=int, default=10,
        help="显示I/O量最大的前N个文件和进程")
    parser.add_argument("-f", "--filter", type=str, default="",
        help="文件名过滤器(只跟踪包含指定字符串的文件)")
    parser.add_argument("-p", "--processes", action="store_true",
        help="显示进程I/O统计")
    parser.add_argument("-F", "--files", action="store_true",
        help="显示文件I/O统计")
    parser.add_argument("-l", "--latency", action="store_true",
        help="显示延迟分布")
    parser.add_argument("-a", "--all", action="store_true",
        help="显示所有I/O事件")
    parser.add_argument("-v", "--verbose", action="store_true",
        help="启用详细日志输出")
    return parser.parse_args()

def validate_io_args(args):
    """验证I/O分析器参数"""
    if args.duration <= 0:
        logging.error("监控时长必须大于0")
        return False
    if args.interval <= 0:
        logging.error("报告间隔必须大于0")
        return False
    if args.top <= 0:
        logging.error("显示数量必须大于0")
        return False
    return True

def log_io_event(event):
    """记录单个I/O事件"""
    try:
        ts = datetime.fromtimestamp(event.ts / 1000000000).strftime('%H:%M:%S.%f')
        type_name = IO_TYPE_NAMES.get(event.type, f"未知({event.type})")
        comm = event.comm.decode('utf-8', 'replace')
        filename = event.filename.decode('utf-8', 'replace')
        
        if event.type in [IO_READ, IO_WRITE]:
            size = human_readable_size(event.bytes)
            latency = event.delta_us / 1000  # 转换为毫秒
            logging.info(f"[{ts}] 进程: {comm}({event.pid}), 操作: {type_name}, "
                  f"文件: {filename}, 大小: {size}, 延迟: {latency:.3f}毫秒")
        elif event.type in [IO_FSYNC, IO_SYNC]:
            latency = event.delta_us / 1000  # 转换为毫秒
            logging.info(f"[{ts}] 进程: {comm}({event.pid}), 操作: {type_name}, "
                  f"文件: {filename}, 延迟: {latency:.3f}毫秒")
        else:
            logging.info(f"[{ts}] 进程: {comm}({event.pid}), 操作: {type_name}, "
                  f"文件: {filename}")
    except Exception as e:
        logging.error(f"记录I/O事件时出错: {str(e)}")

def log_latency_distribution(dist, dist_type):
    """记录延迟分布"""
    try:
        logging.info(f"\n{dist_type}操作延迟分布:")
        logging.info("-" * 60)
        
        # 由于BPF直方图的print_log2_hist方法输出到标准输出，
        # 我们需要捕获并通过logging输出
        import io
        from contextlib import redirect_stdout
        
        f = io.StringIO()
        with redirect_stdout(f):
            dist.print_log2_hist("延迟(微秒)")
        
        for line in f.getvalue().split('\n'):
            if line.strip():
                logging.info(line)
    except Exception as e:
        logging.error(f"记录延迟分布时出错: {str(e)}")

def generate_io_report(b, file_stats, proc_stats, args, final=False):
    """生成I/O统计报告"""
    try:
        report_type = "最终" if final else "中间"
        logging.info(f"\n===== {report_type}I/O性能报告 =====")
        
        # 进程I/O统计
        if args.processes:
            logging.info("\n----- 按进程的I/O统计 -----")
            
            # 按总I/O量排序
            sorted_procs = sorted(
                proc_stats.values(), 
                key=lambda p: p.read_bytes + p.write_bytes, 
                reverse=True
            )[:args.top]
            
            logging.info("%-20s %-7s %-12s %-12s %-12s %-12s %-12s" % (
                "进程", "PID", "读取次数", "写入次数", "读取量", "写入量", "总I/O量"))
            
            for proc in sorted_procs:
                total_io = proc.read_bytes + proc.write_bytes
                logging.info("%-20s %-7d %-12d %-12d %-12s %-12s %-12s" % (
                    proc.comm, proc.pid, 
                    proc.read_count, proc.write_count,
                    human_readable_size(proc.read_bytes),
                    human_readable_size(proc.write_bytes),
                    human_readable_size(total_io)
                ))
        
        # 文件I/O统计
        if args.files:
            logging.info("\n----- 按文件的I/O统计 -----")
            
            # 按总I/O量排序
            sorted_files = sorted(
                file_stats.values(), 
                key=lambda f: f.read_bytes + f.write_bytes, 
                reverse=True
            )[:args.top]
            
            logging.info("%-30s %-12s %-12s %-12s %-12s %-12s" % (
                "文件", "读取次数", "写入次数", "读取量", "写入量", "总I/O量"))
            
            for file in sorted_files:
                total_io = file.read_bytes + file.write_bytes
                # 文件名可能很长，做适当截断
                filename = file.filename if len(file.filename) <= 27 else "..." + file.filename[-24:]
                logging.info("%-30s %-12d %-12d %-12s %-12s %-12s" % (
                    filename,
                    file.read_count, file.write_count,
                    human_readable_size(file.read_bytes),
                    human_readable_size(file.write_bytes),
                    human_readable_size(total_io)
                ))
        
        # 延迟分布
        if args.latency and final:
            log_latency_distribution(b["read_lat_us"], "读取")
            log_latency_distribution(b["write_lat_us"], "写入")
            log_latency_distribution(b["sync_lat_us"], "同步")
        
        return True
    except Exception as e:
        logging.error(f"生成I/O报告时出错: {str(e)}")
        return False

def main():
    """主函数，处理程序启动、运行和清理"""
    args = parse_args()
    
    # 设置日志
    setup_logging(args.verbose)
    
    # 参数校验
    if not validate_io_args(args):
        return 1
    
    # 确保至少启用一种报告类型
    if not (args.processes or args.files or args.latency or args.all):
        args.processes = True
        args.files = True
    
    logging.info(f"开始监控{'PID ' + str(args.pid) if args.pid else '所有进程'} 的I/O性能...")
    logging.info(f"监控持续时间: {args.duration}秒")
    logging.info(f"报告间隔: {args.interval}秒")
    if args.filter:
        logging.info(f"文件名过滤器: {args.filter}")
    
    try:
        # eBPF程序
        bpf_program = bpf_text.replace('PID_FILTER', str(args.pid))
        # 文件名过滤器
        if args.filter:
            file_filter = f"""
            if (memchr(req.filename, '{args.filter}', sizeof(req.filename)) == NULL)
                return 0;
            """
            bpf_program = bpf_program.replace('FILE_FILTER', file_filter)
        else:
            bpf_program = bpf_program.replace('FILE_FILTER', '')
        
        # 加载eBPF程序
        b = BPF(text=bpf_program)
        
        # 定义用于清理资源的函数
        def cleanup():
            if 'b' in locals():
                b.cleanup()
        
        # 设置信号处理器
        setup_signal_handler(cleanup)
        
        # 附加到I/O相关函数
        b.attach_kprobe(event="vfs_read", fn_name="trace_read_entry")
        b.attach_kretprobe(event="vfs_read", fn_name="trace_read_return")
        b.attach_kprobe(event="vfs_write", fn_name="trace_write_entry")
        b.attach_kretprobe(event="vfs_write", fn_name="trace_write_return")
        b.attach_kprobe(event="vfs_fsync", fn_name="trace_fsync_entry")
        b.attach_kretprobe(event="vfs_fsync", fn_name="trace_fsync_return")
        
        # 如果内核支持，附加到更多函数
        try:
            if BPF.get_kprobe_functions(b'blk_start_request'):
                b.attach_kprobe(event="blk_start_request", fn_name="trace_req_start")
            b.attach_kprobe(event="blk_mq_start_request", fn_name="trace_req_start")
            b.attach_kprobe(event="blk_account_io_done", fn_name="trace_req_completion")
        except Exception as e:
            logging.warning(f"附加到块设备I/O函数时出错: {str(e)}")
        
        # 初始化统计信息
        file_stats = {}
        proc_stats = {}
        
        # I/O事件处理函数
        def handle_io_event(cpu, data, size):
            try:
                event = ct.cast(data, ct.POINTER(IOCompletion)).contents
                if args.all:
                    log_io_event(event)
                    
                # 按文件类型维护统计信息
                filename = event.filename.decode('utf-8', 'replace')
                if filename not in file_stats:
                    file_stats[filename] = create_file_stats(filename)
                
                file_stat = file_stats[filename]
                    
                # 更新文件统计
                if event.type == IO_READ:  # 读
                    file_stats[filename] = file_stat._replace(
                        read_count=file_stat.read_count + 1,
                        read_bytes=file_stat.read_bytes + event.bytes,
                        read_latency=file_stat.read_latency + event.delta_us
                    )
                elif event.type == IO_WRITE:  # 写
                    file_stats[filename] = file_stat._replace(
                        write_count=file_stat.write_count + 1,
                        write_bytes=file_stat.write_bytes + event.bytes,
                        write_latency=file_stat.write_latency + event.delta_us
                    )
                elif event.type == IO_FSYNC:  # 同步
                    file_stats[filename] = file_stat._replace(
                        sync_count=file_stat.sync_count + 1,
                        sync_latency=file_stat.sync_latency + event.delta_us
                    )
                
                # 按进程维护统计信息
                pid = event.pid
                comm = event.comm.decode('utf-8', 'replace')
                proc_key = f"{comm}:{pid}"
                if proc_key not in proc_stats:
                    proc_stats[proc_key] = create_proc_stats(comm, pid)
                
                proc_stat = proc_stats[proc_key]
                    
                # 更新进程统计
                if event.type == IO_READ:  # 读
                    proc_stats[proc_key] = proc_stat._replace(
                        read_count=proc_stat.read_count + 1,
                        read_bytes=proc_stat.read_bytes + event.bytes,
                        read_latency=proc_stat.read_latency + event.delta_us
                    )
                elif event.type == IO_WRITE:  # 写
                    proc_stats[proc_key] = proc_stat._replace(
                        write_count=proc_stat.write_count + 1,
                        write_bytes=proc_stat.write_bytes + event.bytes,
                        write_latency=proc_stat.write_latency + event.delta_us
                    )
                elif event.type == IO_FSYNC:  # 同步
                    proc_stats[proc_key] = proc_stat._replace(
                        sync_count=proc_stat.sync_count + 1,
                        sync_latency=proc_stat.sync_latency + event.delta_us
                    )
            except Exception as e:
                logging.error(f"处理I/O事件时出错: {str(e)}")
        
        # 注册回调
        b["io_events"].open_perf_buffer(handle_io_event)
        
        # 输出表头
        if args.all:
            logging.info(f"{'时间戳':<12} {'进程':<20} {'操作':<8} {'字节数':<10} {'延迟(微秒)':<10} {'文件名':<30}")
            logging.info("-" * 90)
        
        # 开始监控
        start_time = time.time()
        logging.info(f"开始时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        # 定期报告函数
        next_report = start_time + args.interval
        
        def periodic_report():
            nonlocal next_report
            if time.time() >= next_report:
                elapsed = time.time() - start_time
                logging.info(f"\n===== 中间报告 ({elapsed:.1f}秒) =====")
                generate_io_report(b, file_stats, proc_stats, args, final=False)
                next_report = time.time() + args.interval
        
        # 主循环
        try:
            while time.time() - start_time < args.duration:
                b.perf_buffer_poll(timeout=100)
                periodic_report()
        except KeyboardInterrupt:
            logging.warning("监控被用户中断")
            
        # 生成最终报告
        logging.info("\n===== 最终I/O性能报告 =====")
        generate_io_report(b, file_stats, proc_stats, args, final=True)
            
    except Exception as e:
        logging.exception(f"程序执行过程中发生错误: {str(e)}")
        return 1
    finally:
        # 清理资源
        if 'b' in locals():
            b.cleanup()
        logging.info("监控完成.")
    
    return 0

if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code) 