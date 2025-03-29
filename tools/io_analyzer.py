#!/usr/bin/env python3
# I/O分析器 - 使用eBPF跟踪磁盘I/O操作和性能
#
# 这个程序使用eBPF跟踪进程的磁盘I/O操作，
# 提供I/O延迟分析、文件系统调用分析和块I/O统计。

import sys
import time
import argparse
from bcc import BPF
from datetime import datetime
import ctypes as ct

# eBPF程序代码
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/blkdev.h>
#include <linux/sched.h>
#include <linux/fs.h>

// 记录I/O操作的结构体
struct io_data_t {
    u64 ts;           // 时间戳
    u32 pid;          // 进程ID
    u32 size;         // I/O大小
    u64 sector;       // 扇区号
    u64 dur;          // 持续时间 (用于完成)
    u32 cmd_flags;    // 操作标志
    u8 rwflag;        // 读/写标志: 0=读, 1=写
    char comm[TASK_COMM_LEN]; // 命令名称
    char disk[DISK_NAME_LEN]; // 磁盘名称
};

// 跟踪I/O请求的临时结构
struct start_req_t {
    u64 ts;           // 开始时间戳
    u32 size;         // I/O大小
    u64 sector;       // 扇区号
    u32 cmd_flags;    // 操作标志
    char disk[DISK_NAME_LEN]; // 磁盘名称
};

// 磁盘I/O统计
struct io_stat_t {
    u64 bytes;        // 总字节数
    u64 count;        // 操作数
    u64 total_lat_ns; // 总延迟 (ns)
};

// 文件操作跟踪
struct file_op_t {
    u64 ts;           // 时间戳
    u32 pid;          // 进程ID
    u64 bytes;        // 字节数
    u64 offset;       // 文件偏移量
    u8 is_sync;       // 是否同步操作
    u8 is_write;      // 是否写操作
    char comm[TASK_COMM_LEN]; // 命令名称
    char filename[DNAME_INLINE_LEN]; // 文件名
};

// 保存正在进行的I/O请求
BPF_HASH(start_io, struct request *, struct start_req_t);

// 统计每个进程的I/O操作
BPF_HASH(io_stats, u32, struct io_stat_t);

// 统计按磁盘名称的I/O操作
BPF_HASH(disk_stats, u32, struct io_stat_t);

// 存储完成的I/O操作
BPF_PERF_OUTPUT(io_events);

// 存储文件I/O操作
BPF_PERF_OUTPUT(file_events);

// 存储进程的最大延迟
BPF_HASH(max_lat, u32, u64);

// 跟踪块I/O请求提交
int trace_req_start(struct pt_regs *ctx, struct request *req) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tgid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    
    // 检查目标PID
    u32 target_pid = PID_FILTER;
    if (target_pid > 0 && tgid != target_pid) {
        return 0;
    }
    
    // 获取请求信息
    struct start_req_t start_req = {0};
    start_req.ts = bpf_ktime_get_ns();
    start_req.size = req->__data_len;
    start_req.sector = req->__sector;
    start_req.cmd_flags = req->cmd_flags;
    
    // 获取磁盘名称
    struct gendisk *disk = req->rq_disk;
    if (disk) {
        bpf_probe_read_kernel(&start_req.disk, DISK_NAME_LEN, 
                            disk->disk_name);
    }
    
    // 保存起始信息
    start_io.update(&req, &start_req);
    
    return 0;
}

// 跟踪块I/O请求完成
int trace_req_completion(struct pt_regs *ctx, struct request *req) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tgid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    u64 ts = bpf_ktime_get_ns();
    
    // 查找起始跟踪信息
    struct start_req_t *startp = start_io.lookup(&req);
    if (startp == 0) {
        return 0;  // 可能不是我们跟踪的请求
    }
    
    // 计算耗时
    u64 dur = ts - startp->ts;
    
    // 创建输出事件
    struct io_data_t data = {0};
    data.ts = startp->ts;
    data.pid = tgid;
    data.size = startp->size;
    data.sector = startp->sector;
    data.dur = dur;
    data.cmd_flags = startp->cmd_flags;
    data.rwflag = !!(startp->cmd_flags & REQ_OP_WRITE);
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    __builtin_memcpy(&data.disk, startp->disk, DISK_NAME_LEN);
    
    // 检查目标PID
    u32 target_pid = PID_FILTER;
    if (target_pid > 0 && tgid != target_pid) {
        // 清理跟踪数据
        start_io.delete(&req);
        return 0;
    }
    
    // 发送数据到用户空间
    io_events.perf_submit(ctx, &data, sizeof(data));
    
    // 更新进程I/O统计
    struct io_stat_t *stats, zero = {0};
    stats = io_stats.lookup_or_init(&tgid, &zero);
    stats->bytes += data.size;
    stats->count++;
    stats->total_lat_ns += dur;
    
    // 更新进程最大延迟
    u64 *max_val = max_lat.lookup(&tgid);
    if (max_val == 0 || dur > *max_val) {
        max_lat.update(&tgid, &dur);
    }
    
    // 清理跟踪数据
    start_io.delete(&req);
    
    return 0;
}

// 跟踪文件读操作
int trace_read(struct pt_regs *ctx, struct file *file, char __user *buf,
               size_t count, loff_t *pos) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    u32 tgid = id & 0xFFFFFFFF;
    
    // 检查目标PID
    u32 target_pid = PID_FILTER;
    if (target_pid > 0 && tgid != target_pid) {
        return 0;
    }
    
    // 获取文件名
    struct file_op_t data = {0};
    data.ts = bpf_ktime_get_ns();
    data.pid = tgid;
    data.bytes = count;
    data.is_write = 0;
    
    if (pos) {
        bpf_probe_read_kernel(&data.offset, sizeof(data.offset), pos);
    }
    
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    
    // 获取文件名（路径的最后部分）
    const unsigned char *d_name = file->f_path.dentry->d_name.name;
    bpf_probe_read_kernel_str(&data.filename, sizeof(data.filename), d_name);
    
    // 发送事件
    file_events.perf_submit(ctx, &data, sizeof(data));
    
    return 0;
}

// 跟踪文件写操作
int trace_write(struct pt_regs *ctx, struct file *file, const char __user *buf,
                size_t count, loff_t *pos) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    u32 tgid = id & 0xFFFFFFFF;
    
    // 检查目标PID
    u32 target_pid = PID_FILTER;
    if (target_pid > 0 && tgid != target_pid) {
        return 0;
    }
    
    // 获取文件名
    struct file_op_t data = {0};
    data.ts = bpf_ktime_get_ns();
    data.pid = tgid;
    data.bytes = count;
    data.is_write = 1;
    
    if (pos) {
        bpf_probe_read_kernel(&data.offset, sizeof(data.offset), pos);
    }
    
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    
    // 获取文件名（路径的最后部分）
    const unsigned char *d_name = file->f_path.dentry->d_name.name;
    bpf_probe_read_kernel_str(&data.filename, sizeof(data.filename), d_name);
    
    // 发送事件
    file_events.perf_submit(ctx, &data, sizeof(data));
    
    return 0;
}

// 跟踪同步文件操作
int trace_fsync(struct pt_regs *ctx, struct file *file) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    u32 tgid = id & 0xFFFFFFFF;
    
    // 检查目标PID
    u32 target_pid = PID_FILTER;
    if (target_pid > 0 && tgid != target_pid) {
        return 0;
    }
    
    // 获取文件名
    struct file_op_t data = {0};
    data.ts = bpf_ktime_get_ns();
    data.pid = tgid;
    data.is_sync = 1;
    
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    
    // 获取文件名（路径的最后部分）
    const unsigned char *d_name = file->f_path.dentry->d_name.name;
    bpf_probe_read_kernel_str(&data.filename, sizeof(data.filename), d_name);
    
    // 发送事件
    file_events.perf_submit(ctx, &data, sizeof(data));
    
    return 0;
}
"""

# 定义I/O数据结构
class IOData(ct.Structure):
    _fields_ = [
        ("ts", ct.c_ulonglong),
        ("pid", ct.c_uint),
        ("size", ct.c_uint),
        ("sector", ct.c_ulonglong),
        ("dur", ct.c_ulonglong),
        ("cmd_flags", ct.c_uint),
        ("rwflag", ct.c_ubyte),
        ("comm", ct.c_char * 16),
        ("disk", ct.c_char * 32),
    ]

# 定义文件操作数据结构
class FileOp(ct.Structure):
    _fields_ = [
        ("ts", ct.c_ulonglong),
        ("pid", ct.c_uint),
        ("bytes", ct.c_ulonglong),
        ("offset", ct.c_ulonglong),
        ("is_sync", ct.c_ubyte),
        ("is_write", ct.c_ubyte),
        ("comm", ct.c_char * 16),
        ("filename", ct.c_char * 255),
    ]

# I/O统计结构
class IOStat(ct.Structure):
    _fields_ = [
        ("bytes", ct.c_ulonglong),
        ("count", ct.c_ulonglong),
        ("total_lat_ns", ct.c_ulonglong),
    ]

def parse_args():
    parser = argparse.ArgumentParser(
        description="I/O分析工具 - 监控磁盘I/O性能")
    parser.add_argument("pid", type=int, nargs="?", default=0,
        help="要监控的进程ID (0表示所有进程)")
    parser.add_argument("-d", "--duration", type=int, default=10,
        help="监控持续时间(秒)")
    parser.add_argument("-f", "--files", action="store_true",
        help="跟踪文件I/O操作")
    parser.add_argument("-t", "--top", type=int, default=10,
        help="显示I/O最多的前N个进程")
    return parser.parse_args()

def print_io_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(IOData)).contents
    rwflg = "写入" if event.rwflag else "读取"
    print(f"[{datetime.fromtimestamp(event.ts / 1e9).strftime('%H:%M:%S.%f')}] "
          f"{event.comm.decode('utf-8', 'replace')} ({event.pid}) "
          f"{rwflg} {event.size:,} 字节, 延迟: {event.dur / 1000:,.2f} μs "
          f"磁盘: {event.disk.decode('utf-8', 'replace')}")

def print_file_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(FileOp)).contents
    op_type = "写入" if event.is_write else "读取"
    if event.is_sync:
        op_type = "同步"
    
    print(f"[{datetime.fromtimestamp(event.ts / 1e9).strftime('%H:%M:%S.%f')}] "
          f"{event.comm.decode('utf-8', 'replace')} ({event.pid}) "
          f"{op_type} {event.filename.decode('utf-8', 'replace')} "
          f"{event.bytes:,} 字节, 偏移: {event.offset:,}")

def main():
    args = parse_args()
    
    print(f"开始监控{'PID ' + str(args.pid) if args.pid else '所有进程'} 的I/O操作...")
    print(f"监控持续时间: {args.duration}秒")
    
    # 替换eBPF程序中的PID过滤器
    bpf_program = bpf_text.replace('PID_FILTER', str(args.pid))
    
    # 加载eBPF程序
    b = BPF(text=bpf_program)
    
    # 附加块I/O追踪点
    b.attach_kprobe(event="blk_account_io_start", fn_name="trace_req_start")
    b.attach_kprobe(event="blk_account_io_done", fn_name="trace_req_completion")
    
    # 如果跟踪文件I/O，附加文件操作函数
    if args.files:
        b.attach_kprobe(event="vfs_read", fn_name="trace_read")
        b.attach_kprobe(event="vfs_write", fn_name="trace_write")
        b.attach_kprobe(event="vfs_fsync", fn_name="trace_fsync")
    
    # 设置回调
    b["io_events"].open_perf_buffer(print_io_event)
    if args.files:
        b["file_events"].open_perf_buffer(print_file_event)
    
    # 记录启动时间
    start_time = datetime.now()
    print(f"开始时间: {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
    
    # 实时打印事件
    print("\n== 开始实时I/O操作监控 ==\n")
    
    # 监控指定的时间
    elapsed = 0
    try:
        while elapsed < args.duration:
            b.perf_buffer_poll(timeout=1000)
            elapsed += 1
    except KeyboardInterrupt:
        print("监控被用户中断")
    
    end_time = datetime.now()
    print(f"\n结束时间: {end_time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"总监控时间: {(end_time - start_time).total_seconds():.2f}秒")
    
    # 获取进程I/O统计
    io_stats = b.get_table("io_stats")
    max_lat = b.get_table("max_lat")
    
    # 转换为Python字典以便处理
    pid_stats = {}
    for pid, stats in io_stats.items():
        stats_obj = ct.cast(stats, ct.POINTER(IOStat)).contents
        max_latency = max_lat.get(pid, 0)
        
        pid_stats[pid.value] = {
            "bytes": stats_obj.bytes,
            "count": stats_obj.count,
            "avg_lat": stats_obj.total_lat_ns / stats_obj.count if stats_obj.count > 0 else 0,
            "max_lat": max_latency
        }
    
    # 按I/O字节数排序
    sorted_stats = sorted(pid_stats.items(), key=lambda x: x[1]["bytes"], reverse=True)
    
    # 打印进程I/O统计信息
    print("\n===== 进程I/O统计 =====")
    print(f"{'PID':<7} {'命令':<16} {'I/O操作数':>10} {'总字节数':>15} {'总MB':>9} {'平均延迟(μs)':>15} {'最大延迟(μs)':>15}")
    print("-" * 90)
    
    for pid, stat in sorted_stats[:args.top]:
        try:
            with open(f"/proc/{pid}/comm", "r") as f:
                comm = f.read().strip()
        except:
            comm = "[未知]"
            
        print(f"{pid:<7} {comm[:15]:<16} {stat['count']:>10,} {stat['bytes']:>15,} "
              f"{stat['bytes']/1024/1024:>9.2f} {stat['avg_lat']/1000:>15.2f} "
              f"{stat['max_lat']/1000:>15.2f}")
    
    # 清理资源
    b.cleanup()

if __name__ == "__main__":
    if not BPF.support_raw_tracepoint():
        print("警告: 内核版本可能不完全支持eBPF功能，某些特性可能无法正常工作")
    
    main() 