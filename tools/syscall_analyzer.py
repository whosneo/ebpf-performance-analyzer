#!/usr/bin/env python3
# 系统调用分析器 - 使用eBPF跟踪进程的系统调用
#
# 这个程序跟踪进程的系统调用，记录系统调用频率、延迟和参数，
# 帮助了解应用程序与内核的交互。

import os
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
from src.ebpf_common import setup_logging, validate_args, setup_signal_handler

# 支持的最大系统调用号
MAX_SYSCALL_ID = 450  # 大多数系统的系统调用号不会超过这个值

# eBPF程序代码
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/syscalls.h>

// 系统调用统计结构
struct syscall_stat_t {
    u64 count;           // 系统调用计数
    u64 total_ns;        // 总执行时间(纳秒)
    u64 max_ns;          // 最长执行时间
    u64 min_ns;          // 最短执行时间
    u64 errors;          // 错误次数
};

// 系统调用信息结构(用于传递给用户空间)
struct syscall_event_t {
    u64 ts;              // 时间戳
    u32 pid;             // 进程ID
    u32 tid;             // 线程ID
    u32 syscall_id;      // 系统调用号
    s64 ret;             // 返回值
    u64 duration_ns;     // 执行时间
    char comm[TASK_COMM_LEN]; // 进程名称
};

// 存储每个进程每个系统调用的统计信息
BPF_HASH(syscall_stats, u64, struct syscall_stat_t);

// 存储进行中的系统调用的开始时间
BPF_HASH(start_ns, u64, u64);

// 用于将事件传递到用户空间
BPF_PERF_OUTPUT(events);

// 跟踪系统调用入口
TRACEPOINT_PROBE(raw_syscalls, sys_enter) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    u32 tid = id & 0xFFFFFFFF;
    u32 syscall_id = args->id;
    
    // 筛选目标PID
    u32 target_pid = PID_FILTER;
    if (target_pid > 0 && pid != target_pid) {
        return 0;
    }
    
    // 满足最小阈值的目标系统调用ID
    u32 target_syscall_id = SYSCALL_FILTER;
    if (target_syscall_id > 0 && syscall_id != target_syscall_id) {
        return 0;
    }
    
    // 获取当前时间
    u64 ts = bpf_ktime_get_ns();
    
    // 保存开始时间
    start_ns.update(&id, &ts);
    
    return 0;
}

// 跟踪系统调用返回
TRACEPOINT_PROBE(raw_syscalls, sys_exit) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    u32 tid = id & 0xFFFFFFFF;
    s64 ret = args->ret;
    
    // 筛选目标PID
    u32 target_pid = PID_FILTER;
    if (target_pid > 0 && pid != target_pid) {
        return 0;
    }
    
    // 获取开始时间
    u64 *start_time = start_ns.lookup(&id);
    if (start_time == 0) {
        return 0;  // 可能是在我们开始跟踪之前调用的
    }
    
    // 获取当前时间和系统调用持续时间
    u64 ts = bpf_ktime_get_ns();
    u64 duration = ts - *start_time;
    
    // 清理开始时间
    start_ns.delete(&id);
    
    // 获取系统调用ID (保存在TLS中)
    u64 *syscallp = bpf_get_current_task()->thread_info.syscall_work;
    u32 syscall_id = 0;
    if (syscallp) {
        syscall_id = *syscallp;
    }
    
    // 满足最小阈值的目标系统调用ID
    u32 target_syscall_id = SYSCALL_FILTER;
    if (target_syscall_id > 0 && syscall_id != target_syscall_id) {
        return 0;
    }
    
    // 创建跟踪键(pid + syscall_id)
    u64 key = ((u64)pid << 32) | syscall_id;
    
    // 更新统计信息
    struct syscall_stat_t *stat = syscall_stats.lookup(&key);
    if (stat) {
        stat->count++;
        stat->total_ns += duration;
        if (duration > stat->max_ns) {
            stat->max_ns = duration;
        }
        if (duration < stat->min_ns || stat->min_ns == 0) {
            stat->min_ns = duration;
        }
        if (ret < 0) {
            stat->errors++;
        }
    } else {
        struct syscall_stat_t new_stat = {0};
        new_stat.count = 1;
        new_stat.total_ns = duration;
        new_stat.max_ns = duration;
        new_stat.min_ns = duration;
        if (ret < 0) {
            new_stat.errors = 1;
        }
        syscall_stats.update(&key, &new_stat);
    }
    
    // 检查是否超过阈值
    u64 threshold = THRESHOLD_NS;
    if (LOG_ALL == 1 || duration > threshold) {
        // 创建事件
        struct syscall_event_t event = {0};
        event.ts = ts;
        event.pid = pid;
        event.tid = tid;
        event.syscall_id = syscall_id;
        event.ret = ret;
        event.duration_ns = duration;
        
        // 获取进程名称
        bpf_get_current_comm(&event.comm, sizeof(event.comm));
        
        // 发送事件
        events.perf_submit(args, &event, sizeof(event));
    }
    
    return 0;
}
"""

# 系统调用信息结构
class SyscallEvent(ct.Structure):
    _fields_ = [
        ("ts", ct.c_ulonglong),
        ("pid", ct.c_uint),
        ("tid", ct.c_uint),
        ("syscall_id", ct.c_uint),
        ("ret", ct.c_longlong),
        ("duration_ns", ct.c_ulonglong),
        ("comm", ct.c_char * 16)
    ]

# 系统调用统计结构
class SyscallStat(ct.Structure):
    _fields_ = [
        ("count", ct.c_ulonglong),
        ("total_ns", ct.c_ulonglong),
        ("max_ns", ct.c_ulonglong),
        ("min_ns", ct.c_ulonglong),
        ("errors", ct.c_ulonglong)
    ]

def parse_args():
    parser = argparse.ArgumentParser(
        description="系统调用分析工具 - 跟踪进程的系统调用")
    parser.add_argument("pid", type=int, nargs="?", default=0,
        help="要监控的进程ID (0表示所有进程)")
    parser.add_argument("-d", "--duration", type=int, default=10,
        help="监控持续时间(秒)")
    parser.add_argument("-i", "--interval", type=int, default=5,
        help="报告间隔(秒)")
    parser.add_argument("-t", "--threshold", type=float, default=1.0,
        help="系统调用延迟阈值(毫秒)，只输出高于此阈值的调用")
    parser.add_argument("-s", "--syscall", type=int, default=0,
        help="只监控指定的系统调用ID")
    parser.add_argument("-a", "--all", action="store_true",
        help="输出所有系统调用，不管延迟")
    parser.add_argument("-f", "--frequency", type=float, default=0,
        help="采样频率，每秒最多输出的事件数")
    parser.add_argument("-p", "--profile", action="store_true",
        help="生成系统调用性能分析报告")
    parser.add_argument("-v", "--verbose", action="store_true",
        help="启用详细日志输出")
    return parser.parse_args()

def validate_syscall_args(args):
    """验证系统调用分析器参数"""
    if args.duration <= 0:
        logging.error("监控时长必须大于0")
        return False
    if args.threshold < 0:
        logging.error("延迟阈值必须大于或等于0")
        return False
    if args.frequency < 0:
        logging.error("采样频率必须大于或等于0")
        return False
    if args.syscall < 0 or args.syscall > MAX_SYSCALL_ID:
        logging.warning(f"系统调用ID {args.syscall} 可能超出有效范围")
    return True

# 系统调用名称映射
def get_syscall_names():
    # 尝试从系统中获取系统调用名称
    syscall_names = {}
    try:
        syscall_file = "/usr/include/x86_64-linux-gnu/asm/unistd_64.h"
        if os.path.exists(syscall_file):
            with open(syscall_file, "r") as f:
                for line in f:
                    if line.startswith("#define __NR_"):
                        parts = line.strip().split()
                        if len(parts) >= 3:
                            name = parts[1][5:]  # 去掉 "__NR_" 前缀
                            try:
                                num = int(parts[2])
                                syscall_names[num] = name
                            except ValueError:
                                pass
    except Exception as e:
        logging.warning(f"无法加载系统调用名称: {e}")
    
    # 确保我们至少有一些常见的系统调用
    if not syscall_names:
        common_syscalls = {
            0: "read", 1: "write", 2: "open", 3: "close", 4: "stat",
            5: "fstat", 6: "lstat", 7: "poll", 8: "lseek", 9: "mmap",
            10: "mprotect", 11: "munmap", 12: "brk", 13: "rt_sigaction",
            14: "rt_sigprocmask", 15: "rt_sigreturn", 16: "ioctl",
            17: "pread64", 18: "pwrite64", 19: "readv", 20: "writev",
            21: "access", 22: "pipe", 23: "select", 24: "sched_yield",
            25: "mremap", 26: "msync", 27: "mincore", 28: "madvise",
            29: "shmget", 30: "shmat", 31: "shmctl", 32: "dup",
            33: "dup2", 34: "pause", 35: "nanosleep", 36: "getitimer",
            37: "alarm", 38: "setitimer", 39: "getpid", 40: "sendfile",
            41: "socket", 42: "connect", 43: "accept", 44: "sendto",
            45: "recvfrom", 46: "sendmsg", 47: "recvmsg", 48: "shutdown",
            49: "bind", 50: "listen", 51: "getsockname", 52: "getpeername",
            53: "socketpair", 54: "setsockopt", 55: "getsockopt", 56: "clone",
            57: "fork", 58: "vfork", 59: "execve", 60: "exit", 61: "wait4",
            62: "kill", 63: "uname", 64: "semget", 65: "semop", 66: "semctl",
            67: "shmdt", 68: "msgget", 69: "msgsnd", 70: "msgrcv",
            71: "msgctl", 72: "fcntl", 73: "flock", 74: "fsync",
            75: "fdatasync", 76: "truncate", 77: "ftruncate", 78: "getdents",
            79: "getcwd", 80: "chdir", 81: "fchdir", 82: "rename",
            83: "mkdir", 84: "rmdir", 85: "creat", 86: "link",
            87: "unlink", 88: "symlink", 89: "readlink", 90: "chmod",
            91: "fchmod", 92: "chown", 93: "fchown", 94: "lchown",
            95: "umask", 96: "gettimeofday", 97: "getrlimit", 98: "getrusage",
            99: "sysinfo", 100: "times", 101: "ptrace"
        }
        syscall_names.update(common_syscalls)
    
    return syscall_names

def print_event(cpu, data, size, syscall_names, args):
    try:
        event = ct.cast(data, ct.POINTER(SyscallEvent)).contents
        syscall_name = syscall_names.get(event.syscall_id, f"syscall_{event.syscall_id}")
        duration_ms = event.duration_ns / 1000000
        
        # 格式化输出
        timestamp = datetime.fromtimestamp(event.ts / 1000000000).strftime('%H:%M:%S.%f')
        status = "成功" if event.ret >= 0 else f"错误 ({event.ret})"
        logging.info(f"[{timestamp}] PID: {event.pid} ({event.comm.decode('utf-8', 'replace')}), "
              f"系统调用: {syscall_name} (ID: {event.syscall_id}), "
              f"耗时: {duration_ms:.3f}ms, 返回值: {event.ret}, 状态: {status}")
    except Exception as e:
        logging.error(f"处理系统调用事件时出错: {str(e)}")

def generate_syscall_profile_report(b, syscall_names, args):
    """生成系统调用性能分析报告"""
    try:
        logging.info("\n----- 系统调用性能分析报告 -----")
        
        # 从内核中收集统计信息
        syscall_stats = b.get_table("syscall_stats")
        
        # 创建一个列表用于存储和排序统计信息
        stats_list = []
        for k, v in syscall_stats.items():
            pid = k.value >> 32
            syscall_id = k.value & 0xFFFFFFFF
            
            # 跳过不在目标PID中的条目
            if args.pid and pid != args.pid:
                continue
                
            # 如果指定了系统调用ID，只显示该ID
            if args.syscall and syscall_id != args.syscall:
                continue
                
            syscall_name = syscall_names.get(syscall_id, f"syscall_{syscall_id}")
            
            # 计算平均时间
            avg_ns = v.total_ns / v.count if v.count > 0 else 0
            
            # 添加到列表
            stats_list.append((
                pid, syscall_id, syscall_name, v.count, 
                v.total_ns, avg_ns, v.min_ns, v.max_ns, v.errors
            ))
        
        # 按调用次数排序
        sorted_stats = sorted(stats_list, key=lambda x: x[3], reverse=True)
        
        # 输出表头
        logging.info("%-6s %-20s %-12s %-12s %-12s %-12s %-12s %-10s" % (
            "PID", "系统调用", "次数", "总时间(ms)", "平均(ms)", "最小(ms)", "最大(ms)", "错误次数"
        ))
        
        # 输出统计信息
        for stat in sorted_stats:
            pid, syscall_id, syscall_name, count, total_ns, avg_ns, min_ns, max_ns, errors = stat
            
            logging.info("%-6d %-20s %-12d %-12.2f %-12.2f %-12.2f %-12.2f %-10d" % (
                pid, syscall_name, count, 
                total_ns / 1000000, avg_ns / 1000000, 
                min_ns / 1000000, max_ns / 1000000, 
                errors
            ))
        
        # 输出总计
        total_calls = sum(x[3] for x in stats_list)
        total_time = sum(x[4] for x in stats_list) / 1000000
        total_errors = sum(x[8] for x in stats_list)
        
        logging.info("-" * 96)
        logging.info(f"总计: {len(stats_list)} 种系统调用, {total_calls} 次调用, "
              f"总时间: {total_time:.2f}ms, 错误: {total_errors} 次")
              
        return stats_list
    except Exception as e:
        logging.error(f"生成系统调用分析报告时出错: {str(e)}")
        return None

def main():
    args = parse_args()
    
    # 设置日志
    setup_logging(args.verbose)
    
    # 参数校验
    if not validate_syscall_args(args):
        return 1
    
    threshold_ns = int(args.threshold * 1000000)  # 转换为纳秒
    logging.info(f"开始监控{'PID ' + str(args.pid) if args.pid else '所有进程'} 的系统调用...")
    logging.info(f"监控持续时间: {args.duration}秒")
    logging.info(f"报告间隔: {args.interval}秒")
    logging.info(f"延迟阈值: {args.threshold}ms")
    
    if args.syscall:
        logging.info(f"只监控系统调用ID: {args.syscall}")
    
    if args.all:
        logging.info("输出所有系统调用，不管延迟")
    
    try:
        # 加载系统调用名称
        syscall_names = get_syscall_names()
        
        # 替换eBPF程序中的变量
        bpf_program = bpf_text.replace('PID_FILTER', str(args.pid))
        bpf_program = bpf_program.replace('SYSCALL_FILTER', str(args.syscall))
        bpf_program = bpf_program.replace('THRESHOLD_NS', str(threshold_ns))
        bpf_program = bpf_program.replace('LOG_ALL', "1" if args.all else "0")
        
        # 加载eBPF程序
        b = BPF(text=bpf_program)
        
        # 定义用于清理资源的函数
        def cleanup():
            if 'b' in locals():
                b.cleanup()
        
        # 设置信号处理器
        setup_signal_handler(cleanup)
        
        # 监控指定的时间
        start_time = datetime.now()
        logging.info(f"开始时间: {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
        
        # 定义事件回调
        event_count = 0
        start_ts = time.time()
        
        def event_callback(cpu, data, size):
            try:
                nonlocal event_count, start_ts
                
                # 频率限制
                if args.frequency > 0:
                    current_ts = time.time()
                    time_diff = current_ts - start_ts
                    if time_diff > 0:
                        rate = event_count / time_diff
                        if rate > args.frequency:
                            event_count += 1
                            return
                    
                    event_count += 1
                    if time_diff > 1:  # 每秒重置计数器
                        event_count = 0
                        start_ts = current_ts
                
                # 输出事件
                print_event(cpu, data, size, syscall_names, args)
            except Exception as e:
                logging.error(f"处理事件回调时出错: {str(e)}")
        
        # 注册事件回调
        b["events"].open_perf_buffer(event_callback)
        
        # 定义定期报告函数
        next_report = time.time() + args.interval
        
        def periodic_report():
            nonlocal next_report
            if args.profile and time.time() >= next_report:
                elapsed = (datetime.now() - start_time).total_seconds()
                logging.info(f"\n===== 中间报告 ({elapsed:.1f}秒) =====")
                generate_syscall_profile_report(b, syscall_names, args)
                next_report = time.time() + args.interval
        
        try:
            # 监控loop
            while (datetime.now() - start_time).total_seconds() < args.duration:
                b.perf_buffer_poll(timeout=100)
                periodic_report()
        except KeyboardInterrupt:
            logging.warning("监控被用户中断")
        
        end_time = datetime.now()
        logging.info(f"结束时间: {end_time.strftime('%Y-%m-%d %H:%M:%S')}")
        elapsed = (end_time - start_time).total_seconds()
        logging.info(f"总监控时间: {elapsed:.2f}秒")
        
        # 生成性能分析报告
        if args.profile:
            logging.info("\n===== 最终系统调用性能分析报告 =====")
            generate_syscall_profile_report(b, syscall_names, args)
        
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