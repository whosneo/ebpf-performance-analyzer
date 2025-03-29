#!/usr/bin/env python3
# 内存泄漏检测器 - 使用eBPF跟踪内存分配与释放
#
# 这个工具跟踪进程的内存分配和释放操作，标识潜在的内存泄漏点。
# 通过分析内存分配但未释放的模式，帮助开发者找出可能的内存泄漏问题。

import sys
import time
import argparse
import os
import signal
from bcc import BPF
from time import sleep, strftime
import ctypes as ct
from collections import defaultdict, namedtuple
from datetime import datetime

# eBPF程序
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/mm.h>
#include <linux/sched.h>

// 最大栈帧深度
#define MAX_STACK_DEPTH 20

// 内存分配记录
struct alloc_info_t {
    u64 size;            // 分配大小
    u64 timestamp_ns;    // 时间戳(纳秒)
    int stack_id;        // 堆栈ID
};

// 内存地址信息
struct addr_info_t {
    u64 addr;            // 内存地址
    u64 size;            // 分配大小
    u64 timestamp_ns;    // 时间戳
    int stack_id;        // 堆栈ID
};

// 内存事件输出
struct mem_event_t {
    u64 ts;              // 时间戳
    u64 addr;            // 内存地址
    u64 size;            // 分配/释放大小
    u32 pid;             // 进程ID
    int stack_id;        // 堆栈ID
    char comm[TASK_COMM_LEN]; // 进程名称
    bool is_alloc;       // 是否为分配操作
};

// 性能输出缓冲区
BPF_PERF_OUTPUT(mem_events);

// 保存内存分配信息
BPF_HASH(allocs, u64, struct alloc_info_t);

// 跟踪调用栈
BPF_STACK_TRACE(stack_traces, 16384);

// 内存分配统计信息
BPF_HASH(total_alloc, u32);
BPF_HASH(total_free, u32);

// 跟踪malloc
int trace_malloc(struct pt_regs *ctx, size_t size) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    u32 tid = id;
    
    // 检查目标PID
    u32 target_pid = PID_FILTER;
    if (target_pid > 0 && pid != target_pid) {
        return 0;
    }
    
    // 获取栈跟踪
    int stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);
    
    // 创建事件
    struct mem_event_t event = {};
    event.ts = bpf_ktime_get_ns();
    event.addr = 0;  // 尚未知道地址，会在返回时设置
    event.size = size;
    event.pid = pid;
    event.stack_id = stack_id;
    event.is_alloc = true;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    // 更新分配总量
    u64 *existing_size = total_alloc.lookup(&pid);
    if (existing_size) {
        *existing_size += size;
    } else {
        total_alloc.update(&pid, &size);
    }
    
    // 只对特定大小的分配发送事件
    MIN_SIZE_FILTER
    
    mem_events.perf_submit(ctx, &event, sizeof(event));
    
    return 0;
}

// 跟踪malloc返回
int trace_malloc_ret(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    
    // 检查目标PID
    u32 target_pid = PID_FILTER;
    if (target_pid > 0 && pid != target_pid) {
        return 0;
    }
    
    // 获取返回的地址
    void *addr = (void *)PT_REGS_RC(ctx);
    if (!addr) {
        return 0;  // malloc失败，返回NULL
    }
    
    // 创建分配信息
    struct alloc_info_t info = {};
    info.timestamp_ns = bpf_ktime_get_ns();
    info.stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);
    
    u64 addr_key = (u64)addr;
    allocs.update(&addr_key, &info);
    
    return 0;
}

// 跟踪calloc
int trace_calloc(struct pt_regs *ctx, size_t nmemb, size_t size) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    
    // 检查目标PID
    u32 target_pid = PID_FILTER;
    if (target_pid > 0 && pid != target_pid) {
        return 0;
    }
    
    // 计算总分配大小
    u64 total_size = nmemb * size;
    
    // 获取栈跟踪
    int stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);
    
    // 创建事件
    struct mem_event_t event = {};
    event.ts = bpf_ktime_get_ns();
    event.addr = 0;  // 尚未知道，会在返回时设置
    event.size = total_size;
    event.pid = pid;
    event.stack_id = stack_id;
    event.is_alloc = true;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    // 更新分配总量
    u64 *existing_size = total_alloc.lookup(&pid);
    if (existing_size) {
        *existing_size += total_size;
    } else {
        total_alloc.update(&pid, &total_size);
    }
    
    // 只对特定大小的分配发送事件
    if (total_size >= MIN_SIZE) {
        mem_events.perf_submit(ctx, &event, sizeof(event));
    }
    
    return 0;
}

// 跟踪calloc返回
int trace_calloc_ret(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    
    // 检查目标PID
    u32 target_pid = PID_FILTER;
    if (target_pid > 0 && pid != target_pid) {
        return 0;
    }
    
    // 获取返回的地址
    void *addr = (void *)PT_REGS_RC(ctx);
    if (!addr) {
        return 0;  // calloc失败，返回NULL
    }
    
    // 创建分配信息
    struct alloc_info_t info = {};
    info.timestamp_ns = bpf_ktime_get_ns();
    info.stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);
    
    u64 addr_key = (u64)addr;
    allocs.update(&addr_key, &info);
    
    return 0;
}

// 跟踪realloc
int trace_realloc(struct pt_regs *ctx, void *ptr, size_t size) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    
    // 检查目标PID
    u32 target_pid = PID_FILTER;
    if (target_pid > 0 && pid != target_pid) {
        return 0;
    }
    
    // 如果ptr为NULL，相当于malloc
    if (!ptr) {
        return trace_malloc(ctx, size);
    }
    
    // 获取原来的大小
    u64 addr_key = (u64)ptr;
    struct alloc_info_t *old_info = allocs.lookup(&addr_key);
    u64 old_size = 0;
    if (old_info) {
        old_size = old_info->size;
    }
    
    // 创建释放事件
    struct mem_event_t free_event = {};
    free_event.ts = bpf_ktime_get_ns();
    free_event.addr = (u64)ptr;
    free_event.size = old_size;
    free_event.pid = pid;
    free_event.stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);
    free_event.is_alloc = false;
    
    bpf_get_current_comm(&free_event.comm, sizeof(free_event.comm));
    
    // 更新释放总量
    u64 *existing_free = total_free.lookup(&pid);
    if (existing_free) {
        *existing_free += old_size;
    } else {
        total_free.update(&pid, &old_size);
    }
    
    // 发送释放事件
    if (old_size >= MIN_SIZE) {
        mem_events.perf_submit(ctx, &free_event, sizeof(free_event));
    }
    
    // 创建分配事件
    struct mem_event_t alloc_event = {};
    alloc_event.ts = bpf_ktime_get_ns();
    alloc_event.addr = 0;  // 尚未知道，会在返回时设置
    alloc_event.size = size;
    alloc_event.pid = pid;
    alloc_event.stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);
    alloc_event.is_alloc = true;
    
    bpf_get_current_comm(&alloc_event.comm, sizeof(alloc_event.comm));
    
    // 更新分配总量
    u64 *existing_alloc = total_alloc.lookup(&pid);
    if (existing_alloc) {
        *existing_alloc += size;
    } else {
        total_alloc.update(&pid, &size);
    }
    
    // 发送分配事件
    if (size >= MIN_SIZE) {
        mem_events.perf_submit(ctx, &alloc_event, sizeof(alloc_event));
    }
    
    // 删除旧记录
    allocs.delete(&addr_key);
    
    return 0;
}

// 跟踪realloc返回
int trace_realloc_ret(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    
    // 检查目标PID
    u32 target_pid = PID_FILTER;
    if (target_pid > 0 && pid != target_pid) {
        return 0;
    }
    
    // 获取返回的地址
    void *addr = (void *)PT_REGS_RC(ctx);
    if (!addr) {
        return 0;  // realloc失败，返回NULL
    }
    
    // 创建分配信息
    struct alloc_info_t info = {};
    info.timestamp_ns = bpf_ktime_get_ns();
    info.stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);
    
    u64 addr_key = (u64)addr;
    allocs.update(&addr_key, &info);
    
    return 0;
}

// 跟踪free
int trace_free(struct pt_regs *ctx, void *ptr) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    
    // 检查目标PID
    u32 target_pid = PID_FILTER;
    if (target_pid > 0 && pid != target_pid) {
        return 0;
    }
    
    // 如果是NULL，直接返回
    if (!ptr) {
        return 0;
    }
    
    // 查找分配记录
    u64 addr_key = (u64)ptr;
    struct alloc_info_t *info = allocs.lookup(&addr_key);
    u64 size = 0;
    
    if (info) {
        size = info->size;
    }
    
    // 创建释放事件
    struct mem_event_t event = {};
    event.ts = bpf_ktime_get_ns();
    event.addr = (u64)ptr;
    event.size = size;
    event.pid = pid;
    event.stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);
    event.is_alloc = false;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    // 更新释放总量
    u64 *existing_size = total_free.lookup(&pid);
    if (existing_size) {
        *existing_size += size;
    } else {
        total_free.update(&pid, &size);
    }
    
    // 只对特定大小的释放发送事件
    if (size >= MIN_SIZE) {
        mem_events.perf_submit(ctx, &event, sizeof(event));
    }
    
    // 删除记录
    allocs.delete(&addr_key);
    
    return 0;
}

// 跟踪kmalloc
int trace_kmalloc(struct pt_regs *ctx, size_t size, gfp_t flags) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    
    // 只关注用户空间进程
    if (target_pid > 0 && pid != target_pid) {
        return 0;
    }
    
    // 获取栈跟踪
    int stack_id = stack_traces.get_stackid(ctx, 0);
    
    // 创建事件
    struct mem_event_t event = {};
    event.ts = bpf_ktime_get_ns();
    event.addr = 0;  // 尚未知道，会在返回时设置
    event.size = size;
    event.pid = pid;
    event.stack_id = stack_id;
    event.is_alloc = true;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    // 只对特定大小的分配发送事件
    if (size >= MIN_SIZE) {
        mem_events.perf_submit(ctx, &event, sizeof(event));
    }
    
    return 0;
}

// 跟踪kmalloc返回
int trace_kmalloc_ret(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    
    // 只关注用户空间进程
    if (target_pid > 0 && pid != target_pid) {
        return 0;
    }
    
    // 获取返回的地址
    void *addr = (void *)PT_REGS_RC(ctx);
    if (!addr) {
        return 0;  // kmalloc失败，返回NULL
    }
    
    // 创建分配信息
    struct alloc_info_t info = {};
    info.timestamp_ns = bpf_ktime_get_ns();
    info.stack_id = stack_traces.get_stackid(ctx, 0);
    
    u64 addr_key = (u64)addr;
    allocs.update(&addr_key, &info);
    
    return 0;
}

// 跟踪kfree
int trace_kfree(struct pt_regs *ctx, void *ptr) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    
    // 只关注用户空间进程
    if (target_pid > 0 && pid != target_pid) {
        return 0;
    }
    
    // 如果是NULL，直接返回
    if (!ptr) {
        return 0;
    }
    
    // 查找分配记录
    u64 addr_key = (u64)ptr;
    struct alloc_info_t *info = allocs.lookup(&addr_key);
    u64 size = 0;
    
    if (info) {
        size = info->size;
    }
    
    // 创建释放事件
    struct mem_event_t event = {};
    event.ts = bpf_ktime_get_ns();
    event.addr = (u64)ptr;
    event.size = size;
    event.pid = pid;
    event.stack_id = stack_traces.get_stackid(ctx, 0);
    event.is_alloc = false;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    // 只对特定大小的释放发送事件
    if (size >= MIN_SIZE) {
        mem_events.perf_submit(ctx, &event, sizeof(event));
    }
    
    // 删除记录
    allocs.delete(&addr_key);
    
    return 0;
}
"""

# 内存事件结构
class MemEvent(ct.Structure):
    _fields_ = [
        ("ts", ct.c_ulonglong),
        ("addr", ct.c_ulonglong),
        ("size", ct.c_ulonglong),
        ("pid", ct.c_uint),
        ("stack_id", ct.c_int),
        ("comm", ct.c_char * 16),
        ("is_alloc", ct.c_bool)
    ]

# 内存分配记录
class Allocation:
    def __init__(self, address, size, stack_id, timestamp):
        self.address = address
        self.size = size
        self.stack_id = stack_id
        self.timestamp = timestamp
        self.stack_trace = []

# 堆栈跟踪缓存
stack_traces_cache = {}

def human_size(bytes):
    """将字节大小转换为人类可读的形式"""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes < 1024.0:
            return f"{bytes:.2f} {unit}"
        bytes /= 1024.0
    return f"{bytes:.2f} PB"

def get_stack_trace(b, stack_id, pid):
    """获取堆栈跟踪"""
    if stack_id < 0:
        return ["[无法获取堆栈]"]
    
    if stack_id in stack_traces_cache:
        return stack_traces_cache[stack_id]
    
    stack = []
    try:
        for addr in b.get_table("stack_traces").walk(stack_id):
            try:
                sym = b.sym(addr, pid, show_offset=True).decode('utf-8', 'replace')
            except:
                sym = f"[未知:0x{addr:x}]"
            stack.append(sym)
    except Exception as e:
        stack = [f"[错误获取堆栈: {str(e)}]"]
    
    # 缓存结果
    stack_traces_cache[stack_id] = stack
    return stack

def get_proc_maps(pid):
    """获取进程的内存映射"""
    try:
        with open(f"/proc/{pid}/maps", "r") as f:
            return f.readlines()
    except:
        return []

def find_map_for_addr(addr, maps):
    """在映射中查找特定地址"""
    for line in maps:
        parts = line.split()
        if len(parts) < 6:
            continue
        
        addr_range = parts[0].split("-")
        if len(addr_range) != 2:
            continue
        
        start = int(addr_range[0], 16)
        end = int(addr_range[1], 16)
        
        if start <= addr <= end:
            return f"{parts[5].strip()} ({parts[0]} {parts[1]})"
    
    return "[未知映射]"

def parse_args():
    """解析命令行参数"""
    parser = argparse.ArgumentParser(
        description="内存泄漏检测工具 - 跟踪内存分配和释放")
    parser.add_argument("pid", type=int, nargs="?", default=0,
        help="要监控的进程ID (0表示所有进程)")
    parser.add_argument("-d", "--duration", type=int, default=60,
        help="监控持续时间(秒)")
    parser.add_argument("-i", "--interval", type=int, default=5,
        help="报告间隔(秒)")
    parser.add_argument("-s", "--min-size", type=int, default=1024,
        help="最小跟踪大小(字节)")
    parser.add_argument("-t", "--top", type=int, default=10,
        help="显示前N个最大的泄漏")
    parser.add_argument("-a", "--show-all", action="store_true",
        help="显示所有内存事件")
    parser.add_argument("-k", "--kernel", action="store_true",
        help="跟踪内核内存")
    parser.add_argument("-u", "--user", action="store_true",
        help="跟踪用户空间内存")
    parser.add_argument("-f", "--stack-filter", type=str, default="",
        help="堆栈过滤器(仅显示包含指定字符串的堆栈)")
    return parser.parse_args()

def main():
    args = parse_args()
    
    # 默认同时跟踪用户和内核空间
    if not args.kernel and not args.user:
        args.kernel = True
        args.user = True
    
    # 替换eBPF程序中的变量
    bpf_program = bpf_text.replace('PID_FILTER', str(args.pid))
    
    # 设置最小大小过滤器
    min_size_filter = f"if (size < {args.min_size}) {{ return 0; }}"
    bpf_program = bpf_program.replace('MIN_SIZE_FILTER', min_size_filter)
    bpf_program = bpf_program.replace('MIN_SIZE', str(args.min_size))
    
    # 加载eBPF程序
    b = BPF(text=bpf_program)
    
    # 附加到内存函数
    if args.user:
        b.attach_uprobe(name="c", sym="malloc", fn_name="trace_malloc")
        b.attach_uretprobe(name="c", sym="malloc", fn_name="trace_malloc_ret")
        b.attach_uprobe(name="c", sym="calloc", fn_name="trace_calloc")
        b.attach_uretprobe(name="c", sym="calloc", fn_name="trace_calloc_ret")
        b.attach_uprobe(name="c", sym="realloc", fn_name="trace_realloc")
        b.attach_uretprobe(name="c", sym="realloc", fn_name="trace_realloc_ret")
        b.attach_uprobe(name="c", sym="free", fn_name="trace_free")
    
    if args.kernel:
        b.attach_kprobe(event="__kmalloc", fn_name="trace_kmalloc")
        b.attach_kretprobe(event="__kmalloc", fn_name="trace_kmalloc_ret")
        b.attach_kprobe(event="kfree", fn_name="trace_kfree")
    
    # 内存活动
    allocations = {}
    alloc_count = 0
    free_count = 0
    
    # 按堆栈统计
    stack_leak_count = defaultdict(int)
    stack_leak_size = defaultdict(int)
    stack_alloc_count = defaultdict(int)
    
    # 处理用户中断
    def signal_handler(sig, frame):
        print("\n监控被用户中断")
        generate_report(True)
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    
    # 内存事件处理函数
    def process_event(cpu, data, size):
        nonlocal alloc_count, free_count
        
        event = ct.cast(data, ct.POINTER(MemEvent)).contents
        pid = event.pid
        addr = event.addr
        event_size = event.size
        timestamp = event.ts
        stack_id = event.stack_id
        is_alloc = event.is_alloc
        comm = event.comm.decode('utf-8', 'replace')
        
        # 处理分配事件
        if is_alloc:
            alloc_count += 1
            
            # 记录分配信息
            if addr not in allocations:
                alloc = Allocation(addr, event_size, stack_id, timestamp)
                allocations[addr] = alloc
                
                # 获取堆栈
                alloc.stack_trace = get_stack_trace(b, stack_id, pid)
                
                # 更新堆栈统计
                stack_str = "\n".join(alloc.stack_trace)
                stack_alloc_count[stack_str] += 1
            
            if args.show_all:
                ts = datetime.fromtimestamp(timestamp / 1000000000).strftime('%H:%M:%S.%f')
                print(f"[{ts}] 分配: PID {pid} ({comm}) 地址:0x{addr:x} 大小:{human_size(event_size)}")
                
                # 打印堆栈跟踪
                if stack_id >= 0:
                    stack = get_stack_trace(b, stack_id, pid)
                    print(f"堆栈跟踪:")
                    for i, frame in enumerate(stack):
                        print(f"  #{i} {frame}")
                print("")
                
        # 处理释放事件
        else:
            free_count += 1
            
            # 查找分配记录并删除
            if addr in allocations:
                alloc = allocations[addr]
                
                # 更新堆栈统计
                stack_str = "\n".join(alloc.stack_trace)
                stack_leak_count[stack_str] -= 1
                stack_leak_size[stack_str] -= alloc.size
                
                if args.show_all:
                    ts = datetime.fromtimestamp(timestamp / 1000000000).strftime('%H:%M:%S.%f')
                    duration_ms = (timestamp - alloc.timestamp) / 1000000
                    print(f"[{ts}] 释放: PID {pid} ({comm}) 地址:0x{addr:x} 大小:{human_size(alloc.size)} 持有时间:{duration_ms:.2f}ms")
                    
                    # 打印堆栈跟踪
                    if stack_id >= 0:
                        stack = get_stack_trace(b, stack_id, pid)
                        print(f"释放堆栈:")
                        for i, frame in enumerate(stack):
                            print(f"  #{i} {frame}")
                    print("")
                
                # 删除记录
                del allocations[addr]
    
    # 注册回调
    b["mem_events"].open_perf_buffer(process_event)
    
    # 定期报告
    def generate_report(final=False):
        now = time.time()
        active_allocs = len(allocations)
        total_leaked = sum(alloc.size for alloc in allocations.values())
        
        report_type = "最终" if final else "中间"
        print(f"\n===== {report_type}内存报告 =====")
        print(f"跟踪的进程: {'PID ' + str(args.pid) if args.pid else '所有进程'}")
        print(f"最小跟踪大小: {human_size(args.min_size)}")
        print(f"总分配次数: {alloc_count}")
        print(f"总释放次数: {free_count}")
        print(f"活跃分配数: {active_allocs}")
        print(f"总泄漏内存: {human_size(total_leaked)}")
        
        # 如果有活跃分配，打印详细信息
        if active_allocs > 0:
            # 按大小排序的分配
            sorted_allocs = sorted(allocations.values(), key=lambda x: x.size, reverse=True)
            
            print("\n前 {} 个最大的未释放分配:".format(min(args.top, len(sorted_allocs))))
            print(f"{'地址':<14} {'大小':<10} {'分配时间':<20} {'堆栈'}")
            print("-" * 80)
            
            # 获取进程内存映射信息
            maps = get_proc_maps(args.pid) if args.pid > 0 else []
            
            for i, alloc in enumerate(sorted_allocs[:args.top]):
                ts = datetime.fromtimestamp(alloc.timestamp / 1000000000).strftime('%Y-%m-%d %H:%M:%S')
                stack_preview = alloc.stack_trace[0] if alloc.stack_trace else "[无堆栈]"
                
                # 应用堆栈过滤器
                if args.stack_filter and not any(args.stack_filter in frame for frame in alloc.stack_trace):
                    continue
                
                # 查找内存映射
                mapping = find_map_for_addr(alloc.address, maps) if args.pid > 0 else "[未知]"
                
                print(f"0x{alloc.address:<12x} {human_size(alloc.size):<10} {ts:<20} {stack_preview}")
            
            # 按堆栈分组的泄漏
            print("\n按堆栈分组的泄漏:")
            print(f"{'未释放数量':<12} {'总大小':<12} {'分配次数':<12} {'泄漏堆栈'}")
            print("-" * 80)
            
            stack_leaks = []
            for stack_str, count in stack_leak_count.items():
                if count > 0:  # 只显示有泄漏的堆栈
                    # 应用堆栈过滤器
                    if args.stack_filter and args.stack_filter not in stack_str:
                        continue
                    
                    size = stack_leak_size[stack_str]
                    alloc_count = stack_alloc_count[stack_str]
                    
                    # 取堆栈的第一帧作为示例
                    top_frame = stack_str.split('\n')[0] if '\n' in stack_str else stack_str
                    
                    stack_leaks.append((count, size, alloc_count, top_frame, stack_str))
            
            # 按大小排序
            stack_leaks.sort(key=lambda x: x[1], reverse=True)
            
            for i, (count, size, alloc_count, top_frame, stack_str) in enumerate(stack_leaks[:args.top]):
                print(f"{count:<12} {human_size(size):<12} {alloc_count:<12} {top_frame}")
                
                # 显示完整堆栈
                if i < 3:  # 仅显示前3个泄漏的完整堆栈
                    print("完整堆栈:")
                    for j, frame in enumerate(stack_str.split('\n')):
                        if frame:  # 跳过空行
                            print(f"  #{j} {frame}")
                    print("")
    
    # 开始监控
    start_time = time.time()
    print(f"开始监控{'PID ' + str(args.pid) if args.pid else '所有进程'} 的内存分配和释放...")
    print(f"监控持续时间: {args.duration}秒")
    print(f"报告间隔: {args.interval}秒")
    print(f"最小跟踪大小: {human_size(args.min_size)}")
    print(f"开始时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    next_report = start_time + args.interval
    
    try:
        while time.time() - start_time < args.duration:
            b.perf_buffer_poll(timeout=1000)
            
            # 定期报告
            if time.time() >= next_report:
                generate_report()
                next_report = time.time() + args.interval
                
    except KeyboardInterrupt:
        signal_handler(signal.SIGINT, None)
    
    # 最终报告
    generate_report(final=True)
    
    # 清理资源
    b.cleanup()

if __name__ == "__main__":
    main() 