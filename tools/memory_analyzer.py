#!/usr/bin/env python3
# 内存分析器 - 使用eBPF跟踪内存分配和释放
#
# 这个程序使用eBPF跟踪进程的内存分配和释放情况，
# 提供内存泄漏检测和内存使用模式分析。

import sys
import time
import argparse
from bcc import BPF
from datetime import datetime
import ctypes as ct

# eBPF程序代码
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/mm.h>
#include <linux/sched.h>

struct alloc_info_t {
    u64 size;           // 请求的内存大小
    u64 timestamp_ns;   // 分配时间戳
    u32 stack_id;       // 堆栈跟踪ID
};

struct addr_info_t {
    u64 address;        // 内存地址
    u64 size;           // 分配大小
    u32 stack_id;       // 堆栈ID
};

// 存储活跃的内存分配
BPF_HASH(allocs, u64, struct alloc_info_t);

// 存储每个堆栈的分配计数和大小
struct stack_stat_t {
    u64 alloc_count;  // 分配次数
    u64 free_count;   // 释放次数
    u64 total_size;   // 当前总大小
};
BPF_HASH(stack_stats, u32, struct stack_stat_t);

// 使用地址范围保存堆栈跟踪
BPF_HASH(addr_info, u64, struct addr_info_t);

// 堆栈跟踪
BPF_STACK_TRACE(stack_traces, 16384);

// 跟踪kmalloc调用
int trace_alloc(struct pt_regs *ctx, size_t size) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    // 检查目标PID
    u32 target_pid = PID_FILTER;
    if (target_pid > 0 && pid != target_pid) {
        return 0;
    }
    
    // 获取堆栈ID
    u32 stack_id = stack_traces.get_stackid(ctx, 0);
    
    // 更新堆栈统计
    struct stack_stat_t *stack_stat = stack_stats.lookup(&stack_id);
    if (stack_stat == NULL) {
        struct stack_stat_t new_stat = {0};
        new_stat.alloc_count = 1;
        new_stat.total_size = size;
        stack_stats.update(&stack_id, &new_stat);
    } else {
        stack_stat->alloc_count++;
        stack_stat->total_size += size;
    }
    
    // 保存分配信息，在kretprobe中使用
    u64 now = bpf_ktime_get_ns();
    struct alloc_info_t alloc_info = {};
    alloc_info.size = size;
    alloc_info.timestamp_ns = now;
    alloc_info.stack_id = stack_id;
    
    u64 pid_tgid = bpf_get_current_pid_tgid();
    allocs.update(&pid_tgid, &alloc_info);
    
    return 0;
}

// 跟踪kmalloc的返回
int trace_alloc_ret(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct alloc_info_t *alloc_info = allocs.lookup(&pid_tgid);
    if (alloc_info == NULL) {
        return 0; // 可能是过滤掉的PID调用
    }
    
    // 获取分配的内存地址
    u64 addr = PT_REGS_RC(ctx);
    if (addr == 0) {
        // 分配失败，从哈希表中删除临时信息
        allocs.delete(&pid_tgid);
        return 0;
    }
    
    // 保存地址信息
    struct addr_info_t addr_data = {};
    addr_data.address = addr;
    addr_data.size = alloc_info->size;
    addr_data.stack_id = alloc_info->stack_id;
    addr_info.update(&addr, &addr_data);
    
    // 清理临时信息
    allocs.delete(&pid_tgid);
    
    return 0;
}

// 跟踪kfree调用
int trace_free(struct pt_regs *ctx, void *addr) {
    u64 address = (u64)addr;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    // 检查目标PID
    u32 target_pid = PID_FILTER;
    if (target_pid > 0 && pid != target_pid) {
        return 0;
    }
    
    // 查找地址信息
    struct addr_info_t *addr_data = addr_info.lookup(&address);
    if (addr_data == NULL) {
        return 0; // 可能不是我们跟踪的分配
    }
    
    // 获取当前堆栈和之前的分配堆栈
    u32 free_stack_id = stack_traces.get_stackid(ctx, 0);
    u32 alloc_stack_id = addr_data->stack_id;
    
    // 更新分配堆栈的统计信息
    struct stack_stat_t *alloc_stat = stack_stats.lookup(&alloc_stack_id);
    if (alloc_stat != NULL) {
        alloc_stat->free_count++;
        if (alloc_stat->total_size >= addr_data->size) {
            alloc_stat->total_size -= addr_data->size;
        }
    }
    
    // 从跟踪中删除该地址
    addr_info.delete(&address);
    
    return 0;
}
"""

class StackStat(ct.Structure):
    _fields_ = [
        ("alloc_count", ct.c_ulonglong),
        ("free_count", ct.c_ulonglong),
        ("total_size", ct.c_ulonglong),
    ]

class AddrInfo(ct.Structure):
    _fields_ = [
        ("address", ct.c_ulonglong),
        ("size", ct.c_ulonglong),
        ("stack_id", ct.c_uint),
    ]

def parse_args():
    parser = argparse.ArgumentParser(
        description="内存分析工具 - 跟踪内存分配和释放")
    parser.add_argument("pid", type=int, nargs="?", default=0,
        help="要监控的进程ID (0表示所有进程)")
    parser.add_argument("-d", "--duration", type=int, default=10,
        help="监控持续时间(秒)")
    parser.add_argument("-t", "--top", type=int, default=10,
        help="显示内存占用最高的前N个堆栈")
    parser.add_argument("-l", "--leaks", action="store_true",
        help="只显示可能的内存泄漏")
    return parser.parse_args()

def get_stack_trace(bpf, stack_id):
    if stack_id < 0:
        return "未知堆栈"
    
    stack = list(bpf.get_table("stack_traces").walk(stack_id))
    if not stack:
        return "空堆栈"
    
    try:
        kernel_stack = []
        for addr in stack:
            kernel_stack.append(f"{bpf.ksym(addr).decode('utf-8', 'replace')} [{addr:x}]")
        return "\n\t".join(kernel_stack)
    except:
        return f"无法解析堆栈ID {stack_id}"

def main():
    args = parse_args()
    
    print(f"开始监控{'PID ' + str(args.pid) if args.pid else '所有进程'} 的内存分配情况...")
    print(f"监控持续时间: {args.duration}秒")
    
    # 替换eBPF程序中的PID过滤器
    bpf_program = bpf_text.replace('PID_FILTER', str(args.pid))
    
    # 加载eBPF程序
    b = BPF(text=bpf_program)
    b.attach_kprobe(event="__kmalloc", fn_name="trace_alloc")
    b.attach_kretprobe(event="__kmalloc", fn_name="trace_alloc_ret")
    b.attach_kprobe(event="kfree", fn_name="trace_free")
    
    # 监控指定的时间
    start_time = datetime.now()
    print(f"开始时间: {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
    
    try:
        time.sleep(args.duration)
    except KeyboardInterrupt:
        print("监控被用户中断")
    
    end_time = datetime.now()
    print(f"结束时间: {end_time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"总监控时间: {(end_time - start_time).total_seconds():.2f}秒")
    
    # 获取数据
    stack_stats = b.get_table("stack_stats")
    addr_info = b.get_table("addr_info")
    
    # 统计数据
    total_allocs = 0
    total_frees = 0
    total_mem = 0
    leaked_mem = 0
    active_allocs = 0
    
    # 收集堆栈统计信息
    stacks_data = []
    for stack_id, stat in stack_stats.items():
        stat_val = ct.cast(stat, ct.POINTER(StackStat)).contents
        
        # 计算堆栈的内存泄漏
        alloc_count = stat_val.alloc_count
        free_count = stat_val.free_count
        current_size = stat_val.total_size
        
        # 更新总体统计信息
        total_allocs += alloc_count
        total_frees += free_count
        total_mem += current_size
        
        if alloc_count > free_count:
            leaked_allocs = alloc_count - free_count
            active_allocs += leaked_allocs
            
            # 收集堆栈信息
            stack_trace = get_stack_trace(b, stack_id.value)
            
            # 判断是否可能的内存泄漏
            possible_leak = (alloc_count > free_count + 2) 
            
            # 如果只查看泄漏，且不是可能的泄漏，则跳过
            if args.leaks and not possible_leak:
                continue
            
            stacks_data.append({
                "stack_id": stack_id.value,
                "stack_trace": stack_trace,
                "alloc_count": alloc_count,
                "free_count": free_count,
                "diff": alloc_count - free_count,
                "size": current_size,
                "is_leak": possible_leak
            })
    
    # 按内存大小排序
    stacks_data.sort(key=lambda x: x["size"], reverse=True)
    
    # 显示泄漏检测结果
    print("\n===== 内存分配统计 =====")
    print(f"总分配次数: {total_allocs}")
    print(f"总释放次数: {total_frees}")
    print(f"未释放分配次数: {active_allocs}")
    print(f"总活跃内存: {total_mem/1024:.2f} KB")
    
    # 显示前N个内存占用最大的堆栈
    print(f"\n===== 内存占用前 {args.top} 的堆栈 =====")
    for i, data in enumerate(stacks_data[:args.top]):
        if args.leaks and not data["is_leak"]:
            continue
            
        print(f"\n#{i+1} {'[可能泄漏] ' if data['is_leak'] else ''}{data['size']/1024:.2f} KB")
        print(f"    分配: {data['alloc_count']}, 释放: {data['free_count']}, 差值: {data['diff']}")
        print("\n调用堆栈:")
        print(f"\t{data['stack_trace']}")
        print("-" * 80)
    
    # 显示活跃的地址信息数量
    print(f"\n当前跟踪的活跃内存分配: {len(addr_info)} 个")
    
    # 清理资源
    b.cleanup()

if __name__ == "__main__":
    if not BPF.support_kfunc():
        print("警告: 内核版本可能不完全支持eBPF kfunc功能，某些特性可能无法正常工作")
    
    main() 