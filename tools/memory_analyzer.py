#!/usr/bin/env python3
# 内存分析器 - 使用eBPF跟踪内存分配和释放
#
# 这个程序使用eBPF跟踪进程的内存分配和释放情况，
# 提供内存泄漏检测和内存使用模式分析。

import sys
import time
import argparse
import os
from bcc import BPF
from datetime import datetime
import ctypes as ct
import logging

# 导入公共模块
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
from src.ebpf_common import BaseAnalyzer, setup_signal_handler, human_readable_size

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

def get_stack_trace(bpf, stack_id):
    """将堆栈ID转换为可读字符串"""
    try:
        if stack_id < 0:
            return "未知堆栈"
        
        stack = list(bpf.get_table("stack_traces").walk(stack_id))
        if not stack:
            return "空堆栈"
        
        kernel_stack = []
        for addr in stack:
            kernel_stack.append(f"{bpf.ksym(addr).decode('utf-8', 'replace')} [{addr:x}]")
        
        return "\n\t".join(kernel_stack)
    except Exception as e:
        logging.warning(f"解析堆栈ID {stack_id} 时出错: {str(e)}")
        return f"无法解析堆栈ID {stack_id}"

def analyze_memory_usage(bpf, args, final=False):
    """分析内存使用情况并输出报告"""
    
    # 从BPF表获取数据
    stack_stats = bpf.get_table("stack_stats")
    addr_table = bpf.get_table("addr_info")
    
    if len(stack_stats) == 0:
        logging.warning("未收集到内存分配数据，请检查PID是否正确或程序是否有内存活动")
        return
    
    # 计算总体统计信息
    total_allocs = 0
    total_frees = 0
    total_active_size = 0
    stack_data = []
    
    for stack_id, stat in stack_stats.items():
        stat_val = ct.cast(stat, ct.POINTER(StackStat)).contents
        
        # 计算总计
        total_allocs += stat_val.alloc_count
        total_frees += stat_val.free_count
        total_active_size += stat_val.total_size
        
        # 是否有泄漏
        active_allocs = stat_val.alloc_count - stat_val.free_count
        
        # 如果只显示泄漏且该堆栈无泄漏，则跳过
        if args.leaks and active_allocs <= 0:
            continue
        
        # 获取堆栈信息
        stack_trace = get_stack_trace(bpf, stack_id.value)
        
        # 添加到结果列表
        stack_data.append({
            'stack_id': stack_id.value,
            'alloc_count': stat_val.alloc_count,
            'free_count': stat_val.free_count,
            'active_allocs': active_allocs,
            'total_size': stat_val.total_size,
            'stack_trace': stack_trace,
            'is_leak': active_allocs > 0
        })
    
    # 排序堆栈数据 - 按内存大小倒序
    stack_data.sort(key=lambda x: x['total_size'], reverse=True)
    
    # 显示总体统计
    if final:
        print("\n===== 内存分配统计 =====")
    else:
        print("\n===== 内存分配中间统计 =====")
        
    print(f"总分配次数: {total_allocs}")
    print(f"总释放次数: {total_frees}")
    print(f"未释放分配次数: {total_allocs - total_frees}")
    print(f"总活跃内存: {human_readable_size(total_active_size)}")
    
    # 显示堆栈详情
    limit = min(args.top, len(stack_data))
    print(f"\n===== 内存占用前 {limit} 的堆栈 =====")
    
    for i, data in enumerate(stack_data[:limit]):
        leak_text = "[可能泄漏] " if data['is_leak'] else ""
        print(f"#{i+1} {leak_text}{human_readable_size(data['total_size'])}")
        print(f"    分配: {data['alloc_count']}, 释放: {data['free_count']}, 差值: {data['active_allocs']}")
        print("调用堆栈:")
        print(f"    {data['stack_trace']}")
        print()

class MemoryAnalyzer(BaseAnalyzer):
    """内存分析器类"""
    
    def __init__(self):
        super().__init__(
            name="内存分析器",
            description="跟踪内存分配和释放，分析内存使用模式"
        )
    
    def setup_args(self):
        """设置命令行参数解析器"""
        parser = super().setup_args()
        parser.add_argument("-l", "--leaks", action="store_true",
            help="只显示可能的内存泄漏")
        return parser
    
    def run(self):
        """运行内存分析器"""
        # 解析参数
        self.parse_args()
        if not self.validate_args():
            return 1
        
        # 设置日志
        self.setup_logging()
        
        try:
            # 加载BPF程序
            logging.info(f"开始监控{'PID ' + str(self.args.pid) if self.args.pid > 0 else '所有进程'}的内存分配情况...")
            logging.info(f"监控持续时间: {self.args.duration}秒")
            logging.info(f"开始时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            
            # 替换PID占位符
            bpf_code = bpf_text.replace('PID_FILTER', str(self.args.pid))
            b = self.load_bpf(bpf_code)
            
            # 附加kprobe
            b.attach_kprobe(event="__kmalloc", fn_name="trace_alloc")
            b.attach_kretprobe(event="__kmalloc", fn_name="trace_alloc_ret")
            b.attach_kprobe(event="kfree", fn_name="trace_free")
            
            # 设置信号处理
            setup_signal_handler(lambda: self.cleanup())
            
            # 设置中间报告回调
            start_time = time.time()
            next_report = start_time + self.args.interval
            
            # 监控循环
            while time.time() - start_time < self.args.duration:
                try:
                    time.sleep(1)
                    if time.time() >= next_report:
                        analyze_memory_usage(b, self.args)
                        next_report = time.time() + self.args.interval
                except KeyboardInterrupt:
                    break
            
            # 显示最终报告
            end_time = time.time()
            logging.info(f"结束时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            logging.info(f"总监控时间: {end_time - start_time:.2f}秒")
            analyze_memory_usage(b, self.args, final=True)
            
            return 0
            
        except Exception as e:
            logging.error(f"运行内存分析器时发生错误: {str(e)}")
            return 1
        finally:
            self.cleanup()

if __name__ == "__main__":
    analyzer = MemoryAnalyzer()
    sys.exit(analyzer.run()) 