#!/usr/bin/env python3
# 页面错误分析器 - 使用eBPF监控进程页面错误情况
#
# 这个程序跟踪进程的主要页面错误(major fault)和次要页面错误(minor fault)，
# 提供详细的内存页面访问和换页活动分析。

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

# eBPF程序代码
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

// 页面错误统计结构
struct fault_stat {
    u64 major_faults;    // 主要页面错误(需要磁盘I/O)
    u64 minor_faults;    // 次要页面错误(不需要磁盘I/O)
};

// 存储每个进程的页面错误统计
BPF_HASH(fault_stats, u32, struct fault_stat);

// 存储每个堆栈的页面错误统计
struct stack_fault_stat {
    u64 major_faults;
    u64 minor_faults;
    u32 pid;
    char comm[TASK_COMM_LEN];
};
BPF_HASH(stack_fault_stats, u32, struct stack_fault_stat);

// 堆栈跟踪
BPF_STACK_TRACE(stack_traces, 8192);

// 跟踪主要页面错误(major fault)
int trace_major_fault(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tgid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    
    // 检查目标PID
    u32 target_pid = PID_FILTER;
    if (target_pid > 0 && tgid != target_pid) {
        return 0;
    }
    
    // 获取堆栈ID
    u32 stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);
    
    // 获取进程名称
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(&comm, sizeof(comm));
    
    // 更新进程级统计
    struct fault_stat *stats = fault_stats.lookup(&tgid);
    if (stats == NULL) {
        struct fault_stat new_stats = {};
        new_stats.major_faults = 1;
        fault_stats.update(&tgid, &new_stats);
    } else {
        stats->major_faults++;
    }
    
    // 更新堆栈级统计
    struct stack_fault_stat *stack_stats = stack_fault_stats.lookup(&stack_id);
    if (stack_stats == NULL) {
        struct stack_fault_stat new_stats = {};
        new_stats.major_faults = 1;
        new_stats.pid = tgid;
        __builtin_memcpy(&new_stats.comm, comm, sizeof(comm));
        stack_fault_stats.update(&stack_id, &new_stats);
    } else {
        stack_stats->major_faults++;
    }
    
    return 0;
}

// 跟踪次要页面错误(minor fault)
int trace_minor_fault(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tgid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    
    // 检查目标PID
    u32 target_pid = PID_FILTER;
    if (target_pid > 0 && tgid != target_pid) {
        return 0;
    }
    
    // 获取堆栈ID
    u32 stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);
    
    // 获取进程名称
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(&comm, sizeof(comm));
    
    // 更新进程级统计
    struct fault_stat *stats = fault_stats.lookup(&tgid);
    if (stats == NULL) {
        struct fault_stat new_stats = {};
        new_stats.minor_faults = 1;
        fault_stats.update(&tgid, &new_stats);
    } else {
        stats->minor_faults++;
    }
    
    // 更新堆栈级统计
    struct stack_fault_stat *stack_stats = stack_fault_stats.lookup(&stack_id);
    if (stack_stats == NULL) {
        struct stack_fault_stat new_stats = {};
        new_stats.minor_faults = 1;
        new_stats.pid = tgid;
        __builtin_memcpy(&new_stats.comm, comm, sizeof(comm));
        stack_fault_stats.update(&stack_id, &new_stats);
    } else {
        stack_stats->minor_faults++;
    }
    
    return 0;
}
"""

class FaultStat(ct.Structure):
    _fields_ = [
        ("major_faults", ct.c_ulonglong),
        ("minor_faults", ct.c_ulonglong),
    ]

class StackFaultStat(ct.Structure):
    _fields_ = [
        ("major_faults", ct.c_ulonglong),
        ("minor_faults", ct.c_ulonglong),
        ("pid", ct.c_uint),
        ("comm", ct.c_char * 16),
    ]

def parse_args():
    parser = argparse.ArgumentParser(
        description="页面错误分析工具 - 监控进程换页活动")
    parser.add_argument("pid", type=int, nargs="?", default=0,
        help="要监控的进程ID (0表示所有进程)")
    parser.add_argument("-d", "--duration", type=int, default=10,
        help="监控持续时间(秒)")
    parser.add_argument("-i", "--interval", type=int, default=5,
        help="报告间隔(秒)")
    parser.add_argument("-t", "--top", type=int, default=10,
        help="显示页面错误最多的前N个堆栈")
    parser.add_argument("-v", "--verbose", action="store_true",
        help="启用详细日志输出")
    return parser.parse_args()

def validate_page_fault_args(args):
    """验证页面错误分析器参数"""
    if args.duration <= 0:
        logging.error("监控时长必须大于0")
        return False
    if args.top <= 0:
        logging.error("显示的堆栈数量必须大于0")
        return False
    if args.interval <= 0:
        logging.error("报告间隔必须大于0")
        return False
    return True

def stack_id_to_string(bpf, stack_id):
    try:
        if stack_id < 0:
            return "未知堆栈"
        
        stack = list(bpf.get_table("stack_traces").walk(stack_id))
        if not stack:
            return "空堆栈"
        
        stack_trace = []
        for addr in stack:
            sym = bpf.sym(addr, -1).decode('utf-8', 'replace')
            stack_trace.append(f"{sym} [{addr:x}]")
        return "\n\t".join(stack_trace)
    except Exception as e:
        logging.error(f"解析堆栈ID {stack_id} 时出错: {str(e)}")
        return f"无法解析堆栈ID {stack_id}"

def generate_page_fault_report(b, args, final=False):
    """生成页面错误报告"""
    try:
        # 处理和分析收集的数据
        process_stats = {}
        for k, v in b["fault_stats"].items():
            pid = k.value
            if pid in process_stats:
                process_stats[pid]["major_faults"] += v.major_faults
                process_stats[pid]["minor_faults"] += v.minor_faults
            else:
                process_stats[pid] = {
                    "major_faults": v.major_faults,
                    "minor_faults": v.minor_faults,
                    "comm": ""
                }
        
        # 获取进程名称
        stack_stats = b["stack_fault_stats"]
        for stack_id, stats in stack_stats.items():
            pid = stats.pid
            if pid in process_stats and not process_stats[pid]["comm"]:
                process_stats[pid]["comm"] = stats.comm
        
        # 按总页面错误数排序并显示进程级统计
        report_type = "最终" if final else "中间"
        logging.info(f"\n----- {report_type}进程页面错误统计 -----")
        logging.info("%-6s %-16s %-12s %-12s %-12s" % (
            "PID", "进程名", "主要错误", "次要错误", "总计"))
        
        sorted_pids = sorted(process_stats.items(), 
                             key=lambda x: x[1]["major_faults"] + x[1]["minor_faults"], 
                             reverse=True)
        
        for pid, stats in sorted_pids[:args.top]:
            if pid != 0:  # 过滤掉PID 0
                total = stats["major_faults"] + stats["minor_faults"]
                logging.info("%-6d %-16s %-12d %-12d %-12d" % (
                    pid, stats["comm"].decode('utf-8', 'replace') if stats["comm"] else "[未知]", 
                    stats["major_faults"], stats["minor_faults"], total))
        
        # 如果是最终报告，还显示堆栈级统计
        if final:
            # 显示堆栈级统计
            logging.info(f"\n----- 页面错误按堆栈分组的前 {args.top} 名 -----")
            
            # 创建(堆栈ID, 统计)的列表并排序
            stack_list = []
            for stack_id, stats in stack_stats.items():
                total_faults = stats.major_faults + stats.minor_faults
                comm = stats.comm.decode('utf-8', 'replace')
                stack_list.append((stack_id.value, stats.pid, comm, stats.major_faults, stats.minor_faults, total_faults))
            
            # 按总页面错误排序
            sorted_stacks = sorted(stack_list, key=lambda x: x[5], reverse=True)
            
            for i, (stack_id, pid, comm, major, minor, total) in enumerate(sorted_stacks[:args.top]):
                logging.info(f"\n#{i+1} 进程: {comm} (PID: {pid})")
                logging.info(f"主要页面错误: {major}, 次要页面错误: {minor}, 总计: {total}")
                logging.info("\n调用堆栈:")
                stack_trace = stack_id_to_string(b, stack_id)
                logging.info(f"\t{stack_trace}")
                logging.info("-" * 80)
        
        return sorted_pids
    except Exception as e:
        logging.error(f"生成页面错误报告时出错: {str(e)}")
        return None

def main():
    args = parse_args()
    
    # 设置日志
    setup_logging(args.verbose)
    
    # 参数校验
    if not validate_page_fault_args(args):
        return 1
    
    logging.info(f"开始监控{'PID ' + str(args.pid) if args.pid else '所有进程'} 的页面错误情况...")
    logging.info(f"监控持续时间: {args.duration}秒")
    logging.info(f"报告间隔: {args.interval}秒")
    logging.info(f"显示页面错误最多的前 {args.top} 个堆栈")
    
    try:
        # 替换eBPF程序中的PID过滤器
        bpf_program = bpf_text.replace('PID_FILTER', str(args.pid))
        
        # 加载eBPF程序
        b = BPF(text=bpf_program)
        
        # 定义用于清理资源的函数
        def cleanup():
            if 'b' in locals():
                b.cleanup()
        
        # 设置信号处理器
        setup_signal_handler(cleanup)
        
        # 附加到页面错误相关的内核函数
        b.attach_kprobe(event="__handle_mm_fault", fn_name="trace_major_fault")
        b.attach_kprobe(event="handle_pte_fault", fn_name="trace_minor_fault")
        
        # 监控指定的时间
        start_time = datetime.now()
        logging.info(f"开始时间: {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
        
        # 定义定期报告函数
        next_report = time.time() + args.interval
        
        def periodic_report():
            nonlocal next_report
            if time.time() >= next_report:
                elapsed = (datetime.now() - start_time).total_seconds()
                logging.info(f"\n===== 中间报告 ({elapsed:.1f}秒) =====")
                generate_page_fault_report(b, args, final=False)
                next_report = time.time() + args.interval
        
        try:
            # 使用轮询方式而不是简单的sleep，这样可以定期生成报告
            while (datetime.now() - start_time).total_seconds() < args.duration:
                time.sleep(0.1)  # 短睡眠，让CPU喘息
                periodic_report()
        except KeyboardInterrupt:
            logging.warning("监控被用户中断")
        
        end_time = datetime.now()
        logging.info(f"结束时间: {end_time.strftime('%Y-%m-%d %H:%M:%S')}")
        elapsed = (end_time - start_time).total_seconds()
        logging.info(f"总监控时间: {elapsed:.2f}秒")
        
        # 生成最终报告
        logging.info("\n===== 最终页面错误分析报告 =====")
        generate_page_fault_report(b, args, final=True)
        
    except Exception as e:
        logging.exception(f"执行过程中发生错误: {str(e)}")
        return 1
    finally:
        # 清理资源
        if 'b' in locals():
            b.cleanup()
    
    return 0

if __name__ == "__main__":
    if not BPF.support_raw_tracepoint():
        logging.warning("警告: 内核版本可能不完全支持eBPF功能，某些特性可能无法正常工作")
    
    exit_code = main()
    sys.exit(exit_code) 