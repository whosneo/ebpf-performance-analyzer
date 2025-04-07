#!/usr/bin/env python3
# 中断分析器 - 使用eBPF监控系统中断处理
#
# 这个程序跟踪系统中的中断处理，记录中断频率、延迟和处理时间，
# 帮助诊断与中断相关的性能问题。

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
#include <linux/irq.h>
#include <linux/irqdesc.h>
#include <linux/interrupt.h>

// 中断跟踪结构
struct irq_key_t {
    u32 irq;           // 中断号
    u32 pid;           // 处理中断的进程ID
    char name[32];     // 中断名称
};

struct irq_val_t {
    u64 count;         // 中断计数
    u64 total_ns;      // 总处理时间
    u64 max_ns;        // 最长处理时间
};

// 存储每个中断的统计信息
BPF_HASH(irq_stats, struct irq_key_t, struct irq_val_t);

// 存储中断处理的开始时间
BPF_HASH(start_times, u64, u64);

// 跟踪中断处理函数的入口
int trace_irq_handler_entry(struct pt_regs *ctx, int irq, struct irqaction *action) {
    // 获取当前时间
    u64 ts = bpf_ktime_get_ns();
    
    // 获取中断处理的线程ID
    u64 id = bpf_get_current_pid_tgid();
    
    // 保存开始时间
    start_times.update(&id, &ts);
    
    return 0;
}

// 跟踪中断处理函数的退出
int trace_irq_handler_exit(struct pt_regs *ctx, int irq, struct irqaction *action, int ret) {
    // 获取当前时间
    u64 ts = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    
    // 获取开始时间
    u64 *start_ts = start_times.lookup(&id);
    if (start_ts == 0) {
        return 0;   // 没有找到开始时间
    }
    
    // 计算处理时间
    u64 delta = ts - *start_ts;
    
    // 准备键值
    struct irq_key_t key = {};
    key.irq = irq;
    key.pid = pid;
    
    // 尝试获取中断名称
    if (action != NULL) {
        bpf_probe_read_str(&key.name, sizeof(key.name), action->name);
    } else {
        __builtin_memcpy(&key.name, "[未知]", 7);
    }
    
    // 更新统计信息
    struct irq_val_t *val = irq_stats.lookup(&key);
    if (val) {
        val->count++;
        val->total_ns += delta;
        if (delta > val->max_ns)
            val->max_ns = delta;
    } else {
        struct irq_val_t new_val = {};
        new_val.count = 1;
        new_val.total_ns = delta;
        new_val.max_ns = delta;
        irq_stats.update(&key, &new_val);
    }
    
    // 清理
    start_times.delete(&id);
    
    return 0;
}

// 跟踪软中断处理
int trace_softirq_entry(struct pt_regs *ctx, unsigned long vec_nr) {
    // 获取当前时间
    u64 ts = bpf_ktime_get_ns();
    
    // 获取软中断处理的线程ID
    u64 id = bpf_get_current_pid_tgid();
    
    // 加上软中断标志 (高位设置为1表示软中断)
    u64 softirq_id = (1ULL << 63) | id;
    
    // 保存开始时间
    start_times.update(&softirq_id, &ts);
    
    return 0;
}

int trace_softirq_exit(struct pt_regs *ctx, unsigned long vec_nr) {
    // 获取当前时间
    u64 ts = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    
    // 加上软中断标志
    u64 softirq_id = (1ULL << 63) | id;
    
    // 获取开始时间
    u64 *start_ts = start_times.lookup(&softirq_id);
    if (start_ts == 0) {
        return 0;   // 没有找到开始时间
    }
    
    // 计算处理时间
    u64 delta = ts - *start_ts;
    
    // 准备键值 - 软中断编号从1000开始，避免与硬中断冲突
    struct irq_key_t key = {};
    key.irq = 1000 + vec_nr;  // 软中断编号
    key.pid = pid;
    
    // 设置软中断名称
    char *softirq_names[] = {
        "HI", "TIMER", "NET_TX", "NET_RX", "BLOCK", 
        "IRQ_POLL", "TASKLET", "SCHED", "HRTIMER", "RCU"
    };
    
    if (vec_nr < 10) {
        char name[32];
        __builtin_memcpy(&name, "SOFTIRQ-", 9);
        __builtin_memcpy(&name[9], softirq_names[vec_nr], 16);
        __builtin_memcpy(&key.name, name, sizeof(key.name));
    } else {
        __builtin_memcpy(&key.name, "SOFTIRQ-UNKNOWN", 16);
    }
    
    // 更新统计信息
    struct irq_val_t *val = irq_stats.lookup(&key);
    if (val) {
        val->count++;
        val->total_ns += delta;
        if (delta > val->max_ns)
            val->max_ns = delta;
    } else {
        struct irq_val_t new_val = {};
        new_val.count = 1;
        new_val.total_ns = delta;
        new_val.max_ns = delta;
        irq_stats.update(&key, &new_val);
    }
    
    // 清理
    start_times.delete(&softirq_id);
    
    return 0;
}
"""

class IrqKey(ct.Structure):
    _fields_ = [
        ("irq", ct.c_uint),
        ("pid", ct.c_uint),
        ("name", ct.c_char * 32),
    ]

class IrqVal(ct.Structure):
    _fields_ = [
        ("count", ct.c_ulonglong),
        ("total_ns", ct.c_ulonglong),
        ("max_ns", ct.c_ulonglong),
    ]

def parse_args():
    parser = argparse.ArgumentParser(
        description="中断分析工具 - 监控系统中断处理")
    parser.add_argument("-d", "--duration", type=int, default=10,
        help="监控持续时间(秒)")
    parser.add_argument("-t", "--top", type=int, default=20,
        help="显示频率最高的前N个中断")
    parser.add_argument("--hardirq", action="store_true",
        help="只显示硬中断")
    parser.add_argument("--softirq", action="store_true",
        help="只显示软中断")
    parser.add_argument("-v", "--verbose", action="store_true",
        help="启用详细日志输出")
    parser.add_argument("-i", "--interval", type=int, default=5,
        help="报告间隔(秒)")
    return parser.parse_args()

def process_irq_stats(irq_stats, args, duration):
    """处理中断统计数据并生成报告"""
    # 创建中断统计列表
    irq_list = []
    try:
        for k, v in irq_stats.items():
            irq = k.irq
            name = k.name.decode('utf-8', 'replace')
            count = v.count
            total_time = v.total_ns
            avg_time = total_time / count if count > 0 else 0
            max_time = v.max_ns
            is_softirq = irq >= 1000
            
            # 根据过滤条件添加
            if (args.hardirq and is_softirq) or (args.softirq and not is_softirq):
                continue
                
            irq_list.append((irq, name, count, avg_time, max_time, total_time, is_softirq))
    except Exception as e:
        logging.error(f"处理中断统计时出错: {str(e)}")
        return None
    
    # 按中断频率排序
    sorted_irqs = sorted(irq_list, key=lambda x: x[2], reverse=True)
    
    # 显示中断统计
    logging.info("\n----- 中断处理统计 (按频率排序) -----")
    logging.info("%-6s %-20s %-10s %-16s %-16s %-10s" % (
        "中断号", "名称", "计数", "平均时间(µs)", "最长时间(µs)", "类型"))
    
    for i, (irq, name, count, avg_time, max_time, total_time, is_softirq) in enumerate(sorted_irqs[:args.top]):
        irq_type = "软中断" if is_softirq else "硬中断"
        if is_softirq:
            irq_num = irq - 1000  # 还原软中断编号
        else:
            irq_num = irq
            
        logging.info("%-6d %-20s %-10d %-16.2f %-16.2f %-10s" % (
            irq_num, name, count, avg_time / 1000, max_time / 1000, irq_type))
    
    # 显示总的中断统计
    hard_irqs = [x for x in irq_list if not x[6]]
    soft_irqs = [x for x in irq_list if x[6]]
    
    total_hard_count = sum(x[2] for x in hard_irqs)
    total_soft_count = sum(x[2] for x in soft_irqs)
    total_hard_time = sum(x[5] for x in hard_irqs)
    total_soft_time = sum(x[5] for x in soft_irqs)
    
    logging.info("\n----- 中断总结 -----")
    logging.info(f"硬中断总数: {total_hard_count} 次, 总处理时间: {total_hard_time/1e9:.6f} 秒")
    logging.info(f"软中断总数: {total_soft_count} 次, 总处理时间: {total_soft_time/1e9:.6f} 秒")
    logging.info(f"中断总数: {total_hard_count + total_soft_count} 次")
    logging.info(f"中断总处理时间: {(total_hard_time + total_soft_time)/1e9:.6f} 秒")
    
    # 显示中断频率
    logging.info(f"硬中断频率: {total_hard_count/duration:.2f} 次/秒")
    logging.info(f"软中断频率: {total_soft_count/duration:.2f} 次/秒")
    logging.info(f"总中断频率: {(total_hard_count + total_soft_count)/duration:.2f} 次/秒")
    
    return sorted_irqs

def main():
    args = parse_args()
    
    # 设置日志
    setup_logging(args.verbose)
    
    # 参数校验
    if not validate_args(args):
        return 1
    
    logging.info("开始监控系统中断处理情况...")
    logging.info(f"监控持续时间: {args.duration}秒")
    logging.info(f"报告间隔: {args.interval}秒")
    if args.hardirq:
        logging.info("仅监控硬中断")
    if args.softirq:
        logging.info("仅监控软中断")
    
    try:
        # 加载eBPF程序
        b = BPF(text=bpf_text)
        
        # 附加到中断处理相关的内核函数
        b.attach_kprobe(event="handle_irq_event_percpu", fn_name="trace_irq_handler_entry")
        b.attach_kretprobe(event="handle_irq_event_percpu", fn_name="trace_irq_handler_exit")
        
        # 附加到软中断处理相关的函数
        b.attach_kprobe(event="__do_softirq", fn_name="trace_softirq_entry")
        b.attach_kretprobe(event="__do_softirq", fn_name="trace_softirq_exit")
        
        # 监控指定的时间
        start_time = datetime.now()
        logging.info(f"开始时间: {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
        
        # 定期报告函数
        next_report = time.time() + args.interval
        
        def periodic_report():
            nonlocal next_report
            if time.time() >= next_report:
                elapsed = (datetime.now() - start_time).total_seconds()
                logging.info(f"\n===== 中间报告 ({elapsed:.1f}秒) =====")
                process_irq_stats(b.get_table("irq_stats"), args, elapsed)
                next_report = time.time() + args.interval
        
        # 监控循环
        try:
            while (datetime.now() - start_time).total_seconds() < args.duration:
                b.perf_buffer_poll(timeout=100)
                periodic_report()
        except KeyboardInterrupt:
            logging.warning("监控被用户中断")
        
        end_time = datetime.now()
        logging.info(f"结束时间: {end_time.strftime('%Y-%m-%d %H:%M:%S')}")
        elapsed = (end_time - start_time).total_seconds()
        logging.info(f"总监控时间: {elapsed:.2f}秒")
        
        # 最终报告
        logging.info("\n===== 最终报告 =====")
        process_irq_stats(b.get_table("irq_stats"), args, elapsed)
        
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