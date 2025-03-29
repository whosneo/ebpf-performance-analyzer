#!/usr/bin/env python3
# CPU性能分析器 - 使用eBPF监控进程CPU使用情况
#
# 这个程序使用eBPF跟踪进程在用户空间和内核空间的CPU使用情况，
# 提供详细的CPU利用率分析和热点函数识别。

import sys
import time
import argparse
from bcc import BPF
from datetime import datetime

# eBPF程序代码
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct key_t {
    u32 pid;
    u32 tgid;
    u64 user_stack_id;
    u64 kernel_stack_id;
    char comm[TASK_COMM_LEN];
};

struct cpu_val {
    u64 runtime_ns;
};

BPF_HASH(cpu_info, struct key_t, struct cpu_val);
BPF_STACK_TRACE(stack_traces, 8192);

int on_task_switch(struct pt_regs *ctx, struct task_struct *prev) {
    u64 now = bpf_ktime_get_ns();
    u64 delta;
    u32 pid = prev->pid;
    u32 tgid = prev->tgid;
    
    // 检查是否是我们关注的PID
    u32 target_pid = PID_FILTER;
    if (target_pid > 0 && tgid != target_pid) {
        return 0;
    }

    // 获取任务名称
    struct key_t key = {};
    key.pid = pid;
    key.tgid = tgid;
    
    bpf_get_current_comm(&key.comm, sizeof(key.comm));
    
    // 获取用户和内核堆栈ID
    key.user_stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);
    key.kernel_stack_id = stack_traces.get_stackid(ctx, 0);

    // 记录CPU使用时间
    u64 runtime = prev->se.sum_exec_runtime;
    struct cpu_val *val = cpu_info.lookup(&key);
    if (val) {
        delta = runtime - val->runtime_ns;
        val->runtime_ns = runtime;
    } else {
        struct cpu_val new_val = {};
        new_val.runtime_ns = runtime;
        cpu_info.update(&key, &new_val);
        delta = 0;
    }

    return 0;
}
"""

def parse_args():
    parser = argparse.ArgumentParser(
        description="CPU性能分析工具 - 监控进程CPU使用情况")
    parser.add_argument("pid", type=int, nargs="?", default=0,
        help="要监控的进程ID (0表示所有进程)")
    parser.add_argument("-d", "--duration", type=int, default=10,
        help="监控持续时间(秒)")
    parser.add_argument("-t", "--top", type=int, default=10,
        help="显示CPU占用最高的前N个函数")
    return parser.parse_args()

def stack_id_to_string(bpf, stack_id, tgid):
    if stack_id < 0:
        return "未知堆栈"
    stack = list(bpf.get_table("stack_traces").walk(stack_id))
    if not stack:
        return "空堆栈"
    try:
        stack_trace = []
        for addr in stack:
            stack_trace.append(f"{bpf.sym(addr, tgid).decode('utf-8', 'replace')} [{addr:x}]")
        return "\n\t".join(stack_trace)
    except:
        return f"无法解析堆栈ID {stack_id}"

def main():
    args = parse_args()
    
    print(f"开始监控{'PID ' + str(args.pid) if args.pid else '所有进程'} 的CPU使用情况...")
    print(f"监控持续时间: {args.duration}秒")
    
    # 替换eBPF程序中的PID过滤器
    bpf_program = bpf_text.replace('PID_FILTER', str(args.pid))
    
    # 加载eBPF程序
    b = BPF(text=bpf_program)
    b.attach_kprobe(event="finish_task_switch", fn_name="on_task_switch")
    
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
    
    # 处理和分析收集的数据
    cpu_info = b.get_table("cpu_info")
    if len(cpu_info) == 0:
        print("未收集到数据，请检查PID是否正确或程序是否有足够的执行时间")
        return
    
    # 汇总每个堆栈的CPU时间并排序
    stacks = {}
    for k, v in cpu_info.items():
        key_str = f"{k.comm.decode('utf-8', 'replace')}:{k.tgid}"
        user_stack = stack_id_to_string(b, k.user_stack_id, k.tgid)
        kernel_stack = stack_id_to_string(b, k.kernel_stack_id, k.tgid)
        
        stack_key = f"{key_str}|{user_stack}|{kernel_stack}"
        if stack_key in stacks:
            stacks[stack_key] += v.runtime_ns
        else:
            stacks[stack_key] = v.runtime_ns
    
    # 排序并显示前N个CPU占用最高的堆栈
    sorted_stacks = sorted(stacks.items(), key=lambda x: x[1], reverse=True)
    
    print("\n----- CPU使用情况排名前 %d 的进程和函数 -----" % args.top)
    for i, (stack_key, runtime) in enumerate(sorted_stacks[:args.top]):
        process, user_stack, kernel_stack = stack_key.split('|', 2)
        print(f"\n#{i+1} {process} - CPU时间: {runtime/1e9:.6f}秒")
        print("\n用户空间堆栈:")
        print(f"\t{user_stack}")
        print("\n内核空间堆栈:")
        print(f"\t{kernel_stack}")
        print("-" * 80)
    
    print(f"\n共分析了 {len(stacks)} 个独特的调用堆栈")
    
    # 清理资源
    b.cleanup()

if __name__ == "__main__":
    if not BPF.support_raw_tracepoint():
        print("警告: 内核版本可能不完全支持eBPF功能，某些特性可能无法正常工作")
    
    main() 