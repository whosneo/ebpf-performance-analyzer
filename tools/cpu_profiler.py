#!/usr/bin/env python3
# CPU性能分析器 - 使用eBPF监控进程CPU使用情况
#
# 这个程序使用eBPF跟踪进程在用户空间和内核空间的CPU使用情况，
# 提供详细的CPU利用率分析和热点函数识别。

import sys
import time
import argparse
import os
from bcc import BPF
from datetime import datetime
import logging

# 导入通用功能模块
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
from src.ebpf_common import setup_signal_handler, BaseAnalyzer


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

def format_time_ns(ns):
    """将纳秒转换为人类可读的时间格式"""
    if ns < 1000:
        return f"{ns:.2f} ns"
    elif ns < 1000000:
        return f"{ns/1000:.2f} μs"
    elif ns < 1000000000:
        return f"{ns/1000000:.2f} ms"
    else:
        return f"{ns/1000000000:.2f} s"

def stack_id_to_string(bpf, stack_id, tgid):
    """将堆栈ID转换为可读字符串"""
    if stack_id < 0:
        return "未知堆栈"
    try:
        stack = list(bpf.get_table("stack_traces").walk(stack_id))
        if not stack:
            return "空堆栈"
        
        stack_trace = []
        for addr in stack:
            try:
                sym = bpf.sym(addr, tgid).decode('utf-8', 'replace')
                stack_trace.append(f"{sym} [{addr:x}]")
            except Exception as e:
                stack_trace.append(f"[地址解析错误: {addr:x}]")
        return "\n\t".join(stack_trace)
    except Exception as e:
        logging.warning(f"解析堆栈ID {stack_id} 时出错: {str(e)}")
        return f"无法解析堆栈ID {stack_id}"

def process_data(b, args, stack_mode):
    """处理采集的数据，返回处理后的堆栈信息"""
    stacks = {}
    cpu_info = b.get_table("cpu_info")
    if len(cpu_info) == 0:
        logging.warning("未收集到数据，请检查PID是否正确或程序是否有足够的执行时间")
        return stacks
    
    # 处理堆栈数据
    for k, v in cpu_info.items():
        try:
            key_str = f"{k.comm.decode('utf-8', 'replace')}:{k.tgid}"
            
            # 根据堆栈模式处理
            if stack_mode == 'user' or stack_mode == 'both':
                user_stack = stack_id_to_string(b, k.user_stack_id, k.tgid)
            else:
                user_stack = "[跳过用户堆栈]"
                
            if stack_mode == 'kernel' or stack_mode == 'both':
                kernel_stack = stack_id_to_string(b, k.kernel_stack_id, k.tgid)
            else:
                kernel_stack = "[跳过内核堆栈]"
            
            stack_key = f"{key_str}|{user_stack}|{kernel_stack}"
            if stack_key in stacks:
                stacks[stack_key] += v.runtime_ns
            else:
                stacks[stack_key] = v.runtime_ns
        except Exception as e:
            logging.error(f"处理堆栈数据时发生错误: {str(e)}")
    
    return stacks

def display_report(b, args, final=False):
    """显示CPU使用报告"""
    stacks = process_data(b, args, args.stack_mode)
    
    if not stacks:
        return
    
    # 按CPU使用时间排序
    sorted_stacks = sorted(stacks.items(), key=lambda x: x[1], reverse=True)
    
    if final:
        print("\n----- CPU使用情况排名前 %d 的进程和函数 -----" % args.top)
    else:
        print("\n----- 中间报告：CPU使用情况排名前 %d 的进程和函数 -----" % args.top)
    
    # 显示前N个CPU占用最高的堆栈
    for i, (stack_key, runtime_ns) in enumerate(sorted_stacks[:args.top]):
        parts = stack_key.split('|')
        if len(parts) >= 3:
            process = parts[0]
            user_stack = parts[1]
            kernel_stack = parts[2]
            
            print(f"#{i+1} {process} - CPU时间: {format_time_ns(runtime_ns)}")
            if user_stack != "[跳过用户堆栈]":
                print("用户空间堆栈:")
                print(f"\t{user_stack}")
            if kernel_stack != "[跳过内核堆栈]":
                print("内核空间堆栈:")
                print(f"\t{kernel_stack}")
            print()

class CPUProfiler(BaseAnalyzer):
    """CPU性能分析器类"""
    
    def __init__(self):
        super().__init__(
            name="CPU性能分析器",
            description="监控进程CPU使用情况，识别热点函数"
        )
    
    def setup_args(self):
        """设置命令行参数解析器"""
        parser = super().setup_args()
        parser.add_argument("--stack-mode", type=str, choices=['user', 'kernel', 'both'], default='both',
            help="堆栈跟踪模式: user=仅用户空间, kernel=仅内核空间, both=两者")
        return parser
    
    def run(self):
        """运行CPU分析器"""
        # 解析参数
        self.parse_args()
        if not self.validate_args():
            return 1
        
        # 设置日志
        self.setup_logging()
        
        try:
            # 加载BPF程序
            logging.info(f"开始监控{'PID ' + str(self.args.pid) if self.args.pid > 0 else '所有进程'}的CPU使用情况...")
            logging.info(f"监控持续时间: {self.args.duration}秒")
            logging.info(f"开始时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            
            # 替换PID占位符
            bpf_code = bpf_text.replace('PID_FILTER', str(self.args.pid))
            b = self.load_bpf(bpf_code)
            
            # 附加kprobe
            b.attach_kprobe(event="finish_task_switch", fn_name="on_task_switch")
            
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
                        display_report(b, self.args)
                        next_report = time.time() + self.args.interval
                except KeyboardInterrupt:
                    break
            
            # 显示最终报告
            end_time = time.time()
            logging.info(f"结束时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            logging.info(f"总监控时间: {end_time - start_time:.2f}秒")
            display_report(b, self.args, final=True)
            
            return 0
            
        except Exception as e:
            logging.error(f"运行CPU分析器时发生错误: {str(e)}")
            return 1
        finally:
            self.cleanup()

if __name__ == "__main__":
    profiler = CPUProfiler()
    sys.exit(profiler.run()) 