#!/usr/bin/env python3
# 调度器分析器 - 使用eBPF监控Linux进程调度器行为
#
# 这个程序跟踪Linux调度器的活动，记录调度延迟、运行队列长度和进程上下文切换，
# 帮助诊断与调度器相关的性能问题。

import sys
import time
import argparse
from bcc import BPF
from datetime import datetime
import ctypes as ct

# eBPF程序代码
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/nsproxy.h>
#include <linux/pid_namespace.h>

// 调度器事件类型
enum event_type {
    EVENT_WAKEUP = 0,        // 进程被唤醒
    EVENT_CONTEXT_SWITCH,    // 上下文切换
    EVENT_MIGRATE,           // 进程在CPU之间迁移
    EVENT_PREEMPT,           // 进程被抢占
};

// 调度器事件结构
struct sched_event_t {
    u64 ts;                  // 事件时间戳
    u32 pid;                 // 进程ID
    u32 target_pid;          // 目标进程ID (迁移/唤醒的目标)
    u32 cpu;                 // CPU ID
    u32 target_cpu;          // 目标CPU ID
    enum event_type type;    // 事件类型
    u64 delay_ns;            // 调度延迟
    char comm[TASK_COMM_LEN]; // 进程名称
};

// 事件队列，用于将事件从内核传递到用户空间
BPF_PERF_OUTPUT(events);

// 记录每个进程的运行开始时间
BPF_HASH(start_times, u32, u64);

// 记录每个进程的最后运行CPU
BPF_HASH(last_cpu, u32, u32);

// 记录每个唤醒事件的时间
struct wakeup_key_t {
    u32 waker_pid;           // 唤醒进程的ID
    u32 target_pid;          // 被唤醒进程的ID
};
BPF_HASH(wakeup_times, struct wakeup_key_t, u64);

// 跟踪进程被唤醒
int trace_sched_wakeup(struct pt_regs *ctx, struct task_struct *p) {
    // 筛选目标PID
    u32 target_pid = PID_FILTER;
    u32 tpid = p->pid;
    
    if (target_pid > 0 && tpid != target_pid) {
        return 0;
    }
    
    // 获取唤醒时间
    u64 ts = bpf_ktime_get_ns();
    
    // 获取当前进程(唤醒者)信息
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    // 记录唤醒事件
    struct sched_event_t event = {};
    event.ts = ts;
    event.pid = pid;
    event.target_pid = tpid;
    event.cpu = bpf_get_smp_processor_id();
    event.target_cpu = p->cpu;
    event.type = EVENT_WAKEUP;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    // 发送事件
    events.perf_submit(ctx, &event, sizeof(event));
    
    // 记录唤醒时间以计算延迟
    struct wakeup_key_t key = {};
    key.waker_pid = pid;
    key.target_pid = tpid;
    wakeup_times.update(&key, &ts);
    
    return 0;
}

// 跟踪上下文切换
int trace_sched_switch(struct pt_regs *ctx, struct task_struct *prev, struct task_struct *next) {
    // 获取切换时间
    u64 ts = bpf_ktime_get_ns();
    u32 prev_pid = prev->pid;
    u32 next_pid = next->pid;
    
    // 筛选目标PID
    u32 target_pid = PID_FILTER;
    if (target_pid > 0 && prev_pid != target_pid && next_pid != target_pid) {
        return 0;
    }
    
    // 获取当前CPU
    u32 cpu = bpf_get_smp_processor_id();
    
    // 记录切出进程的运行时间
    if (prev_pid != 0) {  // 忽略swapper进程
        u64 *start_ts = start_times.lookup(&prev_pid);
        if (start_ts != NULL) {
            // 获取运行时间
            u64 runtime = ts - *start_ts;
            
            // 记录切出事件
            struct sched_event_t event = {};
            event.ts = ts;
            event.pid = prev_pid;
            event.target_pid = next_pid;
            event.cpu = cpu;
            event.target_cpu = cpu;
            event.type = EVENT_CONTEXT_SWITCH;
            event.delay_ns = runtime;
            
            bpf_probe_read_kernel_str(&event.comm, sizeof(event.comm), prev->comm);
            
            // 发送事件
            events.perf_submit(ctx, &event, sizeof(event));
            
            // 删除开始时间
            start_times.delete(&prev_pid);
        }
    }
    
    // 记录切入进程的开始时间
    if (next_pid != 0) {  // 忽略swapper进程
        start_times.update(&next_pid, &ts);
        
        // 检查是否发生了CPU迁移
        u32 *last_cpu_val = last_cpu.lookup(&next_pid);
        if (last_cpu_val != NULL && *last_cpu_val != cpu) {
            // 记录CPU迁移事件
            struct sched_event_t event = {};
            event.ts = ts;
            event.pid = next_pid;
            event.cpu = *last_cpu_val;
            event.target_cpu = cpu;
            event.type = EVENT_MIGRATE;
            
            bpf_probe_read_kernel_str(&event.comm, sizeof(event.comm), next->comm);
            
            // 发送事件
            events.perf_submit(ctx, &event, sizeof(event));
        }
        
        // 更新进程的最后运行CPU
        last_cpu.update(&next_pid, &cpu);
        
        // 检查是否存在唤醒延迟
        struct wakeup_key_t key = {};
        // 这里我们不知道是谁唤醒的，所以设置为0
        key.waker_pid = 0;
        key.target_pid = next_pid;
        
        u64 *wakeup_ts = wakeup_times.lookup(&key);
        if (wakeup_ts != NULL) {
            u64 delay = ts - *wakeup_ts;
            if (delay > 1000000) {  // 只关注大于1ms的调度延迟
                // 记录调度延迟事件
                struct sched_event_t event = {};
                event.ts = ts;
                event.pid = next_pid;
                event.cpu = cpu;
                event.type = EVENT_WAKEUP;
                event.delay_ns = delay;
                
                bpf_probe_read_kernel_str(&event.comm, sizeof(event.comm), next->comm);
                
                // 发送事件
                events.perf_submit(ctx, &event, sizeof(event));
            }
            
            // 删除唤醒时间
            wakeup_times.delete(&key);
        }
    }
    
    return 0;
}

// 跟踪抢占
int trace_sched_preempt(struct pt_regs *ctx, struct task_struct *p) {
    // 筛选目标PID
    u32 target_pid = PID_FILTER;
    u32 pid = p->pid;
    
    if (target_pid > 0 && pid != target_pid) {
        return 0;
    }
    
    // 获取抢占时间
    u64 ts = bpf_ktime_get_ns();
    
    // 记录抢占事件
    struct sched_event_t event = {};
    event.ts = ts;
    event.pid = pid;
    event.cpu = bpf_get_smp_processor_id();
    event.type = EVENT_PREEMPT;
    
    bpf_probe_read_kernel_str(&event.comm, sizeof(event.comm), p->comm);
    
    // 发送事件
    events.perf_submit(ctx, &event, sizeof(event));
    
    return 0;
}
"""

# 定义事件类型
EVENT_WAKEUP = 0
EVENT_CONTEXT_SWITCH = 1
EVENT_MIGRATE = 2
EVENT_PREEMPT = 3

# 事件名称映射
EVENT_NAMES = {
    EVENT_WAKEUP: "唤醒",
    EVENT_CONTEXT_SWITCH: "上下文切换",
    EVENT_MIGRATE: "CPU迁移",
    EVENT_PREEMPT: "抢占"
}

# 事件结构定义
class SchedEvent(ct.Structure):
    _fields_ = [
        ("ts", ct.c_ulonglong),
        ("pid", ct.c_uint),
        ("target_pid", ct.c_uint),
        ("cpu", ct.c_uint),
        ("target_cpu", ct.c_uint),
        ("type", ct.c_uint),
        ("delay_ns", ct.c_ulonglong),
        ("comm", ct.c_char * 16)
    ]

def parse_args():
    parser = argparse.ArgumentParser(
        description="调度器分析工具 - 监控Linux进程调度器行为")
    parser.add_argument("pid", type=int, nargs="?", default=0,
        help="要监控的进程ID (0表示所有进程)")
    parser.add_argument("-d", "--duration", type=int, default=10,
        help="监控持续时间(秒)")
    parser.add_argument("-t", "--threshold", type=int, default=1,
        help="调度延迟阈值(毫秒)，只显示高于此阈值的延迟")
    parser.add_argument("--event-filter", type=str, default="all",
        help="事件过滤器 (all, wakeup, context, migrate, preempt)")
    return parser.parse_args()

def print_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(SchedEvent)).contents
    event_type = event.type
    
    # 根据事件类型格式化输出
    if event_type == EVENT_WAKEUP:
        if event.delay_ns > 0:  # 这是一个调度延迟事件
            print(f"[{event.ts}] 进程 {event.comm.decode('utf-8', 'replace')} ({event.pid}) "
                  f"在CPU {event.cpu} 上的调度延迟: {event.delay_ns/1000000:.2f}ms")
        else:  # 这是一个唤醒事件
            print(f"[{event.ts}] 进程 {event.comm.decode('utf-8', 'replace')} ({event.pid}) "
                  f"在CPU {event.cpu} 上唤醒了进程 ({event.target_pid}) 在CPU {event.target_cpu}")
    
    elif event_type == EVENT_CONTEXT_SWITCH:
        print(f"[{event.ts}] 上下文切换: 进程 {event.comm.decode('utf-8', 'replace')} ({event.pid}) "
              f"在CPU {event.cpu} 上切出，运行时间: {event.delay_ns/1000000:.2f}ms")
    
    elif event_type == EVENT_MIGRATE:
        print(f"[{event.ts}] CPU迁移: 进程 {event.comm.decode('utf-8', 'replace')} ({event.pid}) "
              f"从CPU {event.cpu} 迁移到CPU {event.target_cpu}")
    
    elif event_type == EVENT_PREEMPT:
        print(f"[{event.ts}] 进程抢占: 进程 {event.comm.decode('utf-8', 'replace')} ({event.pid}) "
              f"在CPU {event.cpu} 上被抢占")

def main():
    args = parse_args()
    
    # 设置事件过滤器
    event_filter = args.event_filter.lower()
    filter_map = {
        "all": [EVENT_WAKEUP, EVENT_CONTEXT_SWITCH, EVENT_MIGRATE, EVENT_PREEMPT],
        "wakeup": [EVENT_WAKEUP],
        "context": [EVENT_CONTEXT_SWITCH],
        "migrate": [EVENT_MIGRATE],
        "preempt": [EVENT_PREEMPT]
    }
    
    events_to_monitor = filter_map.get(event_filter, filter_map["all"])
    
    print(f"开始监控{'PID ' + str(args.pid) if args.pid else '所有进程'} 的调度器行为...")
    print(f"监控持续时间: {args.duration}秒")
    print(f"调度延迟阈值: {args.threshold}ms")
    print(f"监控事件类型: {', '.join([EVENT_NAMES[e] for e in events_to_monitor])}")
    
    # 替换eBPF程序中的PID过滤器
    bpf_program = bpf_text.replace('PID_FILTER', str(args.pid))
    
    # 加载eBPF程序
    b = BPF(text=bpf_program)
    
    # 附加到调度器相关的内核函数
    b.attach_kprobe(event="try_to_wake_up", fn_name="trace_sched_wakeup")
    b.attach_kprobe(event="finish_task_switch", fn_name="trace_sched_switch")
    b.attach_kprobe(event="preempt_schedule_irq", fn_name="trace_sched_preempt")
    
    # 定义事件回调
    def event_callback(cpu, data, size):
        event = ct.cast(data, ct.POINTER(SchedEvent)).contents
        
        # 根据事件过滤器过滤事件
        if event.type not in events_to_monitor:
            return
        
        # 对于延迟事件，根据阈值过滤
        if event.type == EVENT_WAKEUP and event.delay_ns > 0:
            delay_ms = event.delay_ns / 1000000
            if delay_ms < args.threshold:
                return
        
        # 打印事件
        print_event(cpu, data, size)
    
    # 注册事件回调
    b["events"].open_perf_buffer(event_callback)
    
    # 监控指定的时间
    start_time = datetime.now()
    print(f"开始时间: {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
    
    try:
        while datetime.now() - start_time < datetime.timedelta(seconds=args.duration):
            b.perf_buffer_poll(timeout=100)
    except KeyboardInterrupt:
        print("监控被用户中断")
    
    end_time = datetime.now()
    print(f"结束时间: {end_time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"总监控时间: {(end_time - start_time).total_seconds():.2f}秒")
    
    # 清理资源
    b.cleanup()

if __name__ == "__main__":
    main() 