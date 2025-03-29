#!/usr/bin/env python3
# 锁分析器 - 使用eBPF监控锁竞争情况
#
# 这个程序跟踪系统中的锁获取和释放操作，
# 分析锁争用情况、持有时间，帮助诊断锁相关的性能问题。

import sys
import time
import argparse
from bcc import BPF
from datetime import datetime
import ctypes as ct
from collections import defaultdict

# eBPF程序代码
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

enum lock_type {
    MUTEX,              // 互斥锁
    RWLOCK,             // 读写锁
    SPINLOCK,           // 自旋锁
    SEMAPHORE,          // 信号量
    FUTEX               // 快速用户空间互斥锁
};

enum lock_op {
    LOCK_ACQUIRE,       // 获取锁
    LOCK_ACQUIRED,      // 成功获取锁
    LOCK_RELEASE,       // 释放锁
    LOCK_CONTENDED      // 锁争用
};

// 锁事件结构
struct lock_event_t {
    u64 ts;                   // 时间戳
    u32 pid;                  // 进程ID
    u64 lock_addr;            // 锁的地址
    enum lock_type type;      // 锁类型
    enum lock_op op;          // 操作类型
    u64 duration_ns;          // 持有/等待时间
    u32 stack_id;             // 堆栈ID
    char comm[TASK_COMM_LEN]; // 进程名称
};

// 锁的持有和等待时间记录
struct lock_time_t {
    u64 acquire_ts;           // 开始获取锁的时间戳
    u64 acquired_ts;          // 成功获取锁的时间戳
    u32 stack_id;             // 堆栈ID
};

// 锁统计数据
struct lock_stat_t {
    u64 acquire_count;        // 尝试获取次数
    u64 acquired_count;       // 成功获取次数
    u64 release_count;        // 释放次数
    u64 contention_count;     // 争用次数
    u64 total_wait_time;      // 总等待时间
    u64 total_hold_time;      // 总持有时间
    u64 max_wait_time;        // 最长等待时间
    u64 max_hold_time;        // 最长持有时间
};

// 锁事件输出
BPF_PERF_OUTPUT(lock_events);

// 保存锁的持有和等待时间信息
BPF_HASH(lock_times, u64, struct lock_time_t);

// 跟踪锁等待的堆栈
BPF_STACK_TRACE(stack_traces, 8192);

// 锁统计数据
BPF_HASH(lock_stats, u64, struct lock_stat_t);

// 跟踪mutex获取
int trace_mutex_lock(struct pt_regs *ctx, struct mutex *lock) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    u64 lock_addr = (u64)lock;
    
    // 检查目标PID
    u32 target_pid = PID_FILTER;
    if (target_pid > 0 && pid != target_pid) {
        return 0;
    }
    
    // 记录获取锁的时间
    u64 ts = bpf_ktime_get_ns();
    struct lock_time_t lock_time = {};
    lock_time.acquire_ts = ts;
    lock_time.stack_id = stack_traces.get_stackid(ctx, 0);
    lock_times.update(&id, &lock_time);
    
    // 更新锁统计
    u64 stat_key = ((u64)lock_addr << 32) | MUTEX;
    struct lock_stat_t *stat = lock_stats.lookup(&stat_key);
    if (stat == NULL) {
        struct lock_stat_t new_stat = {};
        new_stat.acquire_count = 1;
        lock_stats.update(&stat_key, &new_stat);
    } else {
        stat->acquire_count++;
    }
    
    // 发送锁事件
    struct lock_event_t event = {};
    event.ts = ts;
    event.pid = pid;
    event.lock_addr = lock_addr;
    event.type = MUTEX;
    event.op = LOCK_ACQUIRE;
    event.stack_id = lock_time.stack_id;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    lock_events.perf_submit(ctx, &event, sizeof(event));
    
    return 0;
}

// 跟踪mutex获取成功
int trace_mutex_lock_return(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    
    // 检查目标PID
    u32 target_pid = PID_FILTER;
    if (target_pid > 0 && pid != target_pid) {
        return 0;
    }
    
    // 获取锁时间记录
    struct lock_time_t *lock_time = lock_times.lookup(&id);
    if (lock_time == NULL) {
        return 0;  // 可能是过滤掉的进程
    }
    
    // 记录获取成功的时间
    u64 ts = bpf_ktime_get_ns();
    lock_time->acquired_ts = ts;
    
    // 计算等待时间
    u64 wait_time = ts - lock_time->acquire_ts;
    
    // 发送锁事件
    struct lock_event_t event = {};
    event.ts = ts;
    event.pid = pid;
    event.type = MUTEX;
    event.op = LOCK_ACQUIRED;
    event.duration_ns = wait_time;
    event.stack_id = lock_time->stack_id;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    // 检查锁等待时间是否超过阈值
    u64 threshold = THRESHOLD_NS;
    if (wait_time > threshold) {
        event.op = LOCK_CONTENDED;
        lock_events.perf_submit(ctx, &event, sizeof(event));
    }
    
    return 0;
}

// 跟踪mutex释放
int trace_mutex_unlock(struct pt_regs *ctx, struct mutex *lock) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    u64 lock_addr = (u64)lock;
    
    // 检查目标PID
    u32 target_pid = PID_FILTER;
    if (target_pid > 0 && pid != target_pid) {
        return 0;
    }
    
    // 获取锁时间记录
    struct lock_time_t *lock_time = lock_times.lookup(&id);
    if (lock_time == NULL) {
        return 0;
    }
    
    // 计算持有时间
    u64 ts = bpf_ktime_get_ns();
    u64 hold_time = 0;
    if (lock_time->acquired_ts > 0) {
        hold_time = ts - lock_time->acquired_ts;
    }
    
    // 更新锁统计
    u64 stat_key = ((u64)lock_addr << 32) | MUTEX;
    struct lock_stat_t *stat = lock_stats.lookup(&stat_key);
    if (stat != NULL) {
        stat->release_count++;
        stat->total_hold_time += hold_time;
        if (hold_time > stat->max_hold_time) {
            stat->max_hold_time = hold_time;
        }
    }
    
    // 发送锁事件
    struct lock_event_t event = {};
    event.ts = ts;
    event.pid = pid;
    event.lock_addr = lock_addr;
    event.type = MUTEX;
    event.op = LOCK_RELEASE;
    event.duration_ns = hold_time;
    event.stack_id = lock_time->stack_id;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    lock_events.perf_submit(ctx, &event, sizeof(event));
    
    // 清理
    lock_times.delete(&id);
    
    return 0;
}

// 跟踪自旋锁获取
int trace_spin_lock(struct pt_regs *ctx, spinlock_t *lock) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    u64 lock_addr = (u64)lock;
    
    // 检查目标PID
    u32 target_pid = PID_FILTER;
    if (target_pid > 0 && pid != target_pid) {
        return 0;
    }
    
    // 记录获取锁的时间
    u64 ts = bpf_ktime_get_ns();
    struct lock_time_t lock_time = {};
    lock_time.acquire_ts = ts;
    lock_time.stack_id = stack_traces.get_stackid(ctx, 0);
    lock_times.update(&id, &lock_time);
    
    // 更新锁统计
    u64 stat_key = ((u64)lock_addr << 32) | SPINLOCK;
    struct lock_stat_t *stat = lock_stats.lookup(&stat_key);
    if (stat == NULL) {
        struct lock_stat_t new_stat = {};
        new_stat.acquire_count = 1;
        lock_stats.update(&stat_key, &new_stat);
    } else {
        stat->acquire_count++;
    }
    
    // 发送锁事件
    struct lock_event_t event = {};
    event.ts = ts;
    event.pid = pid;
    event.lock_addr = lock_addr;
    event.type = SPINLOCK;
    event.op = LOCK_ACQUIRE;
    event.stack_id = lock_time.stack_id;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    lock_events.perf_submit(ctx, &event, sizeof(event));
    
    return 0;
}

// 跟踪自旋锁获取成功
int trace_spin_lock_return(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    
    // 检查目标PID
    u32 target_pid = PID_FILTER;
    if (target_pid > 0 && pid != target_pid) {
        return 0;
    }
    
    // 获取锁时间记录
    struct lock_time_t *lock_time = lock_times.lookup(&id);
    if (lock_time == NULL) {
        return 0;
    }
    
    // 记录获取成功的时间
    u64 ts = bpf_ktime_get_ns();
    lock_time->acquired_ts = ts;
    
    // 计算等待时间
    u64 wait_time = ts - lock_time->acquire_ts;
    
    // 发送锁事件
    struct lock_event_t event = {};
    event.ts = ts;
    event.pid = pid;
    event.type = SPINLOCK;
    event.op = LOCK_ACQUIRED;
    event.duration_ns = wait_time;
    event.stack_id = lock_time->stack_id;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    // 检查锁等待时间是否超过阈值
    u64 threshold = THRESHOLD_NS;
    if (wait_time > threshold) {
        event.op = LOCK_CONTENDED;
        lock_events.perf_submit(ctx, &event, sizeof(event));
    }
    
    return 0;
}

// 跟踪自旋锁释放
int trace_spin_unlock(struct pt_regs *ctx, spinlock_t *lock) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    u64 lock_addr = (u64)lock;
    
    // 检查目标PID
    u32 target_pid = PID_FILTER;
    if (target_pid > 0 && pid != target_pid) {
        return 0;
    }
    
    // 获取锁时间记录
    struct lock_time_t *lock_time = lock_times.lookup(&id);
    if (lock_time == NULL) {
        return 0;
    }
    
    // 计算持有时间
    u64 ts = bpf_ktime_get_ns();
    u64 hold_time = 0;
    if (lock_time->acquired_ts > 0) {
        hold_time = ts - lock_time->acquired_ts;
    }
    
    // 更新锁统计
    u64 stat_key = ((u64)lock_addr << 32) | SPINLOCK;
    struct lock_stat_t *stat = lock_stats.lookup(&stat_key);
    if (stat != NULL) {
        stat->release_count++;
        stat->total_hold_time += hold_time;
        if (hold_time > stat->max_hold_time) {
            stat->max_hold_time = hold_time;
        }
    }
    
    // 发送锁事件
    struct lock_event_t event = {};
    event.ts = ts;
    event.pid = pid;
    event.lock_addr = lock_addr;
    event.type = SPINLOCK;
    event.op = LOCK_RELEASE;
    event.duration_ns = hold_time;
    event.stack_id = lock_time->stack_id;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    lock_events.perf_submit(ctx, &event, sizeof(event));
    
    // 清理
    lock_times.delete(&id);
    
    return 0;
}

// 跟踪Futex等待
int trace_futex_wait(struct pt_regs *ctx, u32 *uaddr) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    u64 futex_addr = (u64)uaddr;
    
    // 检查目标PID
    u32 target_pid = PID_FILTER;
    if (target_pid > 0 && pid != target_pid) {
        return 0;
    }
    
    // 记录开始等待的时间
    u64 ts = bpf_ktime_get_ns();
    struct lock_time_t lock_time = {};
    lock_time.acquire_ts = ts;
    lock_time.stack_id = stack_traces.get_stackid(ctx, 0);
    lock_times.update(&id, &lock_time);
    
    // 更新统计
    u64 stat_key = ((u64)futex_addr << 32) | FUTEX;
    struct lock_stat_t *stat = lock_stats.lookup(&stat_key);
    if (stat == NULL) {
        struct lock_stat_t new_stat = {};
        new_stat.acquire_count = 1;
        lock_stats.update(&stat_key, &new_stat);
    } else {
        stat->acquire_count++;
    }
    
    // 发送事件
    struct lock_event_t event = {};
    event.ts = ts;
    event.pid = pid;
    event.lock_addr = futex_addr;
    event.type = FUTEX;
    event.op = LOCK_ACQUIRE;
    event.stack_id = lock_time.stack_id;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    lock_events.perf_submit(ctx, &event, sizeof(event));
    
    return 0;
}

// 跟踪Futex唤醒
int trace_futex_wake(struct pt_regs *ctx, u32 *uaddr) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    u64 futex_addr = (u64)uaddr;
    
    // 检查目标PID
    u32 target_pid = PID_FILTER;
    if (target_pid > 0 && pid != target_pid) {
        return 0;
    }
    
    // 获取时间记录
    struct lock_time_t *lock_time = lock_times.lookup(&id);
    if (lock_time == NULL) {
        return 0;
    }
    
    // 计算持有时间
    u64 ts = bpf_ktime_get_ns();
    u64 wait_time = ts - lock_time->acquire_ts;
    
    // 更新统计
    u64 stat_key = ((u64)futex_addr << 32) | FUTEX;
    struct lock_stat_t *stat = lock_stats.lookup(&stat_key);
    if (stat != NULL) {
        stat->release_count++;
        stat->total_wait_time += wait_time;
        if (wait_time > stat->max_wait_time) {
            stat->max_wait_time = wait_time;
        }
    }
    
    // 发送事件
    struct lock_event_t event = {};
    event.ts = ts;
    event.pid = pid;
    event.lock_addr = futex_addr;
    event.type = FUTEX;
    event.op = LOCK_RELEASE;
    event.duration_ns = wait_time;
    event.stack_id = lock_time->stack_id;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    lock_events.perf_submit(ctx, &event, sizeof(event));
    
    // 清理
    lock_times.delete(&id);
    
    return 0;
}
"""

# 锁类型
LOCK_TYPE_MUTEX = 0
LOCK_TYPE_RWLOCK = 1
LOCK_TYPE_SPINLOCK = 2
LOCK_TYPE_SEMAPHORE = 3
LOCK_TYPE_FUTEX = 4

# 锁操作
LOCK_OP_ACQUIRE = 0
LOCK_OP_ACQUIRED = 1
LOCK_OP_RELEASE = 2
LOCK_OP_CONTENDED = 3

# 锁类型名称
LOCK_TYPE_NAMES = {
    LOCK_TYPE_MUTEX: "互斥锁",
    LOCK_TYPE_RWLOCK: "读写锁",
    LOCK_TYPE_SPINLOCK: "自旋锁",
    LOCK_TYPE_SEMAPHORE: "信号量",
    LOCK_TYPE_FUTEX: "快速用户互斥锁"
}

# 锁操作名称
LOCK_OP_NAMES = {
    LOCK_OP_ACQUIRE: "获取",
    LOCK_OP_ACQUIRED: "已获取",
    LOCK_OP_RELEASE: "释放",
    LOCK_OP_CONTENDED: "争用"
}

# 锁事件结构
class LockEvent(ct.Structure):
    _fields_ = [
        ("ts", ct.c_ulonglong),
        ("pid", ct.c_uint),
        ("lock_addr", ct.c_ulonglong),
        ("type", ct.c_uint),
        ("op", ct.c_uint),
        ("duration_ns", ct.c_ulonglong),
        ("stack_id", ct.c_uint),
        ("comm", ct.c_char * 16)
    ]

# 锁统计结构
class LockStat(ct.Structure):
    _fields_ = [
        ("acquire_count", ct.c_ulonglong),
        ("acquired_count", ct.c_ulonglong),
        ("release_count", ct.c_ulonglong),
        ("contention_count", ct.c_ulonglong),
        ("total_wait_time", ct.c_ulonglong),
        ("total_hold_time", ct.c_ulonglong),
        ("max_wait_time", ct.c_ulonglong),
        ("max_hold_time", ct.c_ulonglong)
    ]

def parse_args():
    parser = argparse.ArgumentParser(
        description="锁分析工具 - 监控系统锁竞争")
    parser.add_argument("pid", type=int, nargs="?", default=0,
        help="要监控的进程ID (0表示所有进程)")
    parser.add_argument("-d", "--duration", type=int, default=10,
        help="监控持续时间(秒)")
    parser.add_argument("-t", "--threshold", type=float, default=1.0,
        help="锁争用阈值(毫秒)，超过此值视为争用")
    parser.add_argument("-l", "--lock-type", type=str, default="all",
        help="锁类型过滤器(all, mutex, spinlock, rwlock, semaphore, futex)")
    parser.add_argument("-o", "--output", type=str, default="contention",
        help="输出模式(all, contention, summary)")
    parser.add_argument("-c", "--count", type=int, default=10,
        help="显示争用最严重的前N个锁")
    return parser.parse_args()

def addr2sym(b, addr, pid):
    """将地址转换为符号名称"""
    try:
        sym = b.sym(addr, pid).decode('utf-8', 'replace')
        return sym if sym else f"[未知 @ {addr:x}]"
    except:
        return f"[未知 @ {addr:x}]"

def print_stack(b, stack_id, pid):
    """打印堆栈跟踪"""
    if stack_id < 0:
        print("\t<未记录堆栈>")
        return
    
    stack = list(b.get_table("stack_traces").walk(stack_id))
    if not stack:
        print("\t<空堆栈>")
        return
    
    for addr in stack:
        print(f"\t{addr2sym(b, addr, pid)}")

def main():
    args = parse_args()
    
    # 设置锁类型过滤器
    lock_type_filter = args.lock_type.lower()
    type_filter_map = {
        "all": [LOCK_TYPE_MUTEX, LOCK_TYPE_RWLOCK, LOCK_TYPE_SPINLOCK, 
                LOCK_TYPE_SEMAPHORE, LOCK_TYPE_FUTEX],
        "mutex": [LOCK_TYPE_MUTEX],
        "rwlock": [LOCK_TYPE_RWLOCK],
        "spinlock": [LOCK_TYPE_SPINLOCK],
        "semaphore": [LOCK_TYPE_SEMAPHORE],
        "futex": [LOCK_TYPE_FUTEX]
    }
    types_to_monitor = type_filter_map.get(lock_type_filter, type_filter_map["all"])
    
    threshold_ns = int(args.threshold * 1000000)  # 转换为纳秒
    print(f"开始监控{'PID ' + str(args.pid) if args.pid else '所有进程'} 的锁争用情况...")
    print(f"监控持续时间: {args.duration}秒")
    print(f"锁争用阈值: {args.threshold}ms")
    print(f"监控锁类型: {', '.join([LOCK_TYPE_NAMES[t] for t in types_to_monitor])}")
    
    # 替换eBPF程序中的变量
    bpf_program = bpf_text.replace('PID_FILTER', str(args.pid))
    bpf_program = bpf_program.replace('THRESHOLD_NS', str(threshold_ns))
    
    # 加载eBPF程序
    b = BPF(text=bpf_program)
    
    # 附加到锁相关函数
    b.attach_kprobe(event="mutex_lock", fn_name="trace_mutex_lock")
    b.attach_kretprobe(event="mutex_lock", fn_name="trace_mutex_lock_return")
    b.attach_kprobe(event="mutex_unlock", fn_name="trace_mutex_unlock")
    
    b.attach_kprobe(event="_raw_spin_lock", fn_name="trace_spin_lock")
    b.attach_kretprobe(event="_raw_spin_lock", fn_name="trace_spin_lock_return")
    b.attach_kprobe(event="_raw_spin_unlock", fn_name="trace_spin_unlock")
    
    b.attach_kprobe(event="do_futex", fn_name="trace_futex_wait")
    b.attach_kprobe(event="futex_wake", fn_name="trace_futex_wake")
    
    # 锁争用数据统计
    lock_contention = defaultdict(lambda: {"count": 0, "total_wait": 0, "max_wait": 0})
    
    # 锁详细信息
    lock_details = {}
    
    # 定义事件回调
    def event_callback(cpu, data, size):
        event = ct.cast(data, ct.POINTER(LockEvent)).contents
        
        # 根据锁类型过滤
        if event.type not in types_to_monitor:
            return
        
        # 获取基本信息
        ts = event.ts
        pid = event.pid
        comm = event.comm.decode('utf-8', 'replace')
        lock_addr = event.lock_addr
        lock_type = event.type
        op = event.op
        duration_ns = event.duration_ns
        duration_ms = duration_ns / 1000000
        
        # 保存锁详细信息
        lock_key = (lock_addr, lock_type)
        if lock_key not in lock_details:
            lock_details[lock_key] = {
                "address": lock_addr,
                "type": lock_type,
                "name": f"{LOCK_TYPE_NAMES[lock_type]}@{lock_addr:x}",
                "processes": set()
            }
        lock_details[lock_key]["processes"].add((pid, comm))
        
        # 处理争用事件
        if op == LOCK_OP_CONTENDED:
            lock_contention[lock_key]["count"] += 1
            lock_contention[lock_key]["total_wait"] += duration_ns
            if duration_ns > lock_contention[lock_key]["max_wait"]:
                lock_contention[lock_key]["max_wait"] = duration_ns
        
        # 根据输出模式决定是否输出
        if args.output == "all" or (args.output == "contention" and op == LOCK_OP_CONTENDED):
            timestamp = datetime.fromtimestamp(ts / 1000000000).strftime('%H:%M:%S.%f')
            lock_type_name = LOCK_TYPE_NAMES.get(lock_type, f"未知({lock_type})")
            op_name = LOCK_OP_NAMES.get(op, f"未知({op})")
            
            if op in [LOCK_OP_ACQUIRED, LOCK_OP_CONTENDED, LOCK_OP_RELEASE]:
                print(f"[{timestamp}] PID: {pid} ({comm}), "
                      f"锁类型: {lock_type_name}, 地址: 0x{lock_addr:x}, "
                      f"操作: {op_name}, 持续时间: {duration_ms:.3f}ms")
                
                # 显示争用的堆栈
                if op == LOCK_OP_CONTENDED:
                    print(f"持有锁的堆栈:")
                    print_stack(b, event.stack_id, pid)
                    print("-" * 80)
            else:
                print(f"[{timestamp}] PID: {pid} ({comm}), "
                      f"锁类型: {lock_type_name}, 地址: 0x{lock_addr:x}, "
                      f"操作: {op_name}")
    
    # 注册事件回调
    b["lock_events"].open_perf_buffer(event_callback)
    
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
    
    # 输出锁争用摘要
    print("\n----- 锁争用情况摘要 -----")
    
    if not lock_contention:
        print("未检测到锁争用。")
    else:
        # 按争用次数排序
        sorted_contention = sorted(lock_contention.items(), 
                                key=lambda x: x[1]["count"], 
                                reverse=True)
        
        print("%-16s %-12s %-12s %-16s %-16s %-20s" % (
            "锁地址", "类型", "争用次数", "总等待时间(ms)", "最大等待(ms)", "相关进程"))
        
        for i, ((lock_addr, lock_type), stats) in enumerate(sorted_contention[:args.count]):
            if i >= args.count:
                break
                
            lock_info = lock_details.get((lock_addr, lock_type), {})
            lock_type_name = LOCK_TYPE_NAMES.get(lock_type, f"未知({lock_type})")
            
            # 获取相关进程
            processes = []
            for pid, comm in lock_info.get("processes", []):
                processes.append(f"{comm}({pid})")
            process_str = ", ".join(processes[:3])
            if len(processes) > 3:
                process_str += f"... +{len(processes)-3}"
            
            print("0x%-14x %-12s %-12d %-16.2f %-16.2f %-20s" % (
                lock_addr, 
                lock_type_name, 
                stats["count"],
                stats["total_wait"] / 1000000,
                stats["max_wait"] / 1000000,
                process_str))
        
        # 总计
        total_contentions = sum(stats["count"] for _, stats in lock_contention.items())
        total_wait_time = sum(stats["total_wait"] for _, stats in lock_contention.items()) / 1000000
        print("-" * 92)
        print(f"总计: {len(lock_contention)} 个锁发生争用, {total_contentions} 次争用, 总等待时间: {total_wait_time:.2f}ms")
    
    # 清理资源
    b.cleanup()

if __name__ == "__main__":
    main() 