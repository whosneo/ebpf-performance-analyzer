#!/usr/bin/env python3
# 缓存分析器 - 使用eBPF监控系统缓存性能
#
# 这个程序跟踪系统缓存活动，包括页面缓存命中率和CPU缓存访问，
# 帮助诊断与缓存相关的性能问题。

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

// 缓存类型
enum cache_type_t {
    PAGE_CACHE,     // 页面缓存
    SLAB_CACHE,     // SLAB缓存
    INODE_CACHE,    // Inode缓存
    DENTRY_CACHE,   // 目录项缓存
};

// 缓存访问类型
enum cache_op_t {
    CACHE_HIT,      // 缓存命中
    CACHE_MISS,     // 缓存未命中
    CACHE_ALLOC,    // 缓存分配
    CACHE_FREE      // 缓存释放
};

// 缓存事件结构
struct cache_event_t {
    u64 ts;                  // 时间戳
    u32 pid;                 // 进程ID
    enum cache_type_t type;  // 缓存类型
    enum cache_op_t op;      // 操作类型
    u32 count;               // 事件计数
    char comm[TASK_COMM_LEN]; // 进程名称
};

// 存储缓存统计信息
struct cache_stat_t {
    u64 hits;     // 命中次数
    u64 misses;   // 未命中次数
    u64 allocs;   // 分配次数
    u64 frees;    // 释放次数
};

// 缓存统计哈希表
BPF_HASH(page_cache_stats, u32, struct cache_stat_t);
BPF_HASH(slab_cache_stats, u32, struct cache_stat_t);
BPF_HASH(inode_cache_stats, u32, struct cache_stat_t);
BPF_HASH(dentry_cache_stats, u32, struct cache_stat_t);

// 用于将数据传递到用户空间
BPF_PERF_OUTPUT(cache_events);

// 跟踪页面缓存命中
int trace_page_cache_hit(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    
    // 检查目标PID
    u32 target_pid = PID_FILTER;
    if (target_pid > 0 && pid != target_pid) {
        return 0;
    }
    
    // 更新页面缓存统计
    struct cache_stat_t *stats = page_cache_stats.lookup(&pid);
    if (stats == NULL) {
        struct cache_stat_t new_stats = {};
        new_stats.hits = 1;
        page_cache_stats.update(&pid, &new_stats);
    } else {
        stats->hits++;
    }
    
    // 创建缓存事件
    struct cache_event_t event = {};
    event.ts = bpf_ktime_get_ns();
    event.pid = pid;
    event.type = PAGE_CACHE;
    event.op = CACHE_HIT;
    event.count = 1;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    // 发送事件
    cache_events.perf_submit(ctx, &event, sizeof(event));
    
    return 0;
}

// 跟踪页面缓存未命中
int trace_page_cache_miss(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    
    // 检查目标PID
    u32 target_pid = PID_FILTER;
    if (target_pid > 0 && pid != target_pid) {
        return 0;
    }
    
    // 更新页面缓存统计
    struct cache_stat_t *stats = page_cache_stats.lookup(&pid);
    if (stats == NULL) {
        struct cache_stat_t new_stats = {};
        new_stats.misses = 1;
        page_cache_stats.update(&pid, &new_stats);
    } else {
        stats->misses++;
    }
    
    // 创建缓存事件
    struct cache_event_t event = {};
    event.ts = bpf_ktime_get_ns();
    event.pid = pid;
    event.type = PAGE_CACHE;
    event.op = CACHE_MISS;
    event.count = 1;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    // 发送事件
    cache_events.perf_submit(ctx, &event, sizeof(event));
    
    return 0;
}

// 跟踪inode缓存操作
int trace_inode_cache_op(struct pt_regs *ctx, int op_type) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    
    // 检查目标PID
    u32 target_pid = PID_FILTER;
    if (target_pid > 0 && pid != target_pid) {
        return 0;
    }
    
    // 获取操作类型
    enum cache_op_t op;
    if (op_type == 1) {
        op = CACHE_HIT;
    } else if (op_type == 2) {
        op = CACHE_MISS;
    } else if (op_type == 3) {
        op = CACHE_ALLOC;
    } else {
        op = CACHE_FREE;
    }
    
    // 更新inode缓存统计
    struct cache_stat_t *stats = inode_cache_stats.lookup(&pid);
    if (stats == NULL) {
        struct cache_stat_t new_stats = {};
        if (op == CACHE_HIT) {
            new_stats.hits = 1;
        } else if (op == CACHE_MISS) {
            new_stats.misses = 1;
        } else if (op == CACHE_ALLOC) {
            new_stats.allocs = 1;
        } else {
            new_stats.frees = 1;
        }
        inode_cache_stats.update(&pid, &new_stats);
    } else {
        if (op == CACHE_HIT) {
            stats->hits++;
        } else if (op == CACHE_MISS) {
            stats->misses++;
        } else if (op == CACHE_ALLOC) {
            stats->allocs++;
        } else {
            stats->frees++;
        }
    }
    
    // 创建缓存事件
    struct cache_event_t event = {};
    event.ts = bpf_ktime_get_ns();
    event.pid = pid;
    event.type = INODE_CACHE;
    event.op = op;
    event.count = 1;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    // 发送事件
    cache_events.perf_submit(ctx, &event, sizeof(event));
    
    return 0;
}

// 跟踪inode缓存命中
int trace_inode_cache_hit(struct pt_regs *ctx) {
    return trace_inode_cache_op(ctx, 1);
}

// 跟踪inode缓存未命中
int trace_inode_cache_miss(struct pt_regs *ctx) {
    return trace_inode_cache_op(ctx, 2);
}

// 跟踪inode缓存分配
int trace_inode_cache_alloc(struct pt_regs *ctx) {
    return trace_inode_cache_op(ctx, 3);
}

// 跟踪inode缓存释放
int trace_inode_cache_free(struct pt_regs *ctx) {
    return trace_inode_cache_op(ctx, 4);
}

// 跟踪dentry缓存操作
int trace_dentry_cache_op(struct pt_regs *ctx, int op_type) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    
    // 检查目标PID
    u32 target_pid = PID_FILTER;
    if (target_pid > 0 && pid != target_pid) {
        return 0;
    }
    
    // 获取操作类型
    enum cache_op_t op;
    if (op_type == 1) {
        op = CACHE_HIT;
    } else if (op_type == 2) {
        op = CACHE_MISS;
    } else if (op_type == 3) {
        op = CACHE_ALLOC;
    } else {
        op = CACHE_FREE;
    }
    
    // 更新dentry缓存统计
    struct cache_stat_t *stats = dentry_cache_stats.lookup(&pid);
    if (stats == NULL) {
        struct cache_stat_t new_stats = {};
        if (op == CACHE_HIT) {
            new_stats.hits = 1;
        } else if (op == CACHE_MISS) {
            new_stats.misses = 1;
        } else if (op == CACHE_ALLOC) {
            new_stats.allocs = 1;
        } else {
            new_stats.frees = 1;
        }
        dentry_cache_stats.update(&pid, &new_stats);
    } else {
        if (op == CACHE_HIT) {
            stats->hits++;
        } else if (op == CACHE_MISS) {
            stats->misses++;
        } else if (op == CACHE_ALLOC) {
            stats->allocs++;
        } else {
            stats->frees++;
        }
    }
    
    // 创建缓存事件
    struct cache_event_t event = {};
    event.ts = bpf_ktime_get_ns();
    event.pid = pid;
    event.type = DENTRY_CACHE;
    event.op = op;
    event.count = 1;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    // 发送事件
    cache_events.perf_submit(ctx, &event, sizeof(event));
    
    return 0;
}

// 跟踪dentry缓存命中
int trace_dentry_cache_hit(struct pt_regs *ctx) {
    return trace_dentry_cache_op(ctx, 1);
}

// 跟踪dentry缓存未命中
int trace_dentry_cache_miss(struct pt_regs *ctx) {
    return trace_dentry_cache_op(ctx, 2);
}

// 跟踪dentry缓存分配
int trace_dentry_cache_alloc(struct pt_regs *ctx) {
    return trace_dentry_cache_op(ctx, 3);
}

// 跟踪dentry缓存释放
int trace_dentry_cache_free(struct pt_regs *ctx) {
    return trace_dentry_cache_op(ctx, 4);
}

// 跟踪slab缓存分配
int trace_kmem_cache_alloc(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    
    // 检查目标PID
    u32 target_pid = PID_FILTER;
    if (target_pid > 0 && pid != target_pid) {
        return 0;
    }
    
    // 更新slab缓存统计
    struct cache_stat_t *stats = slab_cache_stats.lookup(&pid);
    if (stats == NULL) {
        struct cache_stat_t new_stats = {};
        new_stats.allocs = 1;
        slab_cache_stats.update(&pid, &new_stats);
    } else {
        stats->allocs++;
    }
    
    // 创建缓存事件
    struct cache_event_t event = {};
    event.ts = bpf_ktime_get_ns();
    event.pid = pid;
    event.type = SLAB_CACHE;
    event.op = CACHE_ALLOC;
    event.count = 1;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    // 发送事件
    cache_events.perf_submit(ctx, &event, sizeof(event));
    
    return 0;
}

// 跟踪slab缓存释放
int trace_kmem_cache_free(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    
    // 检查目标PID
    u32 target_pid = PID_FILTER;
    if (target_pid > 0 && pid != target_pid) {
        return 0;
    }
    
    // 更新slab缓存统计
    struct cache_stat_t *stats = slab_cache_stats.lookup(&pid);
    if (stats == NULL) {
        struct cache_stat_t new_stats = {};
        new_stats.frees = 1;
        slab_cache_stats.update(&pid, &new_stats);
    } else {
        stats->frees++;
    }
    
    // 创建缓存事件
    struct cache_event_t event = {};
    event.ts = bpf_ktime_get_ns();
    event.pid = pid;
    event.type = SLAB_CACHE;
    event.op = CACHE_FREE;
    event.count = 1;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    // 发送事件
    cache_events.perf_submit(ctx, &event, sizeof(event));
    
    return 0;
}
"""

# 缓存类型
CACHE_TYPE_PAGE = 0
CACHE_TYPE_SLAB = 1
CACHE_TYPE_INODE = 2
CACHE_TYPE_DENTRY = 3

# 缓存操作类型
CACHE_OP_HIT = 0
CACHE_OP_MISS = 1
CACHE_OP_ALLOC = 2
CACHE_OP_FREE = 3

# 缓存类型名称映射
CACHE_TYPE_NAMES = {
    CACHE_TYPE_PAGE: "页面缓存",
    CACHE_TYPE_SLAB: "SLAB缓存",
    CACHE_TYPE_INODE: "Inode缓存",
    CACHE_TYPE_DENTRY: "目录项缓存"
}

# 缓存操作名称映射
CACHE_OP_NAMES = {
    CACHE_OP_HIT: "命中",
    CACHE_OP_MISS: "未命中",
    CACHE_OP_ALLOC: "分配",
    CACHE_OP_FREE: "释放"
}

# 缓存事件结构
class CacheEvent(ct.Structure):
    _fields_ = [
        ("ts", ct.c_ulonglong),
        ("pid", ct.c_uint),
        ("type", ct.c_uint),
        ("op", ct.c_uint),
        ("count", ct.c_uint),
        ("comm", ct.c_char * 16)
    ]

# 缓存统计结构
class CacheStat(ct.Structure):
    _fields_ = [
        ("hits", ct.c_ulonglong),
        ("misses", ct.c_ulonglong),
        ("allocs", ct.c_ulonglong),
        ("frees", ct.c_ulonglong)
    ]

def parse_args():
    parser = argparse.ArgumentParser(
        description="缓存分析工具 - 监控系统缓存")
    parser.add_argument("pid", type=int, nargs="?", default=0,
        help="要监控的进程ID (0表示所有进程)")
    parser.add_argument("-d", "--duration", type=int, default=10,
        help="监控持续时间(秒)")
    parser.add_argument("-t", "--type", type=str, default="all",
        help="缓存类型过滤器(all, page, slab, inode, dentry)")
    parser.add_argument("-o", "--operation", type=str, default="all",
        help="操作类型过滤器(all, hit, miss, alloc, free)")
    parser.add_argument("-s", "--sample", type=int, default=0,
        help="采样率(每N个事件只显示1个，0表示不采样)")
    parser.add_argument("--summary", action="store_true",
        help="只显示摘要统计")
    return parser.parse_args()

def main():
    args = parse_args()
    
    # 设置缓存类型过滤器
    cache_type_filter = args.type.lower()
    type_filter_map = {
        "all": [CACHE_TYPE_PAGE, CACHE_TYPE_SLAB, CACHE_TYPE_INODE, CACHE_TYPE_DENTRY],
        "page": [CACHE_TYPE_PAGE],
        "slab": [CACHE_TYPE_SLAB],
        "inode": [CACHE_TYPE_INODE],
        "dentry": [CACHE_TYPE_DENTRY]
    }
    types_to_monitor = type_filter_map.get(cache_type_filter, type_filter_map["all"])
    
    # 设置操作类型过滤器
    op_filter = args.operation.lower()
    op_filter_map = {
        "all": [CACHE_OP_HIT, CACHE_OP_MISS, CACHE_OP_ALLOC, CACHE_OP_FREE],
        "hit": [CACHE_OP_HIT],
        "miss": [CACHE_OP_MISS],
        "alloc": [CACHE_OP_ALLOC],
        "free": [CACHE_OP_FREE]
    }
    ops_to_monitor = op_filter_map.get(op_filter, op_filter_map["all"])
    
    print(f"开始监控{'PID ' + str(args.pid) if args.pid else '所有进程'} 的缓存活动...")
    print(f"监控持续时间: {args.duration}秒")
    print(f"监控缓存类型: {', '.join([CACHE_TYPE_NAMES[t] for t in types_to_monitor])}")
    print(f"监控操作类型: {', '.join([CACHE_OP_NAMES[o] for o in ops_to_monitor])}")
    
    if args.sample > 0:
        print(f"采样率: 每 {args.sample} 个事件显示1个")
    
    # 替换eBPF程序中的PID过滤器
    bpf_program = bpf_text.replace('PID_FILTER', str(args.pid))
    
    # 加载eBPF程序
    b = BPF(text=bpf_program)
    
    # 附加到页面缓存相关函数
    b.attach_kprobe(event="mark_page_accessed", fn_name="trace_page_cache_hit")
    b.attach_kprobe(event="filemap_fault", fn_name="trace_page_cache_miss")
    
    # 附加到inode缓存相关函数
    b.attach_kprobe(event="find_inode_fast", fn_name="trace_inode_cache_hit")
    b.attach_kprobe(event="alloc_inode", fn_name="trace_inode_cache_alloc")
    b.attach_kprobe(event="destroy_inode", fn_name="trace_inode_cache_free")
    
    # 附加到dentry缓存相关函数
    b.attach_kprobe(event="d_lookup", fn_name="trace_dentry_cache_hit")
    b.attach_kprobe(event="d_alloc", fn_name="trace_dentry_cache_alloc")
    b.attach_kprobe(event="d_free", fn_name="trace_dentry_cache_free")
    
    # 附加到slab分配相关函数
    b.attach_kprobe(event="kmem_cache_alloc", fn_name="trace_kmem_cache_alloc")
    b.attach_kprobe(event="kmem_cache_free", fn_name="trace_kmem_cache_free")
    
    # 用于采样和累积统计
    event_count = 0
    
    # 类型和操作的累积统计
    accumulated_stats = {
        CACHE_TYPE_PAGE: {"hit": 0, "miss": 0, "alloc": 0, "free": 0},
        CACHE_TYPE_SLAB: {"hit": 0, "miss": 0, "alloc": 0, "free": 0},
        CACHE_TYPE_INODE: {"hit": 0, "miss": 0, "alloc": 0, "free": 0},
        CACHE_TYPE_DENTRY: {"hit": 0, "miss": 0, "alloc": 0, "free": 0}
    }
    
    # 进程级统计
    process_stats = {}
    
    # 定义事件回调
    def event_callback(cpu, data, size):
        nonlocal event_count
        event = ct.cast(data, ct.POINTER(CacheEvent)).contents
        
        # 根据过滤器过滤事件
        if event.type not in types_to_monitor or event.op not in ops_to_monitor:
            return
        
        # 更新累积统计
        if event.op == CACHE_OP_HIT:
            accumulated_stats[event.type]["hit"] += event.count
        elif event.op == CACHE_OP_MISS:
            accumulated_stats[event.type]["miss"] += event.count
        elif event.op == CACHE_OP_ALLOC:
            accumulated_stats[event.type]["alloc"] += event.count
        elif event.op == CACHE_OP_FREE:
            accumulated_stats[event.type]["free"] += event.count
        
        # 更新进程级统计
        process_name = event.comm.decode('utf-8', 'replace')
        if event.pid not in process_stats:
            process_stats[event.pid] = {
                "name": process_name,
                "types": {
                    CACHE_TYPE_PAGE: {"hit": 0, "miss": 0, "alloc": 0, "free": 0},
                    CACHE_TYPE_SLAB: {"hit": 0, "miss": 0, "alloc": 0, "free": 0},
                    CACHE_TYPE_INODE: {"hit": 0, "miss": 0, "alloc": 0, "free": 0},
                    CACHE_TYPE_DENTRY: {"hit": 0, "miss": 0, "alloc": 0, "free": 0}
                }
            }
        
        # 更新进程缓存统计
        if event.op == CACHE_OP_HIT:
            process_stats[event.pid]["types"][event.type]["hit"] += event.count
        elif event.op == CACHE_OP_MISS:
            process_stats[event.pid]["types"][event.type]["miss"] += event.count
        elif event.op == CACHE_OP_ALLOC:
            process_stats[event.pid]["types"][event.type]["alloc"] += event.count
        elif event.op == CACHE_OP_FREE:
            process_stats[event.pid]["types"][event.type]["free"] += event.count
        
        # 如果不是只显示摘要，则输出实时事件
        if not args.summary:
            # 采样处理
            event_count += 1
            if args.sample > 0 and event_count % args.sample != 0:
                return
            
            # 格式化输出
            timestamp = datetime.fromtimestamp(event.ts / 1000000000).strftime('%H:%M:%S.%f')
            cache_type = CACHE_TYPE_NAMES.get(event.type, f"未知({event.type})")
            op_name = CACHE_OP_NAMES.get(event.op, f"未知({event.op})")
            
            print(f"[{timestamp}] PID: {event.pid} ({process_name}), "
                  f"缓存类型: {cache_type}, 操作: {op_name}, 计数: {event.count}")
    
    # 注册事件回调
    b["cache_events"].open_perf_buffer(event_callback)
    
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
    
    # 输出缓存统计摘要
    print("\n----- 缓存命中率统计 -----")
    for cache_type in types_to_monitor:
        type_name = CACHE_TYPE_NAMES[cache_type]
        hits = accumulated_stats[cache_type]["hit"]
        misses = accumulated_stats[cache_type]["miss"]
        allocs = accumulated_stats[cache_type]["alloc"]
        frees = accumulated_stats[cache_type]["free"]
        
        total_accesses = hits + misses
        hit_rate = (hits / total_accesses * 100) if total_accesses > 0 else 0
        
        print(f"{type_name}:")
        print(f"  命中: {hits}, 未命中: {misses}, 命中率: {hit_rate:.2f}%")
        print(f"  分配: {allocs}, 释放: {frees}, 净分配: {allocs - frees}")
    
    # 输出每个进程的缓存统计
    print("\n----- 进程缓存统计 -----")
    
    # 按总缓存访问量排序进程
    def get_total_accesses(pid_stats):
        pid, stats = pid_stats
        total = 0
        for cache_type in types_to_monitor:
            total += stats["types"][cache_type]["hit"] + stats["types"][cache_type]["miss"]
        return total
    
    sorted_processes = sorted(process_stats.items(), key=get_total_accesses, reverse=True)
    
    # 显示前10个进程
    for pid, stats in sorted_processes[:10]:
        process_name = stats["name"]
        print(f"\nPID: {pid} ({process_name})")
        
        for cache_type in types_to_monitor:
            type_name = CACHE_TYPE_NAMES[cache_type]
            type_stats = stats["types"][cache_type]
            hits = type_stats["hit"]
            misses = type_stats["miss"]
            allocs = type_stats["alloc"]
            frees = type_stats["free"]
            
            total_accesses = hits + misses
            hit_rate = (hits / total_accesses * 100) if total_accesses > 0 else 0
            
            print(f"  {type_name}:")
            print(f"    命中: {hits}, 未命中: {misses}, 命中率: {hit_rate:.2f}%")
            print(f"    分配: {allocs}, 释放: {frees}, 净分配: {allocs - frees}")
    
    # 清理资源
    b.cleanup()

if __name__ == "__main__":
    main() 