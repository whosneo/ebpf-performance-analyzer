#!/usr/bin/env python3
# 网络性能分析器 - 使用eBPF跟踪网络连接和数据传输
#
# 这个程序使用eBPF跟踪进程的网络连接和数据传输情况，
# 提供连接延迟、数据传输量和网络错误分析。

import sys
import time
import argparse
from bcc import BPF
from datetime import datetime
import ctypes as ct
import socket
import struct
import os
import logging

# 导入公共模块
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
from src.ebpf_common import setup_logging, validate_args, human_readable_size, run_monitoring_loop, setup_signal_handler

# eBPF程序代码
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <net/inet_sock.h>
#include <bcc/proto.h>
#include <linux/tcp.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>

// 记录连接信息
struct conn_info_t {
    u64 ts_us;         // 时间戳 (微秒)
    u32 pid;           // 进程ID
    u32 tid;           // 线程ID
    u32 uid;           // 用户ID
    u32 saddr;         // 源IP
    u32 daddr;         // 目标IP
    u16 sport;         // 源端口
    u16 dport;         // 目标端口
    u16 family;        // 地址族
    u8 protocol;       // 协议
    u8 type;           // 事件类型: 1=连接, 2=接收, 3=发送, 4=关闭, 5=重传
};

// 跟踪数据传输的信息
struct data_info_t {
    u64 ts_us;         // 时间戳 (微秒)
    u32 pid;           // 进程ID
    u32 tid;           // 线程ID
    u64 bytes;         // 传输字节数
    u32 saddr;         // 源IP
    u32 daddr;         // 目标IP
    u16 sport;         // 源端口
    u16 dport;         // 目标端口
    u8 is_tx;          // 传输方向: 0=接收, 1=发送
    u8 protocol;       // 协议: 0=不适用, 6=TCP, 17=UDP
    char comm[TASK_COMM_LEN]; // 命令名称
};

// 网络延迟统计
struct latency_stat_t {
    u64 connect_time;  // 连接建立时间
    u64 total_time;    // 总时间
    u64 count;         // 计数
};

// 网络数据统计(按进程)
struct network_stat_t {
    u64 rx_bytes;      // 接收字节数
    u64 tx_bytes;      // 发送字节数
    u64 rx_packets;    // 接收数据包数量
    u64 tx_packets;    // 发送数据包数量
    u64 retransmits;   // 重传次数
};

// 连接追踪
BPF_HASH(conn_track, u64, struct conn_info_t);

// 每个进程的网络统计
BPF_HASH(net_stats, u32, struct network_stat_t);

// 输出连接事件
BPF_PERF_OUTPUT(conn_events);

// 输出数据传输事件
BPF_PERF_OUTPUT(data_events);

// 获取进程ID和线程ID
static inline u64 get_pid_tgid() {
    return bpf_get_current_pid_tgid();
}

// 获取用户ID
static inline u32 get_uid() {
    return bpf_get_current_uid_gid() & 0xFFFFFFFF;
}

// 获取IPv4地址族套接字地址信息
static void get_ipv4_sock_addr(struct sock *sk, u32 *saddr, u32 *daddr, u16 *sport, u16 *dport) {
    *saddr = sk->__sk_common.skc_rcv_saddr;
    *daddr = sk->__sk_common.skc_daddr;
    
    // 获取端口信息(注意大小端转换)
    struct inet_sock *inet = (struct inet_sock *)sk;
    *sport = inet->inet_sport;
    *sport = (*sport >> 8) | (((*sport << 8) & 0xff00));
    *dport = sk->__sk_common.skc_dport;
    *dport = (*dport >> 8) | (((*dport << 8) & 0xff00));
}

// 跟踪TCP连接建立(connect)
int trace_connect_entry(struct pt_regs *ctx, struct sock *sk) {
    u64 pid_tgid = get_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = pid_tgid & 0xFFFFFFFF;
    
    // 检查目标PID
    u32 target_pid = PID_FILTER;
    if (target_pid > 0 && pid != target_pid) {
        return 0;
    }
    
    // 只跟踪IPv4 TCP连接
    if (sk->__sk_common.skc_family != AF_INET && sk->__sk_common.skc_family != AF_INET6) {
        return 0;
    }
    
    // 获取连接信息
    struct conn_info_t conn_info = {};
    conn_info.ts_us = bpf_ktime_get_ns() / 1000;
    conn_info.pid = pid;
    conn_info.tid = tid;
    conn_info.uid = get_uid();
    conn_info.family = sk->__sk_common.skc_family;
    conn_info.protocol = sk->__sk_common.skc_protocol;
    conn_info.type = 1;  // 连接事件
    
    // 获取IP地址和端口信息
    get_ipv4_sock_addr(sk, &conn_info.saddr, &conn_info.daddr, &conn_info.sport, &conn_info.dport);
    
    // 发送事件通知
    conn_events.perf_submit(ctx, &conn_info, sizeof(conn_info));
    
    // 更新连接跟踪
    u64 conn_id = (u64)sk;
    conn_track.update(&conn_id, &conn_info);
    
    return 0;
}

// 跟踪TCP接收(tcp_recvmsg)
int trace_tcp_receive(struct pt_regs *ctx, struct sock *sk, struct msghdr *msg, 
                     size_t len, int flags, int *addr_len) {
    u64 pid_tgid = get_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = pid_tgid & 0xFFFFFFFF;
    
    // 检查目标PID
    u32 target_pid = PID_FILTER;
    if (target_pid > 0 && pid != target_pid) {
        return 0;
    }
    
    // 确保它是TCP套接字
    if (sk->__sk_common.skc_protocol != IPPROTO_TCP) {
        return 0;
    }
    
    // 创建数据传输事件
    struct data_info_t data_info = {};
    data_info.ts_us = bpf_ktime_get_ns() / 1000;
    data_info.pid = pid;
    data_info.tid = tid;
    data_info.bytes = len;
    data_info.is_tx = 0;  // 接收
    data_info.protocol = IPPROTO_TCP;
    bpf_get_current_comm(&data_info.comm, sizeof(data_info.comm));
    
    // 获取源和目的地址信息
    get_ipv4_sock_addr(sk, &data_info.saddr, &data_info.daddr, &data_info.sport, &data_info.dport);
    
    // 发送数据事件通知
    data_events.perf_submit(ctx, &data_info, sizeof(data_info));
    
    // 更新网络统计
    struct network_stat_t *stats, zero = {};
    stats = net_stats.lookup_or_init(&pid, &zero);
    stats->rx_bytes += len;
    stats->rx_packets++;
    
    return 0;
}

// 跟踪TCP发送(tcp_sendmsg)
int trace_tcp_send(struct pt_regs *ctx, struct sock *sk, struct msghdr *msg, size_t size) {
    u64 pid_tgid = get_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = pid_tgid & 0xFFFFFFFF;
    
    // 检查目标PID
    u32 target_pid = PID_FILTER;
    if (target_pid > 0 && pid != target_pid) {
        return 0;
    }
    
    // 确保它是TCP套接字
    if (sk->__sk_common.skc_protocol != IPPROTO_TCP) {
        return 0;
    }
    
    // 创建数据传输事件
    struct data_info_t data_info = {};
    data_info.ts_us = bpf_ktime_get_ns() / 1000;
    data_info.pid = pid;
    data_info.tid = tid;
    data_info.bytes = size;
    data_info.is_tx = 1;  // 发送
    data_info.protocol = IPPROTO_TCP;
    bpf_get_current_comm(&data_info.comm, sizeof(data_info.comm));
    
    // 获取源和目的地址信息
    get_ipv4_sock_addr(sk, &data_info.saddr, &data_info.daddr, &data_info.sport, &data_info.dport);
    
    // 发送数据事件通知
    data_events.perf_submit(ctx, &data_info, sizeof(data_info));
    
    // 更新网络统计
    struct network_stat_t *stats, zero = {};
    stats = net_stats.lookup_or_init(&pid, &zero);
    stats->tx_bytes += size;
    stats->tx_packets++;
    
    return 0;
}

// 跟踪UDP接收(udp_recvmsg)
int trace_udp_receive(struct pt_regs *ctx, struct sock *sk, struct msghdr *msg, 
                     size_t len, int flags, int *addr_len) {
    u64 pid_tgid = get_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = pid_tgid & 0xFFFFFFFF;
    
    // 检查目标PID
    u32 target_pid = PID_FILTER;
    if (target_pid > 0 && pid != target_pid) {
        return 0;
    }
    
    // 确保它是UDP套接字
    if (sk->__sk_common.skc_protocol != IPPROTO_UDP) {
        return 0;
    }
    
    // 创建数据传输事件
    struct data_info_t data_info = {};
    data_info.ts_us = bpf_ktime_get_ns() / 1000;
    data_info.pid = pid;
    data_info.tid = tid;
    data_info.bytes = len;
    data_info.is_tx = 0;  // 接收
    data_info.protocol = IPPROTO_UDP;
    bpf_get_current_comm(&data_info.comm, sizeof(data_info.comm));
    
    // 获取源和目的地址信息
    get_ipv4_sock_addr(sk, &data_info.saddr, &data_info.daddr, &data_info.sport, &data_info.dport);
    
    // 发送数据事件通知
    data_events.perf_submit(ctx, &data_info, sizeof(data_info));
    
    // 更新网络统计
    struct network_stat_t *stats, zero = {};
    stats = net_stats.lookup_or_init(&pid, &zero);
    stats->rx_bytes += len;
    stats->rx_packets++;
    
    return 0;
}

// 跟踪UDP发送(udp_sendmsg)
int trace_udp_send(struct pt_regs *ctx, struct sock *sk, struct msghdr *msg, size_t size) {
    u64 pid_tgid = get_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = pid_tgid & 0xFFFFFFFF;
    
    // 检查目标PID
    u32 target_pid = PID_FILTER;
    if (target_pid > 0 && pid != target_pid) {
        return 0;
    }
    
    // 确保它是UDP套接字
    if (sk->__sk_common.skc_protocol != IPPROTO_UDP) {
        return 0;
    }
    
    // 创建数据传输事件
    struct data_info_t data_info = {};
    data_info.ts_us = bpf_ktime_get_ns() / 1000;
    data_info.pid = pid;
    data_info.tid = tid;
    data_info.bytes = size;
    data_info.is_tx = 1;  // 发送
    data_info.protocol = IPPROTO_UDP;
    bpf_get_current_comm(&data_info.comm, sizeof(data_info.comm));
    
    // 获取源和目的地址信息
    get_ipv4_sock_addr(sk, &data_info.saddr, &data_info.daddr, &data_info.sport, &data_info.dport);
    
    // 发送数据事件通知
    data_events.perf_submit(ctx, &data_info, sizeof(data_info));
    
    // 更新网络统计
    struct network_stat_t *stats, zero = {};
    stats = net_stats.lookup_or_init(&pid, &zero);
    stats->tx_bytes += size;
    stats->tx_packets++;
    
    return 0;
}

// 跟踪TCP重传
int trace_tcp_retransmit(struct pt_regs *ctx, struct sock *sk) {
    u64 pid_tgid = get_pid_tgid();
    u32 pid = pid_tgid >> 32;
    
    // 该函数在网络栈的下层运行，可能与实际进程无关
    // 我们需要从套接字获取所有者信息
    sk = (struct sock *)PT_REGS_PARM1(ctx);
    if (!sk) 
        return 0;
    
    // 获取该套接字的进程ID（可能为0表示内核）
    pid = sk->__sk_common.skc_pid;
    if (pid == 0)
        return 0;
        
    // 检查目标PID
    u32 target_pid = PID_FILTER;
    if (target_pid > 0 && pid != target_pid) {
        return 0;
    }
    
    // 更新重传统计
    struct network_stat_t *stats, zero = {};
    stats = net_stats.lookup_or_init(&pid, &zero);
    stats->retransmits++;
    
    return 0;
}
"""

# 连接信息结构
class ConnInfo(ct.Structure):
    _fields_ = [
        ("ts_us", ct.c_ulonglong),
        ("pid", ct.c_uint),
        ("tid", ct.c_uint),
        ("uid", ct.c_uint),
        ("saddr", ct.c_uint),
        ("daddr", ct.c_uint),
        ("sport", ct.c_ushort),
        ("dport", ct.c_ushort),
        ("family", ct.c_ushort),
        ("protocol", ct.c_ubyte),
        ("type", ct.c_ubyte),
    ]

# 数据传输信息结构
class DataInfo(ct.Structure):
    _fields_ = [
        ("ts_us", ct.c_ulonglong),
        ("pid", ct.c_uint),
        ("tid", ct.c_uint),
        ("bytes", ct.c_ulonglong),
        ("saddr", ct.c_uint),
        ("daddr", ct.c_uint),
        ("sport", ct.c_ushort),
        ("dport", ct.c_ushort),
        ("is_tx", ct.c_ubyte),
        ("protocol", ct.c_ubyte),
        ("comm", ct.c_char * 16),
    ]

# 网络统计结构
class NetworkStat(ct.Structure):
    _fields_ = [
        ("rx_bytes", ct.c_ulonglong),
        ("tx_bytes", ct.c_ulonglong),
        ("rx_packets", ct.c_ulonglong),
        ("tx_packets", ct.c_ulonglong),
        ("retransmits", ct.c_ulonglong),
    ]

def parse_args():
    parser = argparse.ArgumentParser(
        description="网络性能分析工具 - 监控网络连接和数据传输")
    parser.add_argument("pid", type=int, nargs="?", default=0,
        help="要监控的进程ID (0表示所有进程)")
    parser.add_argument("-d", "--duration", type=int, default=10,
        help="监控持续时间(秒)")
    parser.add_argument("-i", "--interval", type=int, default=5,
        help="报告间隔(秒)")
    parser.add_argument("-v", "--verbose", action="store_true",
        help="显示详细的网络事件")
    parser.add_argument("-t", "--top", type=int, default=10,
        help="显示网络使用最多的前N个进程")
    return parser.parse_args()

def inet_ntoa(addr):
    return socket.inet_ntoa(struct.pack("I", addr))

def print_conn_event(cpu, data, size):
    try:
        event = ct.cast(data, ct.POINTER(ConnInfo)).contents
        
        # 解析事件类型
        event_type = "未知"
        if event.type == 1:
            event_type = "连接"
        elif event.type == 2:
            event_type = "接收"
        elif event.type == 3:
            event_type = "发送"
        elif event.type == 4:
            event_type = "关闭"
        elif event.type == 5:
            event_type = "重传"
        
        # 解析协议
        proto = "未知"
        if event.protocol == socket.IPPROTO_TCP:
            proto = "TCP"
        elif event.protocol == socket.IPPROTO_UDP:
            proto = "UDP"
        
        # 打印事件
        logging.info(f"[{datetime.fromtimestamp(event.ts_us / 1e6).strftime('%H:%M:%S.%f')}] "
              f"PID {event.pid} {event_type} {proto} "
              f"{inet_ntoa(event.saddr)}:{event.sport} -> "
              f"{inet_ntoa(event.daddr)}:{event.dport}")
    except Exception as e:
        logging.error(f"处理连接事件时出错: {str(e)}")

def print_data_event(cpu, data, size):
    try:
        event = ct.cast(data, ct.POINTER(DataInfo)).contents
        
        # 解析方向和协议
        direction = "发送" if event.is_tx else "接收"
        proto = "TCP" if event.protocol == socket.IPPROTO_TCP else "UDP" if event.protocol == socket.IPPROTO_UDP else "未知"
        
        # 打印事件
        logging.info(f"[{datetime.fromtimestamp(event.ts_us / 1e6).strftime('%H:%M:%S.%f')}] "
              f"{event.comm.decode('utf-8', 'replace')} ({event.pid}) {direction} {proto} "
              f"{inet_ntoa(event.saddr)}:{event.sport} -> "
              f"{inet_ntoa(event.daddr)}:{event.dport} "
              f"{event.bytes:,} 字节")
    except Exception as e:
        logging.error(f"处理数据事件时出错: {str(e)}")

def generate_network_summary(b, args):
    """生成网络使用摘要报告"""
    try:
        # 获取网络统计
        net_stats = b.get_table("net_stats")
        
        # 转换为Python字典以便处理
        pid_stats = {}
        for pid, stats in net_stats.items():
            stats_obj = ct.cast(stats, ct.POINTER(NetworkStat)).contents
            
            pid_stats[pid.value] = {
                "rx_bytes": stats_obj.rx_bytes,
                "tx_bytes": stats_obj.tx_bytes,
                "rx_packets": stats_obj.rx_packets,
                "tx_packets": stats_obj.tx_packets,
                "retransmits": stats_obj.retransmits,
                "total_bytes": stats_obj.rx_bytes + stats_obj.tx_bytes
            }
        
        # 按总流量排序
        sorted_stats = sorted(pid_stats.items(), key=lambda x: x[1]["total_bytes"], reverse=True)
        
        # 打印进程网络统计信息
        logging.info("\n===== 进程网络统计 =====")
        logging.info(f"{'PID':<7} {'进程名':<16} {'接收':>12} {'发送':>12} {'总流量':>12} {'数据包':>10} {'重传':>8} {'重传率%':>10}")
        logging.info("-" * 90)
        
        for pid, stat in sorted_stats[:args.top]:
            try:
                with open(f"/proc/{pid}/comm", "r") as f:
                    comm = f.read().strip()
            except:
                comm = "[未知]"
            
            # 计算统计数据
            rx_human = human_readable_size(stat["rx_bytes"])
            tx_human = human_readable_size(stat["tx_bytes"])
            total_human = human_readable_size(stat["rx_bytes"] + stat["tx_bytes"])
            total_packets = stat["rx_packets"] + stat["tx_packets"]
            retrans_rate = 0
            if stat["tx_packets"] > 0:
                retrans_rate = (stat["retransmits"] / stat["tx_packets"]) * 100
                
            logging.info(f"{pid:<7} {comm[:15]:<16} {rx_human:>12} {tx_human:>12} {total_human:>12} "
                  f"{total_packets:>10,d} {stat['retransmits']:>8,d} {retrans_rate:>10.2f}")
        
        return sorted_stats
    except Exception as e:
        logging.error(f"生成网络摘要时出错: {str(e)}")
        return None

def main():
    args = parse_args()
    
    # 设置日志
    setup_logging(args.verbose)
    
    # 参数校验
    if not validate_args(args):
        return 1
    
    logging.info(f"开始监控{'PID ' + str(args.pid) if args.pid else '所有进程'} 的网络活动...")
    logging.info(f"监控持续时间: {args.duration}秒")
    logging.info(f"报告间隔: {args.interval}秒")
    
    try:
        # 替换eBPF程序中的PID过滤器
        bpf_program = bpf_text.replace('PID_FILTER', str(args.pid))
        
        # 加载eBPF程序
        b = BPF(text=bpf_program)
        
        # 附加探针
        b.attach_kprobe(event="tcp_v4_connect", fn_name="trace_connect_entry")
        b.attach_kprobe(event="tcp_v6_connect", fn_name="trace_connect_entry")
        b.attach_kprobe(event="tcp_recvmsg", fn_name="trace_tcp_receive")
        b.attach_kprobe(event="tcp_sendmsg", fn_name="trace_tcp_send")
        b.attach_kprobe(event="udp_recvmsg", fn_name="trace_udp_receive")
        b.attach_kprobe(event="udp_sendmsg", fn_name="trace_udp_send")
        b.attach_kprobe(event="tcp_retransmit_skb", fn_name="trace_tcp_retransmit")
        
        # 设置回调
        if args.verbose:
            b["conn_events"].open_perf_buffer(print_conn_event)
            b["data_events"].open_perf_buffer(print_data_event)
        
        # 记录启动时间
        start_time = datetime.now()
        logging.info(f"开始时间: {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
        
        if args.verbose:
            logging.info("\n== 开始实时网络活动监控 ==\n")
        
        # 定义用于清理资源的函数
        def cleanup():
            if 'b' in locals():
                b.cleanup()
        
        # 设置信号处理器，确保资源正确清理
        setup_signal_handler(cleanup)
        
        # 定义定期报告函数
        next_report = time.time() + args.interval
        
        def periodic_report():
            nonlocal next_report
            if time.time() >= next_report:
                elapsed = (datetime.now() - start_time).total_seconds()
                logging.info(f"\n===== 中间报告 ({elapsed:.1f}秒) =====")
                generate_network_summary(b, args)
                next_report = time.time() + args.interval
        
        # 监控指定的时间
        try:
            while (datetime.now() - start_time).total_seconds() < args.duration:
                if args.verbose:
                    b.perf_buffer_poll(timeout=100)
                else:
                    # 如果不需要详细输出，使用sleep节省资源
                    time.sleep(0.1)
                periodic_report()
        except KeyboardInterrupt:
            logging.warning("监控被用户中断")
        
        end_time = datetime.now()
        logging.info(f"\n结束时间: {end_time.strftime('%Y-%m-%d %H:%M:%S')}")
        elapsed = (end_time - start_time).total_seconds()
        logging.info(f"总监控时间: {elapsed:.2f}秒")
        
        # 最终报告
        logging.info("\n===== 最终网络统计报告 =====")
        generate_network_summary(b, args)
        
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