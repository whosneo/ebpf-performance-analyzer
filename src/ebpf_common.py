#!/usr/bin/env python3
# eBPF性能分析器公共模块
#
# 该模块提供eBPF性能分析工具的共享功能，包括日志设置、
# 参数验证、错误处理和资源管理等公共功能。

import sys
import logging
import argparse
import os
import signal
from bcc import BPF
from datetime import datetime
import time

def setup_logging(verbose=False):
    """设置日志记录"""
    log_level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    return logging.getLogger()

def validate_pid(pid):
    """验证进程ID是否有效"""
    if pid < 0:
        raise ValueError("PID必须为非负数")
    if pid > 0 and not os.path.exists(f"/proc/{pid}"):
        raise ValueError(f"PID {pid} 不存在或无法访问")
    return pid

def validate_duration(duration):
    """验证监控持续时间"""
    if duration <= 0:
        raise ValueError("监控时长必须大于0")
    return duration

def validate_interval(interval):
    """验证报告间隔"""
    if interval <= 0:
        raise ValueError("报告间隔必须大于0")
    return interval

def validate_top_count(top):
    """验证显示数量"""
    if top <= 0:
        raise ValueError("显示数量必须大于0")
    return top

def validate_args(args):
    """验证命令行参数"""
    try:
        if hasattr(args, 'pid'):
            args.pid = validate_pid(args.pid)
        if hasattr(args, 'duration'):
            args.duration = validate_duration(args.duration)
        if hasattr(args, 'interval'):
            args.interval = validate_interval(args.interval)
        if hasattr(args, 'top'):
            args.top = validate_top_count(args.top)
        return True
    except ValueError as e:
        logging.error(f"参数验证错误: {str(e)}")
        return False

def safe_load_bpf(bpf_text, args):
    """安全加载eBPF程序，处理可能的错误"""
    try:
        # 替换常见的占位符
        if hasattr(args, 'pid'):
            bpf_text = bpf_text.replace('PID_FILTER', str(args.pid))
        
        # 尝试加载BPF程序
        return BPF(text=bpf_text)
    except Exception as e:
        logging.error(f"加载BPF程序失败: {str(e)}")
        if 'Permission denied' in str(e):
            logging.error("可能需要root权限运行此程序")
        elif 'Failed to compile BPF module' in str(e):
            logging.error("BPF程序编译失败，请检查内核版本兼容性")
        raise

def handle_common_args(parser):
    """添加各分析器共有的命令行参数"""
    parser.add_argument("pid", type=int, nargs="?", default=0,
        help="要监控的进程ID (0表示所有进程)")
    parser.add_argument("-d", "--duration", type=int, default=60,
        help="监控持续时间(秒)")
    parser.add_argument("-i", "--interval", type=int, default=5,
        help="报告间隔(秒)")
    parser.add_argument("-t", "--top", type=int, default=10,
        help="显示前N个项目")
    parser.add_argument("-v", "--verbose", action="store_true",
        help="启用详细日志输出")
    return parser

def human_readable_size(size_bytes):
    """将字节大小转换为人类可读的形式"""
    if size_bytes < 0:
        return "0 B"
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size_bytes < 1024.0:
            return f"{size_bytes:.2f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.2f} PB"

def setup_signal_handler(cleanup_func):
    """设置信号处理器，确保程序正确退出"""
    def signal_handler(sig, frame):
        logging.warning("监控被用户中断")
        if cleanup_func:
            cleanup_func()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    return signal_handler

def run_monitoring_loop(b, duration, interval, callback=None):
    """运行监控循环"""
    start_time = time.time()
    logging.info(f"开始时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    next_report = start_time + interval
    
    try:
        while time.time() - start_time < duration:
            b.perf_buffer_poll(timeout=1000)
            
            # 定期回调
            if callback and time.time() >= next_report:
                callback()
                next_report = time.time() + interval
                
    except KeyboardInterrupt:
        logging.warning("监控被用户中断")
        return False
    except Exception as e:
        logging.exception(f"监控过程中发生错误: {str(e)}")
        return False
    
    return True

class BaseAnalyzer:
    """性能分析器基类"""
    
    def __init__(self, name, description):
        self.name = name
        self.description = description
        self.logger = None
        self.bpf = None
        self.args = None
    
    def setup_args(self):
        """设置命令行参数解析器"""
        parser = argparse.ArgumentParser(description=self.description)
        return handle_common_args(parser)
    
    def parse_args(self):
        """解析命令行参数"""
        parser = self.setup_args()
        self.args = parser.parse_args()
        return self.args
    
    def validate_args(self):
        """验证命令行参数"""
        return validate_args(self.args)
    
    def setup_logging(self):
        """设置日志记录"""
        self.logger = setup_logging(self.args.verbose)
        return self.logger
    
    def load_bpf(self, bpf_text):
        """加载BPF程序"""
        self.bpf = safe_load_bpf(bpf_text, self.args)
        return self.bpf
    
    def cleanup(self):
        """清理资源"""
        if self.bpf:
            self.bpf.cleanup()
    
    def run(self):
        """运行分析器"""
        raise NotImplementedError("子类必须实现此方法") 