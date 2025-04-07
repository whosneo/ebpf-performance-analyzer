 #!/usr/bin/env python3
# eBPF公共模块单元测试

import unittest
import sys
import os
import logging
import tempfile
from unittest.mock import patch, MagicMock

# 导入公共模块
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
from src.ebpf_common import (
    setup_logging, validate_pid, validate_duration, validate_interval,
    validate_top_count, validate_args, human_readable_size, BaseAnalyzer
)

class TestEbpfCommon(unittest.TestCase):
    """测试eBPF公共模块的功能"""
    
    def test_setup_logging(self):
        """测试日志设置功能"""
        # 测试普通日志级别
        logger = setup_logging(verbose=False)
        self.assertEqual(logger.level, logging.INFO)
        
        # 测试详细日志级别
        logger = setup_logging(verbose=True)
        self.assertEqual(logger.level, logging.DEBUG)
    
    def test_validate_pid(self):
        """测试PID验证功能"""
        # 有效的PID 0（所有进程）应该通过
        self.assertEqual(validate_pid(0), 0)
        
        # 无效的负数PID应该抛出异常
        with self.assertRaises(ValueError):
            validate_pid(-1)
        
        # 测试不存在的PID
        # 注意：需要临时模拟os.path.exists返回False
        with patch('os.path.exists', return_value=False):
            with self.assertRaises(ValueError):
                validate_pid(999999)  # 假设这个PID不存在
    
    def test_validate_duration(self):
        """测试持续时间验证功能"""
        # 有效的持续时间应该通过
        self.assertEqual(validate_duration(10), 10)
        self.assertEqual(validate_duration(60), 60)
        
        # 无效的持续时间应该抛出异常
        with self.assertRaises(ValueError):
            validate_duration(0)
        with self.assertRaises(ValueError):
            validate_duration(-1)
    
    def test_validate_interval(self):
        """测试时间间隔验证功能"""
        # 有效的时间间隔应该通过
        self.assertEqual(validate_interval(1), 1)
        self.assertEqual(validate_interval(5), 5)
        
        # 无效的时间间隔应该抛出异常
        with self.assertRaises(ValueError):
            validate_interval(0)
        with self.assertRaises(ValueError):
            validate_interval(-1)
    
    def test_validate_top_count(self):
        """测试显示数量验证功能"""
        # 有效的显示数量应该通过
        self.assertEqual(validate_top_count(1), 1)
        self.assertEqual(validate_top_count(10), 10)
        
        # 无效的显示数量应该抛出异常
        with self.assertRaises(ValueError):
            validate_top_count(0)
        with self.assertRaises(ValueError):
            validate_top_count(-1)
    
    def test_validate_args(self):
        """测试参数验证功能"""
        # 创建一个模拟的参数对象
        args = MagicMock()
        args.pid = 0
        args.duration = 60
        args.interval = 5
        args.top = 10
        
        # 有效的参数应该返回True
        self.assertTrue(validate_args(args))
        
        # 无效的PID应该返回False
        args.pid = -1
        with patch('logging.error'):  # 忽略日志输出
            self.assertFalse(validate_args(args))
        
        # 恢复有效的PID但设置无效的持续时间
        args.pid = 0
        args.duration = 0
        with patch('logging.error'):
            self.assertFalse(validate_args(args))
    
    def test_human_readable_size(self):
        """测试人类可读的大小格式化功能"""
        # 测试各种大小单位
        self.assertEqual(human_readable_size(0), "0.00 B")
        self.assertEqual(human_readable_size(1023), "1023.00 B")
        self.assertEqual(human_readable_size(1024), "1.00 KB")
        self.assertEqual(human_readable_size(1024 * 1024), "1.00 MB")
        self.assertEqual(human_readable_size(1024 * 1024 * 1024), "1.00 GB")
        self.assertEqual(human_readable_size(1024 * 1024 * 1024 * 1024), "1.00 TB")
    
    def test_base_analyzer(self):
        """测试BaseAnalyzer类的基本功能"""
        # 创建一个BaseAnalyzer的子类实例
        analyzer = BaseAnalyzer("测试分析器", "测试分析器描述")
        
        # 测试基本属性
        self.assertEqual(analyzer.name, "测试分析器")
        self.assertEqual(analyzer.description, "测试分析器描述")
        self.assertIsNone(analyzer.logger)
        self.assertIsNone(analyzer.bpf)
        self.assertIsNone(analyzer.args)
        
        # 测试方法（注意这些方法在BaseAnalyzer中可能是抽象的）
        with self.assertRaises(NotImplementedError):
            analyzer.run()

if __name__ == '__main__':
    unittest.main()