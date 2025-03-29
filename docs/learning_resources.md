# eBPF学习资源

本文档汇总了学习eBPF技术的各种资源，帮助您深入了解eBPF的工作原理和应用场景。

## 官方文档和网站

- [eBPF官方网站](https://ebpf.io/) - eBPF的官方网站，包含基本概念和教程
- [BCC参考指南](https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md) - BCC工具的详细参考指南
- [BPF和XDP参考指南](https://docs.cilium.io/en/stable/bpf/) - Cilium项目的BPF文档
- [Linux内核BPF文档](https://www.kernel.org/doc/html/latest/bpf/index.html) - Linux内核的BPF子系统文档

## 入门教程

- [什么是eBPF](https://ebpf.io/what-is-ebpf/) - eBPF技术的简要介绍
- [eBPF.io学习路径](https://ebpf.io/get-started) - 从零开始学习eBPF的路径
- [Brendan Gregg的BPF教程](https://www.brendangregg.com/bpf-performance-tools-book.html) - 性能分析专家的BPF教程
- [学习eBPF编程](https://github.com/lizrice/learning-ebpf) - Liz Rice的eBPF编程入门教程
- [BCC教程](https://github.com/iovisor/bcc/blob/master/docs/tutorial.md) - BCC项目的官方教程

## 书籍

- [Linux可观测性与eBPF](https://www.oreilly.com/library/view/linux-observability-with/9781492050193/) - eBPF的可观测性应用
- [BPF性能工具](http://www.brendangregg.com/bpf-performance-tools-book.html) - Brendan Gregg的BPF性能工具书籍
- [用eBPF进行系统编程](https://www.manning.com/books/systems-programming-with-ebpf) - eBPF系统编程指南

## 视频教程

- [eBPF入门](https://www.youtube.com/watch?v=WnJl7bWLZbo) - eBPF基础知识讲解
- [Brendan Gregg的BPF性能工具](https://www.youtube.com/watch?v=JRFNIKUROPE) - BPF性能分析工具讲解
- [使用eBPF观测Kubernetes](https://www.youtube.com/watch?v=cxuM4zxPdsQ) - eBPF在Kubernetes中的应用
- [eBPF和XDP介绍](https://www.youtube.com/watch?v=YjjdZxoaFfw) - eBPF和XDP技术详解

## 在线课程

- [Linux基金会eBPF课程](https://training.linuxfoundation.org/training/linux-kernel-debugging-ebpf-tracing/) - Linux基金会提供的eBPF培训
- [Udemy eBPF编程课程](https://www.udemy.com/course/linux-kernel-programming-with-ebpf/) - eBPF内核编程课程
- [edX Linux性能监控](https://www.edx.org/course/linux-performance-monitoring-and-analysis) - 使用eBPF的Linux性能监控课程

## 博客和文章

- [Brendan Gregg的博客](http://www.brendangregg.com/ebpf.html) - 性能专家关于eBPF的文章
- [Cilium博客](https://cilium.io/blog/) - Cilium项目相关的eBPF应用文章
- [LWN上的eBPF文章](https://lwn.net/Kernel/Index/#Berkeley_Packet_Filter) - Linux Weekly News上的eBPF文章
- [Cloudflare如何使用eBPF](https://blog.cloudflare.com/tag/ebpf/) - Cloudflare的eBPF实践文章

## 开源项目和示例

- [BCC工具集](https://github.com/iovisor/bcc) - BPF编译器集合，包含大量实用工具
- [bpftrace](https://github.com/iovisor/bpftrace) - 用于Linux的DTrace/SystemTap类高级跟踪语言
- [Cilium](https://github.com/cilium/cilium) - 基于eBPF的云原生网络、安全和可观测性
- [Falco](https://github.com/falcosecurity/falco) - 使用eBPF的云原生运行时安全项目
- [Katran](https://github.com/facebookincubator/katran) - Facebook的高性能第4层负载均衡器
- [Pixie](https://github.com/pixie-io/pixie) - 使用eBPF的Kubernetes应用可观测性平台
- [eBPF Exporter](https://github.com/cloudflare/ebpf_exporter) - Cloudflare的eBPF指标导出器

## 社区和论坛

- [IO Visor邮件列表](https://lists.iovisor.org/g/iovisor-dev) - eBPF和BCC相关的讨论
- [eBPF Slack频道](https://ebpf.io/slack) - eBPF社区的Slack频道
- [eBPF Github讨论](https://github.com/topics/ebpf) - Github上关于eBPF的讨论和项目
- [StackOverflow eBPF标签](https://stackoverflow.com/questions/tagged/ebpf) - StackOverflow上的eBPF问答

## 会议和演讲

- [eBPF Summit](https://ebpf.io/summit/) - 专注于eBPF的年度峰会
- [Linux Plumbers Conference](https://www.linuxplumbersconf.org/) - 常有eBPF相关主题
- [KubeCon + CloudNativeCon](https://www.cncf.io/kubecon-cloudnativecon-events/) - 云原生领域中eBPF应用的演讲

## 学习路径建议

如果您是eBPF初学者，建议按照以下顺序学习：

1. **基础概念**: 阅读eBPF官方网站上的"什么是eBPF"
2. **入门实践**: 学习BCC工具使用方法和简单的eBPF程序编写
3. **深入理解**: 阅读《BPF性能工具》或《Linux可观测性与eBPF》
4. **实际应用**: 尝试修改和扩展现有eBPF程序，解决实际问题
5. **高级主题**: 学习XDP、BTF等高级特性和优化技术

## 实践项目创意

以下是一些练习eBPF技能的项目创意：

1. 创建一个系统调用审计工具
2. 实现一个网络流量分析器
3. 开发一个容器资源使用监控工具
4. 构建一个应用性能分析器
5. 编写一个安全威胁检测系统
6. 设计一个网络数据包过滤器
7. 实现一个自定义的负载均衡器

## eBPF工具生态系统

eBPF工具可以分为以下几类：

- **性能分析**: `profile`, `trace`, `funccount`
- **网络分析**: `tcptracer`, `tcpconnect`, `tcptop`
- **I/O分析**: `biosnoop`, `iosnoop`, `fileslower`
- **CPU分析**: `cpudist`, `hardirqs`, `softirqs`
- **安全监控**: `opensnoop`, `execsnoop`, `modinfo`
- **内存分析**: `memleak`, `cachestat`, `mmapsnoop`

## eBPF的未来发展

eBPF技术正在快速发展，未来趋势包括：

- 更多的内核支持和功能扩展
- 更好的开发工具和调试支持
- 在云原生和边缘计算领域的广泛应用
- 与其他技术如AI/ML的结合
- 更强大的安全和可观测性能力 