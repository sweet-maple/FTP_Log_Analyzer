# FTP Traffic Analysis Script

这是一个用于 CTF 比赛或取证分析的 Python 脚本，用于从 PCAP 流量包中提取 FTP 文件传输记录和操作日志。

## 功能

*   解析 PCAP 文件中的 FTP 协议流量。
*   提取 FTP 会话信息。
*   记录文件传输详情。
*   生成 CSV 格式的分析报告。

## 依赖

*   Python 3.x
*   [PyShark](https://github.com/KimiNewt/pyshark)
*   [Wireshark](https://www.wireshark.org/) (TShark)

## 安装与配置

### 1. 环境准备

本项目使用 `uv` 进行包管理（也可以使用 pip）。

```bash
# 安装依赖
uv add pyshark
```

### 2. 关于 TShark 路径

脚本默认设计为与 **Wireshark Portable** 配合使用，期望目录结构如下：

```text
.
├── FTP-analysis.py
├── sample.pcap
└── App/
    └── Wireshark/
        └── tshark.exe
```

**如果你没有将脚本放在 Wireshark Portable 目录下：**

你需要修改 `FTP-analysis.py` 中的 `tshark_executable_path` 设置，或者确保 `tshark` 已经添加到系统的环境变量 PATH 中，并修改脚本移除自定义路径查找逻辑。

## 使用方法

```bash
uv run FTP-analysis.py
```

脚本会自动寻找同目录下的 `sample.pcap`（或其他在代码中指定的文件）进行分析。

## 注意事项

*   `sample.pcap` 为样例数据。
