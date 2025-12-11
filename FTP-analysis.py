import pyshark
import sys
import os # 新增导入
from datetime import datetime
import csv  # 新增导入

def analyze_ftp_pcap(pcap_file):
    """
    分析 pcap 文件，提取 FTP 文件传输记录。
    会使用与本脚本同一目录下的 tshark 可执行文件。

    参数:
    pcap_file (str): pcap 文件的路径。
    """
    # --- 新增部分：构建并验证本地 TShark 路径 ---
    try:
        # 获取脚本所在的目录 (现在应该是 WiresharkPortable 的根目录)
        script_dir = os.path.dirname(os.path.abspath(__file__))

        # 根据操作系统确定 tshark 的文件名
        tshark_name = "tshark.exe" if sys.platform == "win32" else "tshark"

        # 拼接成完整的 tshark 可执行文件路径 (指向 App/Wireshark 子目录)
        tshark_executable_path = os.path.join(script_dir, "App", "Wireshark", tshark_name)
        print(f"[*] 尝试使用 TShark 路径: {tshark_executable_path}")
        # 检查 tshark 是否真的存在于该路径

    except Exception as e:
        print(f"[错误] 查找本地 TShark 路径时出错: {e}")
        return
    # --- 修改结束 ---

    # 字典用于跟踪每个 FTP 会话的状态
    ftp_sessions = {}
    
    # 列表用于存储最终的传输日志
    transfer_logs = []
    # 新增：用于存储所有FTP操作日志
    all_ftp_logs = []

    print(f"[*] 正在打开抓包文件: {pcap_file}")
    print(f"[*] 使用 TShark 路径: {tshark_executable_path}") # 告知用户正在使用的路径

    try:
        # 在调用 FileCapture 时，通过 tshark_path 参数指定路径
        capture = pyshark.FileCapture(
            pcap_file, 
            display_filter='ftp',
            tshark_path=tshark_executable_path # <--- 核心修改点
        )

        for packet in capture:
            try:
                # (后续逻辑与之前完全相同，此处省略以保持简洁)
                # --- 确定会话标识符 ---
                if packet.tcp.dstport == '21':
                    client_ip = packet.ip.src
                    client_port = packet.tcp.srcport
                    server_ip = packet.ip.dst
                    server_port = packet.tcp.dstport
                elif packet.tcp.srcport == '21':
                    client_ip = packet.ip.dst
                    client_port = packet.tcp.dstport
                    server_ip = packet.ip.src
                    server_port = packet.tcp.srcport
                else:
                    continue

                session_key = (client_ip, client_port, server_ip, server_port)

                if session_key not in ftp_sessions:
                    ftp_sessions[session_key] = {'username': None}

                # --- 检查 FTP 命令 ---
                if hasattr(packet.ftp, 'request_command') and packet.ftp.request_command == 'USER':
                    username = packet.ftp.request_arg
                    ftp_sessions[session_key]['username'] = username

                # 新增：记录所有FTP操作
                if hasattr(packet.ftp, 'request_command'):
                    command = packet.ftp.request_command
                    arg = getattr(packet.ftp, 'request_arg', '')
                    current_user = ftp_sessions.get(session_key, {}).get('username', 'Unknown')
                    timestamp = packet.sniff_time
                    all_ftp_logs.append({
                        'timestamp': timestamp,
                        'username': current_user,
                        'command': command,
                        'argument': arg
                    })

                if hasattr(packet.ftp, 'request_command') and packet.ftp.request_command in ['RETR', 'STOR']:
                    command = packet.ftp.request_command
                    filename = packet.ftp.request_arg
                    current_user = ftp_sessions.get(session_key, {}).get('username', 'Unknown')
                    timestamp = packet.sniff_time
                    log_entry = {
                        'timestamp': timestamp, 'username': current_user,
                        'action': '下载 (RETR)' if command == 'RETR' else '上传 (STOR)',
                        'filename': filename
                    }
                    transfer_logs.append(log_entry)
            except (AttributeError, KeyError):
                continue
        
        capture.close()

    except FileNotFoundError:
        print(f"[错误] 文件未找到: {pcap_file}")
        return
    except Exception as e:
        print(f"[错误] 分析过程中发生错误: {e}")
        return

    # --- 打印结果 (与之前相同) ---
    if not transfer_logs:
        print("\n[*] 分析完成，未在文件中找到任何 FTP 文件传输记录。")
    else:
        print("\n[*] 分析完成，发现以下 FTP 文件传输记录:")
        print("-" * 80)
        print(f"{'时间':<28} | {'用户名':<20} | {'操作':<15} | {'文件名'}")
        print("-" * 80)
        sorted_logs = sorted(transfer_logs, key=lambda x: x['timestamp'])
        for log in sorted_logs:
            ts_str = log['timestamp'].strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
            print(f"{ts_str:<28} | {log['username']:<20} | {log['action']:<15} | {log['filename']}")
        print("-" * 80)

        # --- 新增：导出到 CSV ---
        csv_path = os.path.splitext(pcap_file)[0] + "_ftp.csv"
        try:
            with open(csv_path, mode='w', newline='', encoding='utf-8-sig') as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow(['时间', '用户名', '操作', '文件名'])
                for log in sorted_logs:
                    ts_str = log['timestamp'].strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
                    writer.writerow([ts_str, log['username'], log['action'], log['filename']])
            print(f"[*] 结果已导出到 CSV 文件: {csv_path}")
        except Exception as e:
            print(f"[错误] 导出 CSV 时出错: {e}")

    # 新增：导出所有FTP操作到CSV
    if all_ftp_logs:
        all_csv_path = os.path.splitext(pcap_file)[0] + "_ftp_all_ops.csv"
        try:
            with open(all_csv_path, mode='w', newline='', encoding='utf-8-sig') as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow(['时间', '用户名', '命令', '参数'])
                sorted_all_logs = sorted(all_ftp_logs, key=lambda x: x['timestamp'])
                for log in sorted_all_logs:
                    ts_str = log['timestamp'].strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
                    writer.writerow([ts_str, log['username'], log['command'], log['argument']])
            print(f"[*] 所有FTP操作已导出到 CSV 文件: {all_csv_path}")
        except Exception as e:
            print(f"[错误] 导出所有FTP操作CSV时出错: {e}")

if __name__ == "__main__":

    pcap_file_path = r'sample.pcap'
    analyze_ftp_pcap(pcap_file_path)