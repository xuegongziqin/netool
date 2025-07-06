import os
import sys
import json
import socket

import scan
from get import get_info
from send import handle_send
from utils import get_local_ip
from listen import handle_listen
from scan import scan_ips, scan_ports, handle_scan

needed_params = {
    'listen': {
        'msg': ['port', 'ip', 'parallel', 'maxthread'],
        'file': ['port', 'ip', 'savepath', 'parallel', 'maxthread']
    },
    'send': {
        'msg': ['ip', 'port', 'msg', 'times', 'parallel', 'maxthread'],
        'file': ['ip', 'port', 'filepath', 'savepath', 'parallel', 'maxthread', 'compress']
    },
    'scan': {
        'ip': ['mode'],
        'port': ['ip', 'startport', 'endport', 'parallel', 'maxthread']
    },
    'get': {
        'ip': [],
        'mac': []
    },
    'gui': {}
}

def parse_params(args):
    """解析命令行参数"""
    result = {k:v for k,v in (a.split('=',1) for a in args if '=' in a)}
    if result.get('mode', 'no') == 'no':    # 当没有提供模式, 则启用全面的混合扫描。
        result['mode'] = 'all'
    return result

def parse_input(command_type):
    """处理交互模式下的输入"""
    params = {}
    
    # 获取命令类型对应的参数配置
    command_config = needed_params.get(command_type)
    if not command_config:
        print(f"未知命令类型: {command_type}")
        return None
        
    # 处理特殊命令
    if command_type == 'get':
        print("可用类型: ip, mac")
        param_type = input("type>>>").strip().lower()
        if param_type not in ['ip', 'mac']:
            print(f"无效类型: {param_type}，应为 ip 或 mac")
            return None
        params['type'] = param_type
        return params
        
    if command_type == 'gui':
        print("启动图形界面...")
        # GUI启动逻辑
        return {'type': 'gui'}
    
    # 获取子命令类型
    print(f"可用类型: {', '.join(command_config.keys())}")
    sub_type = input("type>>>").strip().lower()
    if sub_type not in command_config:
        print(f"无效类型: {sub_type}")
        return None
        
    params['type'] = sub_type
    
    # 收集所需参数
    required_params = command_config[sub_type]
    for param in required_params:
        # 处理带默认值的参数
        if param == 'ip' and command_type == 'listen':
            default_ip = '0.0.0.0'
            value = input(f"{param}({default_ip})>>>").strip()
            params[param] = value or default_ip
        elif param == 'parallel':
            default_parallel = 'false'
            value = input(f"{param}({default_parallel})>>>").strip().lower()
            params[param] = value or default_parallel
        elif param == 'maxthread':
            default_threads = '100'
            value = input(f"{param}({default_threads})>>>").strip()
            params[param] = value or default_threads
        elif param == 'compress':
            default_compress = 'false'
            value = input(f"{param}({default_compress})>>>").strip().lower()
            params[param] = value or default_compress
        elif param == 'mode':
            default_mode = 'all'
            value = input(f"{param}({default_mode})>>>").strip().lower()
            params[param] = value or default_mode
        else:
            value = input(f"{param}>>>").strip()
            if not value:
                print(f"错误: {param} 是必需参数!")
                return None
            params[param] = value
            
    return params

def print_usage(none=None):
    """显示详细的使用说明"""
    usage = """
-----Netool 使用说明-----

[命令列表]
1. listen    - 启动TCP监听服务
2. send      - 发送TCP数据包或文件
3. scan      - 执行网络扫描
4. gui       - 启动图形界面
5. get       - 获取本机信息
6. help      - 显示帮助信息

----详细参数说明----

### 1. 监听服务 (listen)
格式:netool listen type=<msg/file> [参数]
参数说明：
  - type      : 监听类型(msg/file, 必需)
  - ip        : 监听IP地址(默认：0.0.0.0)
  - port      : 监听端口(必需)
  - savepath  : 文件保存路径(文件类型必需)
  - parallel  : 并行接收(true/false, 默认:false)
  - maxthread : 最大线程数(默认:100)

示例：
  # 监听消息
  netool listen type=msg port=8080
  
  # 监听文件
  netool listen type=file port=8080 savepath=/path/to/save

### 2. 发送数据 (send)
格式:netool send type=<msg/file> [参数]
参数说明：
  - type      : 发送类型(msg/file, 必需)
  - ip        : 目标IP地址(必需)
  - port      : 目标端口(必需)
  - msg       : 发送消息内容(消息类型)
  - filepath  : 文件路径(文件类型必需)
  - savepath  : 文件保存路径(文件类型)
  - times     : 发送次数(消息类型, 默认:1)
  - parallel  : 并行发送(true/false, 默认:false)
  - maxthread : 最大线程数(默认:100)
  - compress  : 压缩发送(true/false, 仅适用于文件, 默认false)

示例：
  # 发送消息
  netool send type=msg ip=192.168.1.100 port=8080 msg="Hello" times=10
  
  # 发送文件
  netool send type=file ip=192.168.1.100 port=8080 filepath=/path/to/file savepath=/save/path compress=true

### 3. 网络扫描 (scan)
格式:netool scan type=<ip/port>
  - type      :扫描类型
#### 1. 扫主机：
格式:netool scan type=ip
提示:本工具使用ICMP+SYN+ARP混合扫描，请确保你有足够权限。
#### 2.扫端口：
格式:netool scan type=port ip=<ip> startport=<startport> endport=<endport> parallel=<true/false> maxthread=<maxthread>
  - ip        : 目标IP地址(必需)
  - startport : 起始端口(必需)
  - endport   : 结束端口(必需)
  - parallel  : 并行扫描(true/false, 默认: false)
  - maxthread : 最大线程数(并行必需)
### 4. 图形界面
格式:netool gui

-----注意事项-----
1. 每个数据块传输前执行双向验证:
   - 发送方生成10位随机数
   - 接收方计算随机数*2并返回
   - 双方验证通过后发送"Ready"
2. 文件分块传输，每块包含哈希验证
"""
    print(usage)

def main():
    # 定义命令处理函数字典
    commands = {
        'listen': handle_listen,
        'send': handle_send,
        'scan': handle_scan,
        'get': get_info,
        'help': print_usage,
        'gui': lambda _: print("启动图形界面...")  # GUI处理函数
    }

    # 情况1: 无参数 -> 进入交互模式
    if len(sys.argv) == 1:
        while True:
            try:
                command = input("command>>> ").strip().lower()
                
                # 退出命令
                if command in ['exit', 'quit', 'q', 'bye']:
                    print("exited")
                    break
                    
                # 帮助命令
                if command == 'help':
                    print_usage()
                    continue
                    
                # 检查是否支持该命令
                if command not in commands:
                    print(f"错误: 未知命令 '{command}'")
                    print("可用命令: listen, send, scan, get, gui, help")
                    continue
                    
                # 获取参数
                params = parse_input(command)
                if params is None:  # 用户取消输入
                    continue
                    
                # 执行命令
                commands[command](params)
                
            except KeyboardInterrupt:
                print("\n检测到中断,输入 'exit' 退出程序")
            except Exception as e:
                print(f"[-] 执行错误: {e}")
                import traceback
                traceback.print_exc()
                
        return

    # 情况2: 有参数 -> 命令行模式
    command = sys.argv[1].lower()
    
    # 处理帮助命令
    if command == 'help':
        print_usage()
        return
        
    # 解析参数
    params = parse_params(sys.argv[2:])
    
    try:
        if command in commands:
            commands[command](params)
        else:
            print(f"[-] 未知命令: {command}")
            print_usage()
    except Exception as e:
        print(f"[-] 运行时错误: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()