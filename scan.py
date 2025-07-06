import os
import re
import sys
import json
import time
import tqdm
import ctypes
import random
import select
import socket
import struct
import platform
import threading
import subprocess
from uuid import getnode
from concurrent.futures import ThreadPoolExecutor
from utils import get_local_ip

OUI_VENDORS = {
    '001C42': 'Parallels',
    '000C29': 'VMware',
    '005056': 'VMware',
    '080027': 'VirtualBox',
    '001A11': 'Apple',
    '000393': 'Apple',
    '003065': 'Apple',
    '001A2B': 'Huawei',
    '00259E': 'Huawei',
    '001247': 'Samsung',
    '0050F2': 'Microsoft',
}

def get_mac_by_ip(target_ip):
    """通过ARP缓存或主动查询获取指定IP的MAC地址"""
    # 先尝试从系统ARP缓存中获取
    cached_mac = _get_mac_from_arp_cache(target_ip)
    if cached_mac:
        return cached_mac

    # 缓存中没有，发送主动ARP请求
    return _get_mac_via_active_arp(target_ip)


def _get_mac_from_arp_cache(target_ip):
    """从系统ARP缓存中获取MAC地址"""
    system = platform.system()

    if system == "Windows":
        try:
            # 使用Windows API获取ARP表
            result = subprocess.check_output(['arp', '-a', target_ip],
                                             stderr=subprocess.STDOUT,
                                             text=True)
            # 解析输出中的MAC地址
            match = re.search(r"([0-9A-Fa-f]{2}(?:[:-][0-9A-Fa-f]{2}){5})", result)
            if match:
                return match.group(1).replace('-', ':').lower()
        except (subprocess.CalledProcessError, FileNotFoundError):
            pass

    elif system in ["Linux", "Darwin"]:  # Darwin is macOS
        try:
            # 读取Linux/MacOS的ARP缓存
            with open('/proc/net/arp') as f:
                for line in f.readlines()[1:]:  # 跳过标题行
                    parts = line.split()
                    if len(parts) >= 4 and parts[0] == target_ip:
                        mac = parts[3]
                        if mac != '00:00:00:00:00:00':
                            return mac.lower()
        except FileNotFoundError:
            # macOS没有/proc/net/arp，使用arp命令
            try:
                result = subprocess.check_output(['arp', target_ip],
                                                 stderr=subprocess.STDOUT,
                                                 text=True)
                match = re.search(r"([0-9A-Fa-f]{2}(?:[:-][0-9A-Fa-f]{2}){5})", result)
                if match:
                    return match.group(1).replace('-', ':').lower()
            except (subprocess.CalledProcessError, FileNotFoundError):
                pass

    return None

def _get_mac_via_active_arp(target_ip):
    """通过主动ARP请求获取MAC地址"""
    local_mac = get_local_mac()
    local_ip = get_local_ip()

    # 创建ARP套接字
    try:
        if platform.system() == 'Windows':
            # Windows需要特殊处理
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            sock.bind((local_ip, 0))
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        else:
            # Linux/MacOS
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    except (PermissionError, OSError) as e:
        print(f"[-]需要管理员权限运行ARP查询: {e}")
        return None
    except Exception as e:
        print(f"[-]创建ARP套接字失败: {e}")
        return None

    try:
        # 发送ARP请求
        arp_packet = _build_arp_request(local_mac, local_ip, target_ip)
        sock.sendto(arp_packet, (target_ip, 0))

        # 设置超时
        sock.settimeout(2)

        # 接收响应
        start_time = time.time()
        while time.time() - start_time < 2:
            try:
                packet, addr = sock.recvfrom(2048)
                if result := _parse_arp_response(packet, local_mac):
                    ip, mac = result
                    if ip == target_ip:
                        return mac
            except socket.timeout:
                break
    except Exception as e:
        print(f"[-]ARP查询错误: {str(e)}")
    finally:
        sock.close()

    return None

def get_local_mac():
    """获取本机MAC地址（跨平台）"""
    if platform.system() == 'Windows':
        return get_windows_mac()
    return ':'.join(("%012X" % getnode())[i:i + 2] for i in range(0, 12, 2)).lower()


def _get_windows_mac():
    """Windows系统获取MAC地址"""

    class IP_ADAPTER_INFO(ctypes.Structure):
        _fields_ = [
            ("next", ctypes.c_void_p),
            ("combo_index", ctypes.c_uint),
            ("adapter_name", ctypes.c_char * 260),
            ("description", ctypes.c_char * 132),
            ("address_length", ctypes.c_uint),
            ("address", ctypes.c_ubyte * 8),
            ("index", ctypes.c_uint),
        ]

    buffer = ctypes.create_string_buffer(4096)
    size = ctypes.c_uint(ctypes.sizeof(buffer))

    # 使用ctypes获取函数指针
    GetAdaptersInfo = ctypes.windll.iphlpapi.GetAdaptersInfo
    GetAdaptersInfo.restype = ctypes.c_uint
    GetAdaptersInfo.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint)]

    if GetAdaptersInfo(buffer, ctypes.byref(size)) != 0:
        return "00:00:00:00:00:00"

    # 遍历适配器链表
    adapter = ctypes.cast(buffer, ctypes.POINTER(IP_ADAPTER_INFO)).contents
    while adapter:
        mac_bytes = bytes(adapter.address[:adapter.address_length])
        if any(mac_bytes):
            return ':'.join(f"{b:02X}" for b in mac_bytes).lower()

        # 移动到下一个适配器
        if adapter.next:
            adapter = ctypes.cast(adapter.next, ctypes.POINTER(IP_ADAPTER_INFO)).contents
        else:
            break

    return "00:00:00:00:00:00"

def handle_scan(params):
    """处理扫描命令"""
    if 'type' not in params:
        print("[-]缺少扫描类型参数")
        return
    
    scan_type = params['type']
    if scan_type == 'ip':
        scan_ips(params)
    elif scan_type == 'port':
        scan_ports(params)
    else:
        print(f"[-]无效的扫描类型: {scan_type}")

def detect_os(ttl, mac):
    """根据TTL和MAC地址推测操作系统"""
    # 处理未知MAC的情况
    if not mac or mac == "未知":
        vendor = "未知"
    else:
        # 解析MAC OUI
        oui = mac.replace(':', '').upper()[:6]
        vendor = OUI_VENDORS.get(oui, '未知')

    # 根据TTL推测初始值
    if ttl:
        if ttl <= 64:
            ttl_guess = "Linux/Unix/MacOS"
        elif ttl <= 128:
            ttl_guess = "Windows"
        else:
            ttl_guess = "其他设备"
    else:
        ttl_guess = "未知"

    # 综合判断
    if vendor == 'Apple':
        return "MacOS/iOS"
    elif vendor == 'Huawei':
        return "HarmonyOS/Android"
    elif vendor == 'Samsung':
        return "Android"
    elif vendor == 'Microsoft':
        return "Windows"
    elif 'VMware' in vendor or 'VirtualBox' in vendor:
        return f"虚拟机({ttl_guess})"
    
    # 根据TTL默认判断
    if ttl_guess == "Windows":
        return "Windows"
    elif ttl_guess == "Linux/Unix/MacOS":
        return "Linux/MacOS"
    return f"{ttl_guess} ({vendor})"

def _get_ttl_via_icmp(target_ip):
    """通过ICMP请求获取TTL值"""
    try:
        # 创建ICMP套接字
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        sock.settimeout(2)
    except (PermissionError, OSError) as e:
        print(f"[-]需要管理员权限运行以发送ICMP请求: {e}")
        return None
    except Exception as e:
        print(f"[-]无法创建ICMP套接字: {e}")
        return None

    # 构造ICMP包
    header = struct.pack('!BBHHH', 8, 0, 0, 1, 1)  # 类型8(请求),代码0
    data = b'pingtest'
    checksum = _calculate_checksum(header + data)
    header = struct.pack('!BBHHH', 8, 0, checksum, 1, 1)
    packet = header + data

    try:
        sock.sendto(packet, (target_ip, 0))
        start_time = time.time()
        while time.time() - start_time < 2:
            try:
                response, addr = sock.recvfrom(1024)
                if addr[0] == target_ip:
                    # 提取IP头部的TTL（第8字节）
                    return response[8]
            except socket.timeout:
                break
    except Exception as e:
        print(f"[-]ICMP错误: {str(e)}")
    finally:
        sock.close()
    return None

def _calculate_checksum(data):
    """计算校验和"""
    if len(data) % 2 != 0:
        data += b'\x00'
    s = sum(struct.unpack('!%dH' % (len(data)//2), data))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff

def _get_local_mac():
    """获取本机MAC地址（跨平台）"""
    if platform.system() == 'Windows':
        return get_windows_mac()
    return ':'.join(("%012X" % getnode())[i:i+2] for i in range(0, 12, 2)).lower()

def get_windows_mac():
    """Windows系统获取MAC地址"""
    class IP_ADAPTER_INFO(ctypes.Structure):
        _fields_ = [
            ("next", ctypes.c_void_p),
            ("combo_index", ctypes.c_uint),
            ("adapter_name", ctypes.c_char * 260),
            ("description", ctypes.c_char * 132),
            ("address_length", ctypes.c_uint),
            ("address", ctypes.c_ubyte * 8),
            ("index", ctypes.c_uint),
        ]

    buffer = ctypes.create_string_buffer(4096)
    size = ctypes.c_uint(ctypes.sizeof(buffer))
    
    # 使用ctypes获取函数指针
    GetAdaptersInfo = ctypes.windll.iphlpapi.GetAdaptersInfo
    GetAdaptersInfo.restype = ctypes.c_uint
    GetAdaptersInfo.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint)]
    
    if GetAdaptersInfo(buffer, ctypes.byref(size)) != 0:
        return "00:00:00:00:00:00"

    # 遍历适配器链表
    adapter = ctypes.cast(buffer, ctypes.POINTER(IP_ADAPTER_INFO)).contents
    while adapter:
        mac_bytes = bytes(adapter.address[:adapter.address_length])
        if any(mac_bytes):
            return ':'.join(f"{b:02X}" for b in mac_bytes).lower()
        
        # 移动到下一个适配器
        if adapter.next:
            adapter = ctypes.cast(adapter.next, ctypes.POINTER(IP_ADAPTER_INFO)).contents
        else:
            break
    
    return "00:00:00:00:00:00"

def _is_icmp_response(packet, target_ip):
    """检查是否是ICMP Echo响应"""
    if len(packet) < 20:
        return False
    
    # 解析IP头
    ip_header = packet[:20]
    iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
    version_ihl = iph[0]
    ihl = version_ihl & 0xF
    iph_length = ihl * 4
    src_ip = socket.inet_ntoa(iph[8])
    
    if src_ip != target_ip:
        return False
    
    # 解析ICMP头
    icmp_header = packet[iph_length:iph_length + 8]
    icmph = struct.unpack('!BBHHH', icmp_header)
    icmp_type = icmph[0]
    icmp_code = icmph[1]
    
    # 检查是否是Echo响应 (type=0)
    return icmp_type == 0 and icmp_code == 0

def _build_ip_header(src_ip, dst_ip):
    """构造IP头部"""
    ip_ver = 4
    ip_ihl = 5
    ip_tos = 0
    ip_tot_len = 0  # 内核会自动填充
    ip_id = random.randint(0, 65535)
    ip_frag_off = 0
    ip_ttl = 64
    ip_proto = socket.IPPROTO_TCP
    ip_check = 0
    ip_saddr = socket.inet_aton(src_ip)
    ip_daddr = socket.inet_aton(dst_ip)
    
    ip_ihl_ver = (ip_ver << 4) + ip_ihl
    
    ip_header = struct.pack('!BBHHHBBH4s4s', 
        ip_ihl_ver, ip_tos, ip_tot_len, 
        ip_id, ip_frag_off, ip_ttl, 
        ip_proto, ip_check, ip_saddr, ip_daddr)
    
    return ip_header

def _build_tcp_header(src_ip, dst_ip, dst_port, seq_num):
    """构造TCP头部"""
    tcp_source = random.randint(1024, 65535)  # 随机源端口
    tcp_dest = dst_port
    tcp_seq = seq_num
    tcp_ack_seq = 0
    tcp_doff = 5  # 数据偏移
    tcp_fin = 0
    tcp_syn = 1
    tcp_rst = 0
    tcp_psh = 0
    tcp_ack = 0
    tcp_urg = 0
    tcp_window = socket.htons(5840)
    tcp_check = 0
    tcp_urg_ptr = 0
    
    tcp_offset_res = (tcp_doff << 4)
    tcp_flags = tcp_fin + (tcp_syn << 1) + (tcp_rst << 2) + (tcp_psh << 3) + (tcp_ack << 4) + (tcp_urg << 5)
    
    tcp_header = struct.pack('!HHLLBBHHH', 
        tcp_source, tcp_dest, 
        tcp_seq, tcp_ack_seq, 
        tcp_offset_res, tcp_flags, 
        tcp_window, tcp_check, tcp_urg_ptr)
    
    # 伪头部用于校验和计算
    psh = struct.pack('!4s4sBBH', 
        socket.inet_aton(src_ip), 
        socket.inet_aton(dst_ip), 
        0, socket.IPPROTO_TCP, len(tcp_header))
    
    psh = psh + tcp_header
    tcp_check = _calculate_checksum(psh)
    
    # 重新打包TCP头部
    tcp_header = struct.pack('!HHLLBBH', 
        tcp_source, tcp_dest, 
        tcp_seq, tcp_ack_seq, 
        tcp_offset_res, tcp_flags, 
        tcp_window) + struct.pack('H', tcp_check) + struct.pack('!H', tcp_urg_ptr)
    
    return tcp_header

def _parse_syn_response(packet, sent_ips_ports):
    """解析SYN响应包"""
    if len(packet) < 40:
        return None
    
    # 解析IP头
    ip_header = packet[:20]
    iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
    version_ihl = iph[0]
    ihl = version_ihl & 0xF
    iph_length = ihl * 4
    src_ip = socket.inet_ntoa(iph[8])
    
    # 解析TCP头
    tcp_header = packet[iph_length:iph_length + 20]
    tcph = struct.unpack('!HHLLBBH', tcp_header[:16])  # 只解析前14字节
    src_port = tcph[0]
    dst_port = tcph[1]
    ack_num = tcph[3]  # 确认号
    
    # 检查是否是SYN-ACK (ACK和SYN标志都置位)
    # 只检查ACK标志位，因为有些系统可能不设置SYN标志
    tcp_flags = tcph[5]
    if not (tcp_flags & 0x10):  # 检查ACK标志
        return None
    
    # 查找对应的SYN包 (ACK号应该是我们发送的SEQ+1)
    if (ack_num - 1) in sent_ips_ports:
        sent_ip, sent_port = sent_ips_ports[ack_num - 1]
        if sent_ip == src_ip:
            return src_ip
    return None


def _build_arp_request(src_mac, src_ip, target_ip):
    """构造ARP请求包"""
    # 以太网帧头
    eth_header = (
        b'\xff' * 6 +                      # 目标MAC（广播）
        bytes.fromhex(src_mac.replace(':', '')) +  # 源MAC
        struct.pack('!H', 0x0806)           # 协议类型（ARP）
    )
    
    # ARP包头
    arp_header = struct.pack('!HHBBH', 
        0x0001, 0x0800, 6, 4, 0x0001)      # 硬件类型|协议类型|MAC长度|IP长度|操作码
    
    # 填充地址信息
    return eth_header + arp_header + (
        bytes.fromhex(src_mac.replace(':', '')) +  # 源MAC
        socket.inet_aton(src_ip) +                 # 源IP
        b'\x00' * 6 +                             # 目标MAC（空）
        socket.inet_aton(target_ip)                # 目标IP
    )

def _parse_arp_response(packet, local_mac):
    """解析ARP响应包"""
    # 检查最小长度
    if len(packet) < 42:
        return None
    
    # 检查以太网类型是否为ARP (0x0806)
    if struct.unpack('!H', packet[12:14])[0] != 0x0806:
        return None

    # 解析ARP包
    arp_data = packet[14:42]
    
    # 检查ARP操作码是否为响应 (2)
    opcode = struct.unpack('!H', arp_data[6:8])[0]
    if opcode != 2:  # ARP响应
        return None
    
    # 提取源MAC和IP
    src_mac = ':'.join(f"{b:02x}" for b in arp_data[8:14])
    src_ip = socket.inet_ntoa(arp_data[14:18])
    
    # 返回元组 (ip, mac)，排除本机MAC
    return (src_ip, src_mac) if src_mac.lower() != local_mac.lower() else None

def scan_ips(params):
    """使用混合扫描局域网活动主机"""
    # 打开日志文件
    log_file = open("./ntlips.json", "a")

    # 获取本机以及局域网信息
    local_ip = get_local_ip()
    base_ip = '.'.join(local_ip.split('.')[:-1]) + '.'
    
    # 活动主机集合
    active_hosts = {}
    active_hosts_lock = threading.Lock()
    
    # 存储发送的SYN序列号
    sent_ips_ports = {}

    # 各种扫描方式的启用情况
    mode = params['mode']
    enable = {
        'syn': False,
        'icmp': False,
        'arp': False
    }
    if mode == 'all':
        enable['icmp'] = True
        enable['syn'] = True
        enable['arp'] = True
    else:
        enable[params['mode']] = True
    
    if params['mode'] == 'all':
        print(f"[混合扫描]开始扫描 {base_ip}0/24...")
    else:
        print(f"[{params['mode'].upper()}]开始扫描 {base_ip}0/24...")
    
    # 创建套接字
    try:
        # 创建ICMP套接字(如果启用)
        if enable['icmp']:
            icmp_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            icmp_sock.setblocking(False)
        
        # 创建ARP套字节(如果启用)
        if enable['arp']:
            arp_sock = socket.socket(
                socket.AF_INET, 
                socket.SOCK_RAW, 
                socket.IPPROTO_RAW if platform.system() == 'Windows' else socket.IPPROTO_ARP
            )
            arp_sock.setblocking(False)
        
        # 创建SYN套字节(如果启用)
        if enable['syn']:
            # Windows 特殊处理
            if platform.system() == 'Windows':
                try:
                    # 创建TCP套接字
                    syn_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
                    syn_sock.bind((local_ip, 0))
                    syn_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                
                    # 启用混杂模式接收所有数据包
                    RCVALL_ON = 3  # Windows 上的正确值
                    syn_sock.ioctl(socket.SIO_RCVALL, RCVALL_ON)
                    print("[+]Windows混杂模式已启用")
                except Exception as e:
                    print(f"[-]Windows原始套接字错误: {e} (需要管理员权限)")
                    return
            else:
                # Linux/MacOS创建原始套接字
                syn_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
                syn_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                syn_sock.setblocking(False)
    except Exception as e:
        print(f"[-]创建套接字失败: {e} (需要管理员权限)")
        return
    
    # 1. 发送ICMP请求(如果启用)
    if enable['icmp']:
       for i in tqdm.tqdm(range(1, 255), desc="发送ICMP请求"):
            target_ip = f"{base_ip}{i}"
            if target_ip == local_ip:
                continue
            
            # 构造ICMP包
            header = struct.pack('!BBHHH', 8, 0, 0, 1, 1)
            data = b'pingtest'
            checksum = _calculate_checksum(header + data)
            header = struct.pack('!BBHHH', 8, 0, checksum, 1, 1)
            packet = header + data
        
            try:
                icmp_sock.sendto(packet, (target_ip, 0))
            except Exception as e:
                print(f"[-]发送ICMP到 {target_ip} 失败: {e}")

    # 2. 发送SYN扫描(如果启用)
    if enable['syn']:
        common_ports = [
            22, 80, 443, 53, 445, 3389, 23, 21, 135, 139, 
            1433, 3306, 8080, 8000, 25, 110, 5432, 161, 179, 
            389, 636, 143, 67, 68, 548, 2049, 137, 138, 5900,
            5985, 5986, 5060, 162, 631, 88, 111, 123, 199, 
            593, 102, 502, 623, 3260, 9000, 5000, 5353, 49152,
            49153, 49154
        ]

        for i in tqdm.tqdm(range(1, 255), desc="发送SYN扫描"):
            target_ip = f"{base_ip}{i}"
            if target_ip == local_ip:
                continue
            
            for port in common_ports:
                try:
                    # 生成随机序列号
                    seq_num = random.randint(0, 0xFFFFFFFF)
                    sent_ips_ports[seq_num] = (target_ip, port)
                
                    # 构造SYN包
                    ip_header = _build_ip_header(local_ip, target_ip)
                    tcp_header = _build_tcp_header(local_ip, target_ip, port, seq_num)
                    syn_sock.sendto(ip_header + tcp_header, (target_ip, 0))
                except Exception as e:
                    print(f"[-]发送SYN到 {target_ip}:{port} 失败: {e}")
    
    # 3. 发送ARP扫描(如果启用)
    if enable['arp']:
        for i in tqdm.tqdm(range(1, 255), desc="发送ARP扫描"):
            target_ip = f"{base_ip}{i}"
            if target_ip == local_ip:
                continue
            
            try:
                # 获取本地MAC地址
                local_mac = get_local_mac()
            
                # 构造并发送ARP请求
                arp_packet = _build_arp_request(local_mac, local_ip, target_ip)
                arp_sock.sendto(arp_packet, (target_ip, 0))
            except Exception as e:
                print(f"[-]发送ARP到 {target_ip} 失败: {e}")

    # 4. 接收响应
    sockets = []
    if enable['icmp']:
        sockets.append(icmp_sock)
    if enable['syn']:
        sockets.append(syn_sock)
    if enable['arp']:
        sockets.append(arp_sock)
    start_time = time.time()
    timeout = 5  # 增加超时时间
    
    if params['mode'] == 'all':
        print("[混合扫描]等待响应...")
    else:
        print(f"[{params['mode'].upper()}]等待响应...")
    while time.time() - start_time < timeout:
        readable, _, _ = select.select(sockets, [], [], 0.5)
        
        for sock in readable:
            try:
                packet, addr = sock.recvfrom(4096)
                
                if enable['icmp']:
                    if sock == icmp_sock:
                        # 处理ICMP响应
                        src_ip = addr[0]
                        if len(packet) > 20 and packet[20] == 0:
                            with active_hosts_lock:
                                if src_ip not in active_hosts:
                                    active_hosts[src_ip] = (None, "ICMP")
                                    print(f"[+]ICMP发现: {src_ip}")
                elif enable['syn']:
                    if sock == syn_sock and enable['syn']:
                        # 处理SYN响应
                        if result := _parse_syn_response(packet, sent_ips_ports):
                            with active_hosts_lock:
                                if result not in active_hosts:
                                    active_hosts[result] = (None, "SYN")
                                    print(f"[+]SYN发现: {result}")
                elif enable['arp']:
                    if sock == arp_sock and enable['arp']:
                        # 处理ARP响应
                        if result := _parse_arp_response(packet, get_local_mac()):
                            src_ip, src_mac = result
                            with active_hosts_lock:
                                if src_ip not in active_hosts:
                                    active_hosts[src_ip] = (src_mac, "ARP")
                                    print(f"[+]ARP发现: {src_ip} (MAC: {src_mac})")
            except socket.error:
                continue
    
    # 5. 关闭套接字
    if enable['icmp']:
        icmp_sock.close()
    if enable['arp']:
        arp_sock.close()
    
    if platform.system() == 'Windows':
        try:
            RCVALL_OFF = 0
            syn_sock.ioctl(socket.SIO_RCVALL, RCVALL_OFF)
            print("[+]Windows混杂模式已关闭")
        except:
            pass
    if enable['syn']:
        syn_sock.close()
    
    # 6. 查询MAC地址和操作系统（对于非ARP发现的主机）
    print("\n[混合扫描]查询MAC地址和操作系统...")
    sorted_ips = sorted(active_hosts.keys(), key=lambda x: [int(i) for i in x.split('.')])
    
    for ip in sorted_ips:
        mac, found_by = active_hosts[ip]
        
        # 对于非ARP发现的主机，获取MAC地址
        if found_by != "ARP" and mac is None:
            mac = get_mac_by_ip(ip) or "未知"
        
        ttl = _get_ttl_via_icmp(ip)
        os_info = detect_os(ttl, mac)
        
        print(f"[+]主机 {ip:15}  MAC: {mac:17}  系统: {os_info:20}  发现方式: {found_by}")
        log = {
            "src_ip": {
                "ip": ip,
                "mac": mac[:17] if mac else "未知",
                "os": os_info[:20],
                "fount_by": found_by
            }
        }
        json.dump(log, log_file)
        log_file.write("\n")
    
    log_file.close()

def scan_ports(params):
    """多线程端口扫描"""
    required = ['ip', 'startport', 'endport']
    if any(r not in params for r in required):
        print(f"[-]缺少必要参数: {required}")
        return

    # 打开端口记录文件
    ports_file = open("ntlprt.json", "w")
    # 开放端口列表
    open_ports = []

    ip = params['ip']
    start = int(params['startport'])
    end = int(params['endport'])
    
    # 检查端口范围是否有效
    if start < 1 or end > 65535 or start > end:
        print("[-]无效的端口范围 (1-65535)")
        return
    
    parallel = params.get('parallel', 'false').lower() == 'true'
    maxthread = min(int(params.get('maxthread', 5000)), 5000)

    print(f"[端口]开始扫描 {ip}:{start}-{end}...")

    def check_port(port):
        """尝试连接指定端口"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                s.connect((ip, port))
                return port, True
        except:
            return port, False

    with ThreadPoolExecutor(max_workers=maxthread if parallel else 1) as executor:
        futures = [executor.submit(check_port, p) for p in range(start, end+1)]
        for future in tqdm.tqdm(futures, desc="端口扫描"):
            port, status = future.result()
            if status:
                open_ports.append(port)
                print(f"\n[+]端口 {port}")

    # 将结果写入文件并关闭文件
    result = {
        params["ip"]: open_ports
    }
    json.dump(result, ports_file)
    ports_file.close()
