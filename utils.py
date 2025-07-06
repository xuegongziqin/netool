import socket

DNS_SERVERS = ["114.114.114.114", "114.114.115.115", "8.8.8.8"]
def get_local_ip():
    """获取本机IPv4地址"""
    for dns_server in DNS_SERVERS:
        try:
            # 通过UDP连接公共DNS服务器获取本机IP
            ip_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            ip_sock.settimeout(2)
            ip_sock.connect((dns_server, 80))
            ip = ip_sock.getsockname()[0]
            return ip
            ip_sock.close()
        except (socket.error, OSError, TimeoutError) as e:
            if dns_server == DNS_SERVERS[-1]:
                # 获取失败，返回回文地址
                return "127.0.0.1"
            else:
                ip_sock.close()
                pass
    return "127.0.0.1"
