from utils import get_local_ip
from scan import get_local_mac

def get_info(params):
    """获取信息"""
    get_type = params.get("type", "fault")
    write_use_local_file = open("local.ntl", "a")
    local_file = open("local.ntl", "r")
    if get_type == "fault":
        print('缺少参数:["type"]')
    elif get_type == "ip":
        ip = get_local_ip()
        if ip not in local_file.read():
            write_use_local_file.write(f"ip:{ip}\n")
        print(ip)
    elif get_type == "mac":
        mac = get_local_mac()
        if mac not in local_file.read():
            write_use_local_file.write(f"mac:{mac}\n")
        print(mac)
    else:
        print(f"未知类型:{get_type}")
    local_file.close()
