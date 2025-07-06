import os
import json
import time
import tqdm
import zlib
import random
import socket
import struct
import hashlib
import threading
from concurrent.futures import ThreadPoolExecutor

def perform_handshake(conn, is_server=False):
    """执行握手验证"""
    try:
        if is_server:
            # 接收方逻辑
            challenge = conn.recv(10).decode()
            if len(challenge) != 10:
                return False
            response = str(int(challenge) * 2)
            conn.send(response.encode())
            ack = conn.recv(5).decode()
            return ack == "Ready"
        else:
            # 发送方逻辑
            challenge = ''.join(random.choices('0123456789', k=10))
            conn.send(challenge.encode())
            response = conn.recv(20).decode()
            if response == str(int(challenge) * 2):
                conn.send(b"Ready")
                return True
            return False
    except Exception as e:
        print(f"握手失败: {e}")
        return False

def handle_send(params):
    """发送TCP数据包或文件"""
    if 'type' not in params:
        print("[-]缺少类型参数 (type=msg or type=file)")
        return

    send_type = params['type']
    if send_type == 'msg':
        # 消息发送逻辑
        required = ['ip', 'port']
        if any(r not in params for r in required):
            print(f"[-]缺少必要参数: {required}")
            return

        ip = params['ip']
        port = int(params['port'])
        msg = params.get('msg', 'test-data')
        times = int(params.get('times', 1))
        parallel = params.get('parallel', 'false').lower() == 'true'
        maxthread = min(int(params.get('maxthread', 100)), 5000)

        def send_packet():
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(2)
                    s.connect((ip, port))

                    s.sendall(msg.encode())
                    print(f"[发送]至{ip}:{port}")
            except Exception as e:
                print(f"[-]发送失败: {e}")

        if parallel:
            with ThreadPoolExecutor(max_workers=maxthread) as executor:
                [executor.submit(send_packet) for _ in range(times)]
        else:
            for _ in range(times):
                send_packet()

    elif send_type == 'file':
        # 文件发送逻辑
        required = ['ip', 'port', 'filepath']
        if any(r not in params for r in required):
            print(f"[-]缺少必要参数: {required}")
            return

        ip = params['ip']
        port = int(params['port'])
        filepath = params['filepath']
        savepath = params.get('savepath', os.path.basename(filepath))
        compress = params.get('compress', 'false').lower() == 'true'  # 压缩选项
        min_compress_size = 1024  # 1KB以下不压缩
        compress_threshold = 0.95  # 只有压缩率<95%才使用压缩
        parallel = params.get('parallel', 'false').lower() == 'true'
        maxthread = min(int(params.get('maxthread', 100)), 5000)

        try:
            # 获取文件信息
            filesize = os.path.getsize(filepath)
            filename = os.path.basename(filepath)

            # 建立控制连接
            ctrl_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            ctrl_sock.connect((ip, port))

            # 控制连接握手
            if not perform_handshake(ctrl_sock):
                print("[-]控制连接握手失败")
                ctrl_sock.close()
                return

            # 发送文件元数据
            metadata = {
                'filename': filename,
                'filesize': filesize,
                'savepath': savepath,
                'chunks': maxthread,
                'compressed': compress  # 添加压缩标志
            }
            ctrl_sock.send(json.dumps(metadata).encode())

            # 等待接收端确认
            ack = ctrl_sock.recv(1024)
            if ack != b"ACK":
                print("[-]接收端未确认元数据")
                ctrl_sock.close()
                return

            # 准备数据块
            chunks = []
            chunk_size = filesize // maxthread
            with open(filepath, 'rb') as f:
                for i in range(maxthread):
                    start = i * chunk_size
                    end = (i + 1) * chunk_size if i < maxthread - 1 else filesize
                    size = end - start
                    f.seek(start)
                    data = f.read(size)
                    original_size = len(data)

                    # 压缩数据（如果启用且数据足够大）
                    compressed = False
                    if compress and len(data) > min_compress_size:
                        try:
                            compressed_data = zlib.compress(data, level=zlib.Z_BEST_SPEED)
                            compression_ratio = len(compressed_data) / len(data)

                            if compression_ratio < compress_threshold:  # 只有压缩率足够好才使用
                                data = compressed_data
                                compressed = True
                                print(
                                    f"[+]数据块{i}压缩成功 ({original_size} -> {len(data)}字节, 压缩率: {compression_ratio * 100:.1f}%)")
                            else:
                                print(f"[-]数据块{i}压缩效果不佳 ({compression_ratio * 100:.1f}%), 使用原始数据")
                        except Exception as e:
                            print(f"[-]数据块{i}压缩失败: {e}")

                    chunk_hash = hashlib.md5(data).hexdigest()
                    chunks.append((i, data, chunk_hash, compressed, original_size))

            # 创建全局进度条
            pbar = tqdm.tqdm(total=filesize, unit='B', unit_scale=True,
                             desc=f"发送 {filename}", bar_format='{l_bar}{bar}| {n_fmt}/{total_fmt}')

            # 启动数据发送线程
            def send_chunk(chunk_data):
                idx, data, chunk_hash, compressed, original_size = chunk_data
                data_port = port + 1 + idx  # 使用不同端口避免冲突
                data_sock = None

                try:
                    # 建立数据连接
                    data_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    data_sock.connect((ip, data_port))

                    # 数据连接握手
                    if not perform_handshake(data_sock):
                        print(f"[-]数据块{idx}握手失败, 请确保端口未占用!")
                        data_sock.close()
                        return False

                    # 发送块信息
                    header = json.dumps({
                        'index': idx,
                        'size': len(data),
                        'hash': chunk_hash,
                        'compressed': compressed,
                        'original_size': original_size
                    }).encode()
                    data_sock.send(struct.pack('!I', len(header)))
                    data_sock.send(header)

                    # 发送数据
                    sent = 0
                    while sent < len(data):
                        # 每次发送最多4096字节
                        chunk = data[sent:sent + 4096]
                        data_sock.sendall(chunk)
                        sent += len(chunk)
                        # 更新进度条
                        pbar.update(len(chunk))

                    # 等待接收确认
                    response = data_sock.recv(1024)
                    if response != b"OK":
                        print(f"[-]数据块{idx}未收到确认")
                        data_sock.close()
                        return False

                    data_sock.close()
                    print(f"[+]数据块{idx}发送成功 (压缩: {'是' if compressed else '否'})")
                    return True
                except Exception as e:
                    print(f"[-]发送数据块{idx}失败: {e}")
                    return False
                finally:
                    if data_sock:  # 确保套接字关闭
                        data_sock.close()

            with ThreadPoolExecutor(max_workers=maxthread) as executor:
                futures = [executor.submit(send_chunk, chunk) for chunk in chunks]
                results = [f.result() for f in futures]

                if all(results):
                    print("[+]文件发送成功")
                    ctrl_sock.send(b"SUCCESS")
                else:
                    print("[-]部分数据块发送失败")
                    ctrl_sock.send(b"FAILED")

            # 关闭进度条
            pbar.close()
            ctrl_sock.close()

            # 计算压缩统计
            if compress:
                original_total = sum(c[4] for c in chunks)
                compressed_total = sum(len(c[1]) for c in chunks)
                if original_total > 0:
                    ratio = (1 - compressed_total / original_total) * 100
                    print(
                        f"[压缩统计] 原始大小: {original_total}字节, 压缩后: {compressed_total}字节, 节省: {ratio:.2f}%")
        except Exception as e:
            print(f"[-]文件发送失败: {e}")
    else:
        print(f"[-]无效的发送类型: {send_type}")
