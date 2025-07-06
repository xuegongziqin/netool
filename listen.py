import os
import json
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

def handle_listen(params):
    """启动TCP监听服务或文件接收"""
    if 'type' not in params:
        print("[-]缺少类型参数 (type=msg or type=file)")
        return

    # 打开日志文件
    log_file = open("ntlips.json", "a")

    listen_type = params['type']
    if listen_type == 'msg':
        # 消息监听逻辑
        if 'port' not in params:
            print("[-]缺少必要参数: port")
            return

        ip = params.get('ip', '0.0.0.0')
        port = int(params['port'])
        parallel = params.get('parallel', 'false').lower() == 'true'
        maxthread = min(int(params.get('maxthread', 100)), 5000)

        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((ip, port))
            s.listen(5)
            print(f"[监听]启动于 {ip}:{port}")

            def client_handler(conn, addr):
                print(f"[连接]来自 {addr}")
                with conn:
                    while True:
                        try:
                            if data := conn.recv(1024):
                                decoded_data = data.decode()
                                print(f"[数据]{decoded_data}")
                                print("--------新数据--------")
                                log = {
                                    "msg": {
                                        "ip": addr,
                                        "msg": decoded_data,
                                    }
                                }
                                json.dump(log, log_file)
                                log_file.write("\n")
                            else:
                                break
                        except:
                            break

            while True:
                conn, addr = s.accept()
                threading.Thread(target=client_handler, args=(conn, addr), daemon=True).start()

        except Exception as e:
            print(f"[-]监听失败: {e}")

    elif listen_type == 'file':
        # 文件接收逻辑
        required = ['port', 'savepath']
        if any(r not in params for r in required):
            print(f"[-]缺少必要参数: {required}")
            return

        ip = params.get('ip', '0.0.0.0')
        port = int(params['port'])
        savepath = params['savepath']
        parallel = params.get('parallel', 'false').lower() == 'true'
        maxthread = min(int(params.get('maxthread', 100)), 5000)

        try:
            # 创建控制套接字
            ctrl_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            ctrl_sock.bind((ip, port))
            ctrl_sock.listen(5)
            print(f"[文件接收]控制端口 {port} 已监听")

            # 接受控制连接
            conn, addr = ctrl_sock.accept()
            print(f"[+]控制连接来自 {addr[0]}")

            # 控制连接握手
            if not perform_handshake(conn, is_server=True):
                print("[-]控制连接握手失败")
                conn.close()
                ctrl_sock.close()
                return

            # 接收元数据
            metadata = json.loads(conn.recv(1024).decode())
            conn.send(b"ACK")  # 发送确认

            filename = metadata['filename']
            filesize = metadata['filesize']
            chunks = metadata['chunks']
            compressed = metadata.get('compressed', False)  # 获取压缩标志
            savepath = metadata.get('savepath', savepath)

            print(f"[+]接收文件: {filename} ({filesize}字节), 分块数: {chunks}, 压缩: {'是' if compressed else '否'}")

            # 准备接收数据
            file_data = [None] * chunks
            lock = threading.Lock()

            # 创建全局进度条
            pbar = tqdm.tqdm(total=filesize, unit='B', unit_scale=True,
                             desc=f"接收 {filename}", bar_format='{l_bar}{bar}| {n_fmt}/{total_fmt}')

            def receive_chunk(data_port):
                try:
                    # 创建数据套接字
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    sock.bind((ip, data_port))
                    sock.listen(1)

                    # 接受数据连接
                    data_conn, data_addr = sock.accept()
                    print(f"[+]数据连接 {data_port} 来自 {data_addr[0]}")

                    # 数据连接握手
                    if not perform_handshake(data_conn, is_server=True):
                        print(f"[-]数据端口{data_port}握手失败")
                        data_conn.close()
                        sock.close()
                        return False

                    # 接收块头
                    header_size = struct.unpack('!I', data_conn.recv(4))[0]
                    header = json.loads(data_conn.recv(header_size).decode())

                    # 接收数据
                    idx = header['index']
                    chunk_size = header['size']
                    chunk_hash = header['hash']
                    compressed_chunk = header.get('compressed', False)  # 块压缩标志
                    original_size = header.get('original_size', chunk_size)  # 原始大小

                    received = b''
                    while len(received) < chunk_size:
                        data = data_conn.recv(min(4096, chunk_size - len(received)))
                        if not data:
                            break

                        received += data
                        # 更新进度条
                        pbar.update(len(data))

                    # 验证哈希
                    actual_hash = hashlib.md5(received).hexdigest()
                    if actual_hash != chunk_hash:
                        print(f"[-]数据块{idx}哈希验证失败: 预期 {chunk_hash}, 实际 {actual_hash}")
                        sock.close()
                        return False

                    # 解压缩（如果需要）
                    if compressed_chunk:
                        try:
                            decompressed = zlib.decompress(received)
                            print(f"[+]数据块{idx}解压缩成功 ({len(received)} -> {len(decompressed)}字节)")
                            if len(decompressed) != original_size:
                                print(
                                    f"[-]警告: 数据块{idx}解压后大小({len(decompressed)})与原始大小({original_size})不匹配")
                            received = decompressed
                        except Exception as e:
                            print(f"[-]数据块{idx}解压缩失败: {e}")
                            sock.close()
                            return False

                    # 保存数据
                    with lock:
                        file_data[idx] = received

                    # 发送确认
                    data_conn.send(b"OK")
                    print(f"[+]数据块{idx}接收成功 ({len(received)}字节)")
                    sock.close()
                    return True
                except Exception as e:
                    print(f"[-]数据端口{data_port}接收失败: {e}")
                    return False
                finally:
                    if sock:  # 确保套接字关闭
                        sock.close()

            # 启动数据接收线程
            ports = [port + 1 + i for i in range(chunks)]

            # 根据是否并行选择执行方式
            if parallel:
                # 多线程并行接收
                with ThreadPoolExecutor(max_workers=chunks) as executor:
                    futures = [executor.submit(receive_chunk, p) for p in ports]
                    results = [f.result() for f in futures]
            else:
                # 单线程顺序接收
                results = []
                for p in ports:
                    results.append(receive_chunk(p))

            # 检查接收结果
            if all(results):
                # 组合文件
                save_dir = os.path.dirname(savepath)
                if save_dir and not os.path.exists(save_dir):
                    os.makedirs(save_dir)

                # 保存文件
                output_path = savepath
                with open(output_path, 'wb') as f:
                    for chunk in file_data:
                        if chunk is not None:
                            f.write(chunk)
                print(f"[+]文件保存至 {output_path}")

                # 如果整个文件被压缩（不是分块压缩），尝试整体解压
                if compressed and not any('compressed' in header for header in metadata.get('chunk_headers', [])):
                    try:
                        with open(output_path, 'rb') as f:
                            compressed_data = f.read()
                        decompressed_data = zlib.decompress(compressed_data)
                        with open(output_path, 'wb') as f:
                            f.write(decompressed_data)
                        print(f"[+]文件整体解压缩成功 ({len(compressed_data)} -> {len(decompressed_data)}字节)")
                    except Exception as e:
                        print(f"[-]文件整体解压缩失败: {e}")

                conn.send(b"SUCCESS")
            else:
                print("[-]文件接收不完整")
                conn.send(b"FAILED")

            # 关闭进度条
            pbar.close()
            conn.close()
            ctrl_sock.close()
        except Exception as e:
            print(f"[-]文件接收失败: {e}")
    else:
        print(f"[-]无效的监听类型: {listen_type}")

    # 关闭日志文件
    log_file.close()
