# Netool - 网络工具集

![命令行工具](https://img.shields.io/badge/平台-Windows|Linux|macOS-blue)
[![许可证](https://img.shields.io/badge/许可证-LGPL3.0-green)](LICENSE)
[Netool](https://netool.netlify.app)

Netool 是一个功能强大的命令行网络工具集，提供TCP监听、数据发送、网络扫描等功能，支持高效的文件传输和图形界面操作。采用LGPL-3.0开源许可证，支持自由使用和二次开发。

## 功能列表

- 🕒 **监听服务**：启动TCP服务器接收消息或文件
- 📤 **发送数据**：向指定TCP服务发送消息或文件
- 🔍 **网络扫描**：执行主机发现和端口扫描
- 🖥️ **图形界面**：启动可视化操作界面

## 安装

### 二进制安装
从[发布页面]([https://github.com/xue-gongziqin/netool/releases](https://github.com/xuegongziqin/netool/releases))下载对应平台的二进制文件

## 使用说明

### 1. 监听服务 (listen)

启动TCP监听服务，支持消息和文件接收

```bash
netool listen type=<msg/file> [参数]
```

**参数说明：**
| 参数       | 说明                          | 必需 | 默认值    |
|------------|-------------------------------|------|-----------|
| type       | 监听类型(msg/file)            | ✔️   | -         |
| ip         | 监听IP地址                    |      | 0.0.0.0   |
| port       | 监听端口                      | ✔️   | -         |
| savepath   | 文件保存路径(文件类型必需)    |      | -         |
| parallel   | 并行接收(true/false)          |      | false     |
| maxthread  | 最大线程数                    |      | 100       |

**示例：**
```bash
# 监听消息
netool listen type=msg port=8080

# 监听文件
netool listen type=file port=8080 savepath=/path/to/save
```

---

### 2. 发送数据 (send)

向指定TCP服务发送消息或文件

```bash
netool send type=<msg/file> [参数]
```

**参数说明：**
| 参数       | 说明                                  | 必需 | 默认值    |
|------------|---------------------------------------|------|-----------|
| type       | 发送类型(msg/file)                    | ✔️   | -         |
| ip         | 目标IP地址                            | ✔️   | -         |
| port       | 目标端口                              | ✔️   | -         |
| msg        | 发送消息内容(消息类型)               |      | -         |
| filepath   | 文件路径(文件类型必需)               |      | -         |
| savepath   | 文件保存路径(文件类型)               |      | -         |
| times      | 发送次数(消息类型)                   |      | 1         |
| parallel   | 并行发送(true/false)                  |      | false     |
| maxthread  | 最大线程数                            |      | 100       |
| compress   | 压缩发送(true/false，仅文件类型)     |      | false     |

**示例：**
```bash
# 发送消息
netool send type=msg ip=192.168.1.100 port=8080 msg="Hello" times=10

# 发送文件(带压缩)
netool send type=file ip=192.168.1.100 port=8080 filepath=/path/to/file savepath=/save/path compress=true
```

---

### 3. 网络扫描 (scan)

执行网络扫描任务，支持主机发现和端口扫描

```bash
netool scan type=<ip/port>
```

#### 3.1 扫主机
```bash
netool scan type=ip
```
> 📌 注意：使用ICMP+SYN+ARP混合扫描，请确保有足够权限

#### 3.2 扫端口
```bash
netool scan type=port ip=<ip> startport=<startport> endport=<endport> [参数]
```

**参数说明：**
| 参数       | 说明                  | 必需 | 默认值    |
|------------|-----------------------|------|-----------|
| ip         | 目标IP地址            | ✔️   | -         |
| startport  | 起始端口              | ✔️   | -         |
| endport    | 结束端口              | ✔️   | -         |
| parallel   | 并行扫描(true/false)  |      | false     |
| maxthread  | 最大线程数            |      | -         |

**示例：**
```bash
# 扫描主机
netool scan type=ip

# 扫描端口(并行模式)
netool scan type=port ip=192.168.1.100 startport=1 endport=1024 parallel=true maxthread=50
```

---

### 4. 图形界面（目前已删除）

启动图形用户界面
```bash
netool gui
```

### 5.交互式
```bash
netool
```
即可进入交互模式

## 数据传输机制

1. **双向验证**：
   - 发送方生成10位随机数
   - 接收方计算随机数*2并返回
   - 双方验证通过后发送"Ready"信号

2. **文件传输**：
   - 文件分块传输（每块包含哈希验证）
   - 支持压缩传输
   - 断点续传支持
   - 并行传输加速

## 注意事项

1. 使用网络扫描功能需要管理员/root权限
2. 文件传输时请确保有足够的磁盘空间
3. 高并发模式下注意系统资源限制
4. 使用压缩传输可提高大文件传输效率
5. 传输敏感数据时建议配合加密工具使用

## 开源许可

本项目采用 [LGPL-3.0 许可证](LICENSE)。您可以在遵守许可证条款的前提下：
- 自由使用本软件
- 修改源代码
- 分发软件副本
- 将本软件作为库链接到专有软件

## 贡献指南

欢迎提交Issue和Pull Request：
1. Fork项目仓库
2. 创建特性分支 (`git checkout -b feature/your-feature`)
3. 提交更改 (`git commit -am 'Add some feature'`)
4. 推送到分支 (`git push origin feature/your-feature`)
5. 创建Pull Request

### 建议帮助我编译macOS以及Linux的发行版，也可以增加对macOS的适配。

**贡献者须知**：提交的代码将遵循项目的LGPL-3.0许可证。

---

**Netool** © 2025 - 高效、可靠、多功能的网络工具集
