# pcap-sieve

从 pcap 文件中提取所有明文 payload 里的 IP 和 domain.

主要用于处理 [r0capture](https://github.com/r0ysue/r0capture) 输出的已解密流量(HTTP, WebSocket, FTP, XMPP, IMAP, SMTP, Protobuf 等).

## Installation

```bash
# 安装依赖
pip install -r requirements.txt

# 或手动安装
pip install pyshark
```

## Usage

```bash
# 基础用法
python pcap-sieve.py -r capture.pcap

# 输出到指定文件
python pcap-sieve.py -r capture.pcap -o result.json

# 处理目录下所有 pcap
python pcap-sieve.py -d ./pcaps/ -o result.json

# 打印输出到终端
python pcap-sieve.py -r capture.pcap -p
```

## Requirements

- Python 3.6+
- pyshark (基于 Wireshark/tshark)
- 系统需安装 Wireshark 或 tshark

## Output

- `{output}.json`: 去重的 IP 和 domain 列表 + 统计信息
- `{output}.jsonl`: 每条命中的详细信息(包含归属包/流)

## 过滤规则

### IP 过滤
- **IPv4**: 排除 0.0.0.0, 127.x.x.x 等特殊地址
- **IPv6**: 排除过短地址(如 `1::`), link-local, multicast 地址

### Domain 过滤
- **文件扩展名**: 排除 `.png/.webp/.js/.css/.apk` 等常见文件后缀
- **UUID 格式**: 排除 `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx.xxx` 格式
- **随机字符串**: 排除辅音密度 >80% 的疑似随机域名
- **格式校验**: TLD 必须 >=2 字符且为字母, 每个 label 长度 2-63 字符

## Roadmap

### 计划支持的数据类型

#### 认证凭据
- **JWT Token**: 提取和解析 JWT payload
- **API Key**: 各种格式的 API 密钥 (sk-xxx, AIza-xxx, etc.)
- **Session ID**: 会话标识符和 Cookie
- **OAuth Token**: Bearer token, refresh token 等

#### 设备指纹
- **IMEI/IMSI**: 设备唯一标识 (15位数字)
- **Android ID**: 系统生成的设备 ID (16位hex)
- **MAC Address**: 网络接口物理地址
- **Device Model**: 设备型号和厂商信息
- **User-Agent**: 完整的 UA 字符串分析

#### 个人信息
- **手机号码**: 各国格式的电话号码 (+86, +1, etc.)
- **邮箱地址**: Email 地址提取
- **身份证号**: 中国身份证等证件号码
- **银行卡号**: 信用卡/借记卡号码 (Luhn 校验)

#### 地理位置
- **GPS 坐标**: 经纬度信息 (lat/lng)
- **IP 地理位置**: 结合 GeoIP 数据库
- **基站信息**: Cell ID, LAC, MNC, MCC

#### 应用数据
- **包名**: Android 应用包名 (com.xxx.xxx)
- **版本信息**: App 版本号和构建信息
- **推送 Token**: FCM, 小米推送, 华为推送等 token
- **广告 ID**: GAID, OAID 等广告标识符

### 扩展功能
- [ ] 支持自定义 regex pattern
- [ ] 支持排除列表(exclude list)  
- [ ] 上下文截取(命中前后 N bytes)
- [ ] 数据脱敏选项
- [ ] 输出格式扩展(CSV, XML)
- [ ] 实时流量分析模式

## Contributing

欢迎提交 Issue 和 Pull Request! 

- **Bug 报告**: 请提供 pcap 样本和错误信息
- **功能建议**: 描述具体的使用场景和需求  
- **代码贡献**: 遵循现有代码风格, 添加相应测试

## License

MIT License

