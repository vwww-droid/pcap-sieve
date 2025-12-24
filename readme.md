# pcap-sieve

从 pcap 文件中提取所有明文 payload 里的 IP, domain 和敏感信息.

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

# 使用自定义正则文件
python pcap-sieve.py -r capture.pcap --regex custom_patterns.json
```

## Requirements

- Python 3.6+
- pyshark (基于 Wireshark/tshark)
- 系统需安装 Wireshark 或 tshark

## Output

- `{output}.json`: 去重的 IP, domain 和敏感信息列表 + 统计信息
- `{output}.jsonl`: 每条命中的详细信息(包含归属包/流)

输出 JSON 格式示例:
```json
{
  "ipv4": ["8.8.8.8", "1.1.1.1"],
  "ipv6": ["2001:4860:4860::8888"],
  "domains": ["example.com", "api.example.net"],
  "Amazon_AWS_Access_Key_ID": ["AKIAIOSFODNN7EXAMPLE"],
  "Generic_API_Key": ["api_key=abcd1234..."],
  "stats": {
    "ipv4_count": 2,
    "ipv6_count": 1,
    "domain_count": 2,
    "sensitive_patterns": 2,
    "match_count": 100
  }
}
```

## 过滤规则

### IP 过滤
- **IPv4**: 排除 0.0.0.0, 127.x.x.x 等特殊地址
- **IPv6**: 排除过短地址(如 `1::`), link-local, multicast 地址

### Domain 过滤
- **文件扩展名**: 排除 `.png/.webp/.js/.css/.apk` 等常见文件后缀
- **UUID 格式**: 排除 `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx.xxx` 格式
- **随机字符串**: 排除辅音密度 >80% 的疑似随机域名
- **格式校验**: TLD 必须 >=2 字符且为字母, 每个 label 长度 2-63 字符

## Features

### 内置提取能力
- **IPv4/IPv6**: 自动验证和过滤特殊地址
- **域名**: 智能过滤文件扩展名、UUID、随机字符串
- **敏感信息**: 通过 `regexes.json` 支持 50+ 种敏感数据模式

### 敏感信息检测

见 [regex.json](./regexes.json)

#### 认证凭据
- AWS Access Key/Secret, API Keys, Bearer/Basic Auth
- JWT Token, OAuth Token, Session ID
- Slack/GitHub/Stripe/Twilio API tokens

#### 云服务
- AWS S3 Bucket URLs, Firebase URLs
- Google Cloud Platform OAuth
- Heroku/Cloudinary credentials

#### 私钥证书
- RSA/DSA/EC Private Keys
- PGP Private Key Block
- SSH Private Keys

#### 社交媒体
- Facebook/Twitter/Discord tokens
- OAuth credentials

#### 其他
- Email addresses (mailto:)
- MAC addresses, IP addresses
- Passwords in URLs
- CTF flags (HackerOne, HackTheBox, TryHackMe)

### 待添加

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
- [x] 支持自定义 regex pattern (通过 --regex 参数)
- [ ] 上下文截取(命中前后 N bytes)
- [ ] 输出格式扩展(CSV, XML)

## More Regex Resources

- **[apkleaks](https://github.com/dwisiswant0/apkleaks/blob/master/config/regexes.json)**: Android APK 敏感信息扫描 (当前使用)
- **[Gitleaks](https://github.com/gitleaks/gitleaks/blob/master/config/gitleaks.toml)**: Git 仓库密钥泄露检测 (8.18+ rules)
- **[truffleHog](https://github.com/trufflesecurity/trufflehog/tree/main/pkg/detectors)**: 高精度密钥检测器 (700+ detectors)
- **[detect-secrets](https://github.com/Yelp/detect-secrets)**: Yelp 的密钥检测框架
- **[shhgit](https://github.com/eth0izzle/shhgit/blob/master/config.yaml)**: 实时 GitHub 密钥监控
- **[SecretFinder](https://github.com/m4ll0k/SecretFinder)**: JS 文件中的敏感信息
- **[noseyparker](https://github.com/praetorian-inc/noseyparker)**: 规则质量高, 误报少

## Contributing

欢迎提交 Issue 和 Pull Request! 

- **Bug 报告**: 请提供 pcap 样本和错误信息
- **功能建议**: 描述具体的使用场景和需求  
- **代码贡献**: 遵循现有代码风格, 添加相应测试

## License

MIT License

