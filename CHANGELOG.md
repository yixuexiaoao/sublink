# 变更日志

版本号记录在仓库根目录 `VERSION` 文件中（前端页面标题、Docker 镜像标签均读取此文件）。每次调整都需要更新 `VERSION` 并在本文件顶部新增对应版本的记录，CI 会检查两者是否一致。

## [3.0.1] - 2026-11-09

### 新增
- 新增 `CLAUDE.md`，记录常用命令、转换流水线架构、新增协议/订阅类型时要改的文件，以及版本与发布规则

### 测试与验证
- `python tests/test_sub.py` 全部通过；前端单文件 `eslint` 无报错，`vue-cli-service build` 成功
- 未进行 GUI 验证：本版本只改文档和版本号，订阅转换等功能代码没有变化

## [3.0] - 2026-11-03

基于原仓库 [jaaksii/sublink](https://github.com/jaaksii/sublink) 2.9-2 的大版本更新。

### 新增
- sing-box 订阅（`/sub/singbox/`），输出 sing-box 1.12+ JSON 完整配置；规则模板 `app/singbox.json` 可在后台编辑，保存时校验 JSON
- Loon 订阅（`/sub/loon/`）、Quantumult X 订阅（`/sub/quanx/`），输出节点格式
- 通用格式订阅（`/sub/general/`），节点链接(远程订阅已展开) base64 编码
- tuic、anytls 协议解析，可输出到 clash(mihomo)、surge、sing-box、v2ray/通用格式
- vless/vmess/trojan grpc `serviceName` 解析；hy2/tuic 的 `insecure`、`allowInsecure` 参数识别
- 订阅转换测试 `tests/test_sub.py`
- GitHub Actions：测试 → 构建镜像冒烟测试 → 推送 amd64/arm64 镜像到 Docker Hub `xiaobaiski/sublink`（标签 `latest`、版本号、`sha-提交`）

### 修复
- **安全**：vmess 链接使用 `eval()` 解析，恶意订阅可在服务器执行任意代码，改为 `json.loads`
- **安全**：JWT 密钥固定为 `sub`，可伪造登录令牌；改为首次启动随机生成并保存到 `db/jwt_secret`，或通过环境变量 `JWT_SECRET_KEY` 指定（升级后需重新登录）
- 令牌无效时前端卡在 Loading，现在退出到登录页
- 全局设置（udp/跳过证书/emoji）需要先打开后台才生效、多进程间不同步，改为生成订阅时从数据库读取
- 未挂载数据目录时容器无法启动（sqlite `unable to open database file`）
- vless `security=none`、vmess 缺少 tls 字段被当成 tls；vmess 非标准格式带 `cert` 参数报错
- 单个节点或远程订阅出错导致整个订阅返回 500，改为跳过出错项
- clash 分组 `auto` 替换时边遍历边修改列表；surge 使用 `re.sub('auto')` 替换全文；surge 布尔值输出为 `True/False`
- 同名节点导致 clash/sing-box 配置无效，现在自动加序号
- 节点协议校验 `'ss' in 节点` 误匹配，改为按协议头校验
- 删除/修改不存在的节点报 500；登录时 IP 归属地查询失败导致无法登录
- Windows 下读写模板报 gbk 编码错误，统一 utf-8
- Docker 基础镜像 Debian bullseye 停止维护导致构建失败

### 优化
- 规则模板解析结果缓存 + libyaml，200 个节点生成 clash 订阅约 215ms → 28ms
- 远程订阅并发拉取，15 秒超时，60 秒内重复请求使用缓存；emoji 国旗查询缓存并发
- 批量写库改为单事务提交，修改订阅失败不丢数据
- 节点解析/格式转换拆分到 `app/converter.py`
- Docker 镜像升级 Python 3.12，依赖精简为 22 个，镜像 215MB → 61MB；gunicorn `--preload` + gthread，可用 `WORKERS`、`THREADS` 调整

## [2.9-1]

- 修复 surge hy2 协议
- 新增删除登录记录命令
- 新增 query 中 cert 证书自定义
