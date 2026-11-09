# sublink for python3
[![电报群组][telegram-image]][tg-url]
![python][python-image]
![vue2][vue-image]
[![作者][author-image]][author-url]

[telegram-image]:https://img.shields.io/badge/%E7%94%B5%E6%8A%A5%E7%BE%A4%E7%BB%84-TG-red?label=%E7%94%B5%E6%8A%A5%E7%BE%A4%E7%BB%84
[tg-url]:https://t.me/+u6gLWF0yP5NiZWQ1
[python-image]:https://img.shields.io/badge/python3.8.2-blue
[vue-image]:https://img.shields.io/badge/vue2-rand
[author-image]:https://img.shields.io/badge/%E4%BD%9C%E8%80%85-TG-8A2BE2
[author-url]:https://t.me/toutie_1


<p align="center">
   <img width="45%" style="border:solid 1px #DCEBFB" src="readme/1.png" >
   <img width="45%" style="border:solid 1px #DCEBFB" src="readme/2.png">
</p>

#### USDT (TRC20):TQ1bheWesAxByGrMztrZFhRFrUZDbJkdse

# 此项目不在维护,新版本：https://github.com/gooaclok819/sublinkX

# 本仓库与原仓库相比新增的功能

本仓库基于原仓库 [jaaksii/sublink](https://github.com/jaaksii/sublink) 2.9-2 版本，Docker 镜像为 [xiaobaiski/sublink](https://hub.docker.com/r/xiaobaiski/sublink)（amd64/arm64）。

## 新增的订阅类型与协议

| 新增功能 | 说明 |
|----------|------|
| sing-box 订阅 | 生成类型 `singbox`，地址 `/sub/singbox/订阅名(base64)`，输出 sing-box 1.12+ JSON 完整配置(CI 中用 sing-box `check` 校验) |
| sing-box 规则模板 | 生成类型选 singbox 后可「编辑规则」，模板为 `app/singbox.json`，分组 `outbounds` 中写 `auto` 插入本订阅所有节点；保存时校验 JSON |
| Loon 订阅 | 生成类型 `Loon`，地址 `/sub/loon/订阅名(base64)`，输出 Loon 节点格式，在 Loon 中作为「订阅节点」添加 |
| Quantumult X 订阅 | 生成类型 `Quantumult X`，地址 `/sub/quanx/订阅名(base64)`，输出 QX 节点格式，在 `[server_remote]` 中引用 |
| 通用格式 | 生成类型 `通用格式`，地址 `/sub/general/订阅名(base64)`，节点链接(远程订阅已展开)经 base64 编码，适合 v2rayN、NekoBox、小火箭等直接导入 |
| tuic 协议 | `tuic://uuid:password@server:port?congestion_control=bbr&udp_relay_mode=native&alpn=h3&sni=xx&allow_insecure=1#名称` |
| anytls 协议 | `anytls://password@server:port/?sni=xx&insecure=1&fp=chrome#名称`(未写端口默认 443) |
| vless/vmess/trojan grpc | 解析 grpc `serviceName`，clash 与 sing-box 可用 |
| Docker 自动构建 | GitHub Actions：先跑订阅转换测试，再构建镜像冒烟测试，通过后推送 amd64/arm64 镜像到 Docker Hub(推送 master 或打 `v*` 标签触发) |

各订阅类型支持的协议(不支持的节点会自动跳过)：

| 订阅类型 | ss | ssr | vmess | vless | trojan | hysteria | hysteria2 | tuic | anytls |
|----------|----|-----|-------|-------|--------|----------|-----------|------|--------|
| v2ray / 通用格式(base64) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| clash(需 mihomo/Clash Meta 内核) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| sing-box(1.12+) | ✅ | ❌ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| surge | ✅ | ❌ | ✅ | ❌ | ✅ | ❌ | ✅ | ✅ | ✅ |
| Loon | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ | ✅ | ❌ | ❌ |
| Quantumult X | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ |

注：surge/Loon/Quantumult X 只生成 tcp、ws 传输的节点(grpc 节点跳过)；surge 的 anytls 需要较新版本。

## 修复的问题

| 问题 | 影响 |
|------|------|
| vmess 链接用 `eval()` 解析 | **安全漏洞**：恶意订阅可在服务器上执行任意代码，已改为 `json.loads` |
| JWT 密钥固定为 `sub` | **安全漏洞**：任何人都能伪造登录令牌访问后台。现在首次启动随机生成并保存到 `db/jwt_secret`，也可用环境变量 `JWT_SECRET_KEY` 指定(升级后需重新登录) |
| 全局设置(udp/跳过证书/emoji)不生效 | 重启后要先打开后台页面才会加载，多个 gunicorn 进程之间也不同步；现在每次生成订阅都从数据库读取 |
| 未挂载数据目录时容器无法启动 | sqlite 报 `unable to open database file`，现在自动创建 `app/db` |
| vless `security=none` 被当成 tls | 节点无法连接 |
| vmess 缺少 tls 字段时被当成 tls、非标准格式带 `cert` 参数时报错 | 节点无法连接/订阅生成失败 |
| 一个节点或远程订阅出错导致整个订阅 500 | 现在跳过出错的节点/订阅，其它节点正常输出 |
| clash 分组 `auto` 替换时边遍历边修改列表，节点追加到末尾 | 现在在 `auto` 原位置插入 |
| surge 用 `re.sub('auto')` 替换全文 | 规则里包含 auto 的内容也会被替换；现在只替换 `[Proxy Group]` 中单独的 `auto` |
| surge 布尔值输出为 `True/False` | 改为 `true/false` |
| 同名节点 | clash/sing-box 要求名称唯一，现在重名自动加序号 |
| 节点协议校验 `'ss' in 节点` | 任何包含 ss 的文本都被当成节点；现在按协议头校验 |
| 删除/修改不存在的节点报 500、登录时 IP 归属地查询失败导致无法登录 | 已修复 |
| Windows 下读写模板报 gbk 编码错误 | 统一使用 utf-8 |
| hy2/tuic 的 `insecure`、`allowInsecure` 参数，远程订阅 urlsafe base64、`
` 换行 | 现在都能正确识别 |

## 性能优化

- 规则模板解析结果按修改时间缓存，并使用 libyaml(C 实现)解析/输出：200 个节点生成 clash 订阅由约 215ms 降到约 28ms
- 多个远程订阅并发拉取(带 15 秒超时，60 秒内重复请求使用缓存)，不会因为某个订阅卡住而一直等待
- emoji 国旗查询结果缓存，开启 emoji 时并发解析节点
- 批量创建/修改订阅改为一次事务提交(原来每个节点提交一次)，修改订阅时删除和写入在同一事务中，失败不丢数据
- Docker 镜像升级为 Python 3.12，依赖从 50 多个精简到实际用到的 22 个(去掉 pandas/numpy 等)，镜像更小、构建更快
- gunicorn 使用 `--preload` 只初始化一次数据库，并改为 gthread 线程模式，拉取远程订阅时不阻塞其它请求(可用 `WORKERS`、`THREADS` 环境变量调整)

## 测试

```
pip install -r requirements.txt
python tests/test_sub.py
```

# 版本

当前版本 **3.0.2**，各版本变更见 [CHANGELOG.md](CHANGELOG.md)。

# 功能说明：

节点转换成订阅，并且能够一直存储

方便多订阅管理，个人搭建使用

解决安全问题预防被偷节点,集成前后端

目前支持v2ray|clash|surge|sing-box|Loon|Quantumult X|通用格式

节点协议支持:ss|ssr|vmess|vless|trojan|hysteria|hysteria2|tuic|anytls

订阅地址格式为 /sub/类型/订阅名(base64)，类型可选 v2ray clash surge singbox loon quanx general；sing-box 需要 1.12 及以上版本

v2ray格式通用的软件已测有下:v2rayn 小火箭等，还有一些没用过不知名

默认账户密码都是admin，请记得修改否则容易泄漏

# 安装说明：

## 拉取或者更新docker镜像

如果你有旧版本拉取前可以先停止和删除容器再删除镜像

docker rm -f sublink

docker images

docker rmi 这里填写IMAGEID

然后拉取镜像输入，默认拉取就是最新版本

 ```docker pull xiaobaiski/sublink```

## 启动docker

<details>
<summary>挂载到当前目录下(方式一)</summary>

进入到你的目录比如你可以创建一个sublink目录然后输入

```
docker run --name sublink -p 8000:5000 \
-v $PWD/db:/app/app/db \
-e PORT=5000 \
-d xiaobaiski/sublink
```

</details>

<details>
<summary>挂载到数据卷(方式二)</summary>

```
docker run --name sublink -p 8000:5000 \
-v sublink_data:/app/app/db \
-e PORT=5000 \
-d xiaobaiski/sublink
```
查看数据存放目录docker volume inspect sublink_data
</details>

<details>
<summary>docker-compose(方式三)</summary>

下载docker-compose.yml,然后启动

```docker-compose up -d```

</details>

| 参数 | 说明          |
|--------------|--------------|
| p          | 公网端口:容器端口    |
| name       | docker名字  |
| v        | 挂载目录 |
| e        | 端口环境变量  |
| d        | 后台方式启动  |


# 假如你忘记了账号或者密码

初始化为admin，确保你的容器在运行的时候终端执行以下命令：

    docker exec -it sublink bash -c "python init_user_pw.py; exit"

# 清空登录记录

确保你的容器在运行的时候终端执行以下命令：
    docker exec -it sublink bash -c "python init_login_log.py; exit"

## Stargazers over time
[![Stargazers over time](https://starchart.cc/jaaksii/sublink.svg?variant=adaptive)](https://starchart.cc/jaaksii/sublink)
