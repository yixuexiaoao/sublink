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

本仓库基于原仓库 [jaaksii/sublink](https://github.com/jaaksii/sublink) 2.9-2 版本，新增内容如下：

| 新增功能 | 说明 |
|----------|------|
| sing-box 订阅 | 新增生成类型 `singbox`，订阅地址 `/sub/singbox/订阅名(base64)`，输出 sing-box 1.12+ JSON 配置(已用 sing-box 1.14 `check` 校验) |
| sing-box 规则模板 | 前端「生成类型」选 singbox 后可「编辑规则」，模板为 `app/singbox.json`，分组 `outbounds` 中写 `auto` 会插入本订阅所有节点；保存时校验 JSON 格式 |
| tuic 协议 | 支持 `tuic://uuid:password@server:port?congestion_control=bbr&udp_relay_mode=native&alpn=h3&sni=xx&allow_insecure=1#名称`，可输出到 clash(mihomo)/surge(tuic-v5)/sing-box/v2ray |
| anytls 协议 | 支持 `anytls://password@server:port/?sni=xx&insecure=1&fp=chrome#名称`(未写端口默认 443)，可输出到 clash(mihomo)/surge/sing-box/v2ray |
| vless grpc | vless 节点 `type=grpc` 时解析 `serviceName`，clash 与 sing-box 均可使用 |
| Docker 自动构建 | 新增 GitHub Actions，推送到 master 或打 `v*` 标签时自动构建 amd64/arm64 镜像并推送到 Docker Hub |

各输出格式支持的协议：

| 输出格式 | ss | ssr | vmess | vless | trojan | hysteria | hysteria2 | tuic | anytls |
|----------|----|-----|-------|-------|--------|----------|-----------|------|--------|
| v2ray(原样输出) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| clash(需 mihomo/Clash Meta 内核) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| surge | ✅ | ❌ | ✅ | ❌ | ✅ | ❌ | ✅ | ✅ | ✅ |
| sing-box(1.12+) | ✅ | ❌ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |

注：sing-box 已移除 ssr，ssr 节点在 sing-box 订阅中会被自动跳过；surge 的 anytls 需要较新版本的 surge。

# 2.9-1更新说明：

修复surpe hy2协议
新增删除登录记录命令
新增query中cert证书自定义

# 功能说明：

节点转换成订阅，并且能够一直存储

方便多订阅管理，个人搭建使用

解决安全问题预防被偷节点,集成前后端

目前支持v2ray|clash|surge|sing-box

节点协议支持:ss|ssr|vmess|vless|trojan|hysteria|hysteria2|tuic|anytls

sing-box订阅地址格式为 /sub/singbox/订阅名(base64)，需要sing-box 1.12及以上版本(anytls出站需要1.12+)

v2ray格式通用的软件已测有下:v2rayn 小火箭等，还有一些没用过不知名

默认账户密码都是admin，请记得修改否则容易泄漏

# 安装说明：

## 拉取或者更新docker镜像

如果你有旧版本拉取前可以先停止和删除容器再删除镜像

docker rm -f sublink

docker images

docker rmi 这里填写IMAGEID

然后拉取镜像输入，默认拉取就是最新版本

 ```docker pull yixuexiaoao/sublink```

## 启动docker

<details>
<summary>挂载到当前目录下(方式一)</summary>

进入到你的目录比如你可以创建一个sublink目录然后输入

```
docker run --name sublink -p 8000:5000 \
-v $PWD/db:/app/app/db \
-e PORT=5000 \
-d yixuexiaoao/sublink
```

</details>

<details>
<summary>挂载到数据卷(方式二)</summary>

```
docker run --name sublink -p 8000:5000 \
-v sublink_data:/app/app/db \
-e PORT=5000 \
-d yixuexiaoao/sublink
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
