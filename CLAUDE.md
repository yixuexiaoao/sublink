# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## 项目概述

节点链接转订阅的自建服务：Flask + SQLite 后端，Vue 2 + Element UI 前端，单容器部署。本仓库 fork 自 `jaaksii/sublink` 2.9-2，3.0 起独立演进，Docker 镜像是 `xiaobaiski/sublink`（账号与 GitHub 用户 `yixuexiaoao` 不同）。

## 常用命令

后端（Python 3.12，依赖全部固定版本）：

```bash
pip install -r requirements.txt
python run.py                 # 开发服务器，端口 5000，默认账号 admin/admin
python tests/test_sub.py      # 全部测试
```

- 测试是一个不依赖外网的脚本（断言集中在 `main()` 里），没有 pytest，也不能单独运行某一条；要测某一项只能临时注释其它断言。
- 可选：`python tests/test_sub.py <输出目录>` 把生成的配置写到该目录；设置 `SINGBOX_BIN=<sing-box 路径>` 时额外跑 `sing-box check`。
- 测试直接读写 `app/db`，会改动本地的全局设置（把 udp 设为开启），不要在有重要数据的开发库上跑。
- Windows 控制台中文或 emoji 报 gbk 编码错误时，加环境变量 `PYTHONIOENCODING=utf-8`。

前端（在 `web/` 下，用 `yarn.lock`，npm 会报依赖冲突；Node 24 需要 `--ignore-engines`）：

```bash
npx yarn@1.22.22 install --frozen-lockfile --ignore-engines
npx vue-cli-service serve                     # 开发，/api 代理到 127.0.0.1:5000
npx eslint --no-fix src/views/index.vue       # 只 lint 改动的文件
npx vue-cli-service build
```

不要用 `yarn lint`：它会扫到第三方的 `src/assets/icon/iconfont.js`，报一百多个无关错误，并且默认自动修复。

## 架构

转换流水线在 `app/converter.py`，`app/view.py` 只放路由和数据库操作：

```
Sub 表中的节点/远程订阅
  -> collect_links()   并发拉取并展开 http(s) 订阅
  -> parse_nodes()     经 PARSERS / NodeParse 解析，出错的节点跳过，重名加序号
  -> *_encode()        由 ENCODERS 按 /sub/<target>/ 分发
```

关键约定：

- **clash(mihomo) 格式的字典是中间格式。** `NodeParse` 的所有方法都产出这种字典，surge、sing-box、Loon、Quantumult X 都由它转换，所以字段名用的是 clash 的（如 `skip-cert-verify`、`ws-opts`）。v2ray 和通用格式例外，直接对原始链接做 base64，因此不经解析，也不受全局设置影响。
- **全局设置放在 `converter.settings`，生成订阅前由 `view.load_config()` 从数据库读取。** gunicorn 是多进程，不能只靠进程内变量同步。
- **规则模板有两份。** `app/clash.yaml`、`app/surge.conf`、`app/singbox.json` 只是初始模板，首次启动时由 `model.create_db()` 复制到 `app/db/`，运行时只读 `app/db/` 下的副本，后台编辑的也是它。改仓库里的模板对已部署实例不生效。模板中分组列表里单独的 `auto` 会被替换成本订阅的所有节点。
- **`app/db/` 被 git 和 Docker 忽略，存放全部运行时数据：** `sub.db`、模板副本、`jwt_secret`（未设环境变量 `JWT_SECRET_KEY` 时随机生成）。
- **登录密码由前端做 MD5 后提交**，后端直接比较 MD5，改登录逻辑时两端要一起改。
- **建表用 `db.create_all()`，部署流程不跑 Alembic。** `migrations/` 是历史遗留，给已有表加字段不会自动生效。`app/xui.py`、`uwsgi.ini` 也未被使用。
- **gunicorn 用 `--preload` + gthread**，`run.py` 在 fork 前初始化数据库并 `engine.dispose()`；`converter` 中的模块级缓存（模板、远程订阅、emoji）每个进程各有一份。

## 改动时容易漏的地方

**构建产物要提交。** Docker 镜像不构建前端，直接打包 `app/static` 和 `app/templates/index.html`。改了 `web/` 之后必须构建并替换：

```bash
cd web && npx vue-cli-service build && cd ..
git rm -rqf app/static/js app/static/css
cp -r web/dist/js web/dist/css app/static/
cp web/dist/index.html app/templates/index.html
rm -rf web/dist
```

**新增节点协议：** `NodeParse` 方法、`PARSERS`、`view.py` 的 `subname_list`（否则创建订阅时会被过滤）、各 `*_line` / `singbox_outbound` 的转换分支、README 的协议支持表。

**新增订阅类型：** `*_encode` 和 `ENCODERS`、`web/src/views/index.vue` 的 `EDIT.option`（及 `tips`）、`tests/test_sub.py`、`.github/workflows/docker.yml` 冒烟测试的 target 列表、README。

## 版本与发布

- 每次调整都要更新根目录 `VERSION`，在 `CHANGELOG.md` 顶部新增 `## [版本] - 日期`（前 20 行内），并同步 README 的 `当前版本 **X**`。CI 校验这三处，不一致就不会发布。
- 前端版本号在构建时由 `web/vue.config.js` 从 `VERSION` 写入，**改版本号后要重新构建前端**，否则页面仍显示旧版本。CI 不检查这一点。
- **推送到 `master` 就会发布：** `.github/workflows/docker.yml` 依次运行测试、amd64 镜像冒烟测试，然后把 amd64/arm64 镜像推送到 Docker Hub，标签为 `latest`、版本号、`sha-<提交>`。
