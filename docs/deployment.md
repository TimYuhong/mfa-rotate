# 部署与日常更新

## 生产配置

前端先构建为 `frontend/dist/`，Docker 再打包后端及静态资源：

```sh
cd frontend
npm ci
npm run build
cd ..
cp deploy/live.env.example deploy/live.env
```

编辑 `deploy/live.env`，填写自己的 HTTPS 域名和访问口令。
可在自己的终端运行 `python -c "import secrets; print(secrets.token_urlsafe(32))"` 生成口令。
实际配置文件已被 Git 与 Docker 构建上下文排除；不要提交真实账号、TOTP 或代理密码。

```sh
docker compose --env-file deploy/live.env up -d --build
docker compose --env-file deploy/live.env ps
```

容器默认只绑定 `127.0.0.1:8790`。在 KPanel 或现有反代中为自己的域名配置可信 HTTPS，
上游填写 `http://127.0.0.1:8790`。不要把账号凭证发送到公网明文 HTTP 入口。

生产 Compose 显式设置 `MFA_LOCAL_DEV=0`。前端隐藏“本机直连”，后端拒绝 `network_mode=direct`；
默认使用代理池。可只读检查 `/api/capabilities` 中的 `routing.allow_direct=false` 和 `default_mode=pool`。
本地开关只在启动器的回环开发环境使用。

## 反向代理

参考 `deploy/nginx-location.conf`，关闭 API 的请求/响应缓冲与缓存。
代理池一次最多 50 条；含 JSON 转义的请求体最大为 64 KiB，反代的请求体限制宜设为 `64k`，
请求体内存缓冲同样设为 `64k`，避免较大代理池被旧的 `8k` 配置拒绝。
应用本身仍按端点限制输入大小。不要开启请求体日志、会话回放或敏感响应采集。
反代读取超时至少 660 秒。

## 更新

1. 在 `/api/capabilities` 核对 `active_count=0`，并停止提交新任务。
2. 更新源码，重建前端，再运行上述 Compose 构建/启动命令。
3. 核对容器状态、域名入口和生产路由设置。

只运行一个 API worker。任务状态只在服务进程内存中，重启不能恢复运行中的任务，
也不能撤销已经完成的账号变更。浏览器结果按域名保存，更新时保持域名和 IndexedDB 名称不变。
新结果的账号、原密码和新密钥一起加密保存在当前浏览器，刷新后仍可导出完整 TXT。
旧结果未保存的密码无法自动恢复，粘贴对应凭证后导出会加密补存，无需再次更换。
这些结果不存入服务器数据库；更换域名、浏览器档案或清理站点数据会影响本地结果可用性。

默认全站合计最多 30 并发（`MFA_GLOBAL_MAX_CONCURRENT`）、每个访问会话最多 10（`MFA_MAX_CONCURRENT`），
容器保持 2 核 CPU、1.5 GiB 内存；配额可以下调。30 是代码硬上限，不是已验证的满载容量。
能力接口中的 `global_max_concurrent` 为全站上限，`active_count` 为全站已占用名额，`max_concurrent` 为页面会话上限。
`reserved_count` 为未消费预留，`waiting_sessions`/`max_waiting_sessions` 为轻量会话等待数及上限；
实际执行加预留不超过全局上限。等待的账号凭证留在浏览器，队列不创建工作进程；等候标记和预留均有短期过期时间。
真实并发容量需用自己的授权账号测量。只运行单实例和一个 API worker；多个进程或副本的内存名额不共享。

## GitHub 维护

```sh
git add app frontend docs deploy compose.yaml Dockerfile README.md
python -B scripts/check_public.py
git diff --cached
git commit -m "Describe the change"
git push
```

仓库保存源码、锁文件和不含凭证的示例配置。个人部署记录、测试账号报告、截图、
压缩部署包、虚拟环境、`node_modules` 和前端产物保留在各自本地，不提交到公开仓库。
本仓库未配置自动部署；推送代码不会自动修改服务器。
