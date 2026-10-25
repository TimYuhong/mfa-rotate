# Keyshift / MFA Rotate

独立 React + FastAPI 工具。默认 `MFA_MODE=disabled`，HTTP 公网预览禁止接收凭证。

单个账号只需粘贴一行：`账号---密码---当前2FA密钥`。批量导入使用相同格式，每行一条。
成功导出为 TXT：`账号---原密码---新2FA密钥`。兼容旧四连字符和三列 TAB 输入；密码含分隔符时使用 TAB，格式不明确时拒绝猜测。

为生成完整 TXT，原密码仅在当前页面内存暂存，不进入 IndexedDB 或后端结果。刷新后若要导出已保存结果，重新粘贴对应原始凭证并直接点导出即可，无需再次更换。页面只提供验证成功的 TXT 导出，不再提供 JSON 恢复备份。未完成结果仍本机加密保存，可查看/复制新密钥并核对任务。

正常刷新不会清除已保存结果。同一浏览器、同一站点使用 IndexedDB 加密保留；本地地址与线上域名各自独立。
“已保存结果”中的“清空结果”会要求再次确认，仅清空本站结果，不改变账号密钥或外观设置。
本页运行任务时禁止清空；操作前请先导出并结束其他标签页任务。清理浏览器站点数据、无痕模式或浏览器回收存储也可能导致结果丢失，浏览器保存不替代导出备份。

Python 运行时要求 3.12+；Docker 固定为已验证的 3.12 镜像摘要。构建阶段会实际导入协议模块，防止仅网页可访问而执行器无法加载。

## 代理池与背景

左侧代理池支持每行一个标准 URL，或 `主机:端口:用户名:密码`，省略协议时使用 SOCKS5。
显式 `http://`、`https://`、`socks5://`、`socks5h://` 保留原协议；HTTPS 代理要求代理入口本身支持 TLS。
直接粘贴即可，输入自动加密保存，刷新原样恢复，包括尚未填写完整的草稿；不要求保存或预检测。
框下显示有效条数，可点击“随机测试”手动抽取一条代理，显示 `第 N 条代理 · SG · IP · 1234 ms`；
连接失败也显示选中的代理编号。
延迟是一次匿名 HTTPS 请求耗时（包含代理建连，不含输入解析与 DNS 准备），不代表 ICMP ping 或账号登录成功。
测试始终使用代理池及实际执行的前置网络，即使本机直连开关开启也不会绕过所测试的代理。
粘贴、刷新不自动触发测试，失败显示原因，不自动切换、重试或回退直连。
任务开始时随机选择当前未占用的代理；全部条目已被占用时允许随机复用，每个访问会话最多 10 并发，全站合计最多 30，不受代理条数限制。
例如 3 条代理可以执行 10 个并发任务，先分配不同条目，再随机复用。
同一任务的登录、重新认证、更换与新密钥验证使用同一代理，运行中不自动切换或回退直连。

本地默认开启“本机直连”，开启时绕过应用代理池、保留系统网络/TUN 设置，关闭后使用代理池。
Windows 已启用系统代理时，“本机直连”沿用当前系统代理；未启用则使用本机网络。
关闭“本机直连”后，填写的代理也通过当前系统代理/本机网络连接；最终出口仍是填写的代理。
任务启动时读取并固定当前设置，不修改 Windows 或 Clash；没有系统代理时沿用 OS/TUN 路由。
系统 HTTP/HTTPS CONNECT、SOCKS5/SOCKS5H 前置入口由任务内 TCP 通道承接，支持四种最终代理协议。
线上模式隐藏开关并在服务端禁止直连，用户需要填写自己的代理池。
代理配置独立加密保存在本站浏览器档案，服务器仅在当前会话内存中使用；清空结果不会清空代理池。
不同浏览器档案、站点和服务会话相互隔离；共用同一浏览器档案仍共享本地配置。
任务执行时，本地 SOCKS5 会识别 TUN 的虚拟 DNS，对固定认证目标使用公网解析并优先 IPv4；
代理和目标解析结果随任务固定，避免将 `198.18.*` 虚拟地址发给远端代理。其他私网地址不会被放行。
代理输入框内展示四种 URL 示例和默认 SOCKS5 提示，自动加密保存行为保留，不常驻显示保存状态文字。

默认少量静态点缀，“轻雪”可选。雪花在浏览器内使用 CSS 动画，桌面最多 24 个、手机最多 10 个；
后台页面暂停，减少动态效果时回到静态点缀。服务器只提供静态资源，不承担动画逐帧计算。

## 本地运行

前端基础组件直接来自 shadcn/ui 官方 New York registry，源码保存在
`frontend/src/components/ui/`，来源与局部定制列于 `SOURCES.json`，MIT 许可一并保留。
交互使用 Radix，图标使用 Lucide，主题通过 Tailwind CSS 语义变量统一。
`frontend/components.json` 配置可用于后续按需添加组件；不再使用原有单文件的仿样式基础组件封装。

要求 Python 3.12+ 和 Node.js 22 LTS。先克隆仓库，在项目根目录执行：

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --no-deps -r requirements.lock
Copy-Item .env.example .env
Set-Location frontend
npm ci
npm run build
Set-Location ..
```

编辑 `.env`，设置自己的 `MFA_ACCESS_KEY`；使用模拟模式填 `MFA_MODE=demo`，
真实操作填 `MFA_MODE=live`。然后运行：

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\start-local.ps1
```

访问 `http://127.0.0.1:8790/`。启动器只从本机 `.env` 读取配置，
该文件不进入 Git 或 Docker 构建上下文；服务仅监听回环地址。

## 维护与验证

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
.\.venv\Scripts\python.exe -B -m pytest -p no:cacheprovider
Set-Location frontend
npm test
npm run build
Set-Location ..
python -B scripts/check_public.py
```

前后端依赖由 `requirements.lock` 与 `frontend/package-lock.json` 固定。
修改后运行相应测试与构建；提交前使用 `check_public.py` 检查 Git 暂存区中的配置、凭证和本机路径。
部署步骤见 [部署说明](docs/deployment.md)，取消与重试契约见 [并发说明](CONCURRENCY.md)。

离线 UI 集成测试仅使用虚构账号：设置 `MFA_MODE=demo`, `MFA_LOCAL_DEV=1`,
`MFA_ORIGIN=http://127.0.0.1:8790`, `MFA_ACCESS_KEY=<local-test-key>`，启动一个
uvicorn worker。demo 生成测试密钥，不访问上游。

## 部署与上线门槛

使用 Compose，KPanel 管理可信 HTTPS 反代。IP+HTTP 只允许禁用提交的预览。
未完成域名、系统时间、目标网络、独立协议轮换授权灰度前，不将模式改为 live。
无浏览器绕过/代理自动切换；遇邮件 OTP 或安全挑战停止。

`MFA_MODE=live` 还要求 `MFA_ORIGIN=https://实际域名` 及随机访问口令。
单 API 进程、全站合计最多 30 并发（`MFA_GLOBAL_MAX_CONCURRENT` 可设 1–30，代码硬上限 30），每个访问会话最多 10（`MFA_MAX_CONCURRENT` 可设 1–10）。
全局名额同时约束所有会话、直接 API 调用和重试；达到任一上限时返回 busy，页面保留任务排队等待。
页面先用不含凭证的请求申请名额，拿到有效名额后才提交一条账号任务；同一页面的名额轮询串行，避免十个等待任务分别刷接口。
服务端按 FIFO 会话顺序分配空位，一次给每个等待会话一个名额；会话后续申请回到队尾，已达会话上限的暂时跳过。
等待队列最多 100 个会话，每会话仅保留一条 ID/过期时间，不保存待执行账号、密码或 2FA；停止轮询 15 秒后清除。
预留名额 10 秒过期，预留与实际任务合计不能超过 30；等待不创建任务子进程。页面等待最长 10 分钟，可单独取消。
只有任务子进程完成清理后才释放名额。每任务独立子进程，任务只在内存中。禁止多个 API worker 或部署多个独立副本，因为内存配额与队列不共享。
内存结果 TTL 15 分钟；部署必须排空任务。后台故障不能恢复已移除旧因子。
新密钥激活前浏览器 AES-GCM/IndexedDB 保存与读回，ACK 后才激活。
同源脚本可访问本机结果，浏览器加密不是对宿主站点的零信任保护。

## 范围与限制

公开版本以已部署运行代码为基线；发布时对协议模块与站点图标进行哈希核对。
单账号真实轮换曾在授权环境验证；模拟批量测试不能证明真实账号的并发成功率。
认证接口、网络出口与上游验证要求可能变化，部署成功不等于账号操作必然成功。

协议核心使用固定源文件快照；`vendor/SOURCE.json` 记录来源及本地修改的文件哈希。
当前快照禁用注册、发码、OAuth token exchange、原始 HTTP dump。
不复制 .env、数据库、日志、HAR 或真实凭证。
服务不连接外部项目账号库。组件来源与许可见 [第三方说明](THIRD_PARTY_NOTICES.md)。
服务端执行期间仍接触明文凭证，不宣称服务器无法看到；未验证宿主机/云平台快照行为。
Docker 不持久化任务、只读根文件系统、tmpfs、无 swap 配额、无 core dump、无容器日志。
`memswap_limit=mem_limit` 必须在目标 cgroup 下核对生效。

## 接口

- GET /api/capabilities
- POST /api/session (访问口令；与账号密码不同)
- POST /api/job-slots (空对象申请/轮询本会话的公平执行名额，不接收账号凭证)
- DELETE /api/job-slots/{token} (仅释放所属会话尚未使用的预留名额)
- POST /api/jobs (单条凭证、operation_id、authorized/storage_ready)
- GET /api/jobs/{id}/events (所属会话 SSE)
- POST /api/job-events (合并轮询多任务事件与游标)
- GET /api/operations/{operation_id} (提交响应丢失时查原任务，不重新提交)
- GET/PUT/DELETE /api/proxy-pool (当前会话的脱敏状态、提交、独立清空)
- POST /api/proxy-pool/test (显式手动抽测当前输入，返回国家代码/IP/请求延迟或脱敏失败原因)
- POST /api/jobs/{id}/retry (校验原任务阶段后重试，凭证仅经请求体传入)
- POST /api/jobs/{id}/receipt (特定密钥交付 ACK)
- POST /api/jobs/{id}/cancel (变更前停止，变更后先交付/核对)
- DELETE /api/jobs/{id} (只允许结束任务)

批量在页面排队并发执行，超过上限等待；每个任务可独立取消，失败不会停止其他任务。
结果区分全部、进行中、队列中、成功、失败、取消；失败重试按状态选择“更换前重试”或“仅验证新密钥”。
失败页的“重试失败”将所有可重试失败任务加入当前等待队列；首次执行与重试共用 FIFO 和并发名额。
状态未知/变更中断的任务保留核对路径。任务栏仅在全部/成功页提供成功 TXT 导出。
移除/激活状态不明时不重放变更。已越过移除边界的取消会先保存并启用新密钥，再停止后续验证。
前端使用合并短轮询，避免十条 SSE 在 HTTP/1 连接限制下挤占密钥 ACK 和取消请求；旧 SSE 接口保留。
重试所需密码和旧密钥仅当前页面内存保留，成功/取消或新批次开始时清除重试凭证；新密钥交付后旧密钥不再保留。成功 TXT 所需密码仍仅在当前页面内存。
刷新后重试验证需重新粘贴该账号凭证（仅取密码，实际验证使用保存的新密钥），不重新更换。
每任务独立 Cookie、设备 ID、CSRF/OAuth 和指纹上下文；相同浏览器型号/UA 可以相同，不代表共用会话。
资源测量与上线注意事项见 `CONCURRENCY.md`。
若本机已有新密钥但后台任务丢失，先核对账户，不要用旧凭证自动重做。

代理模式任务提交附带 `network_mode=pool` 和当前 `proxy_pool_version`，不附代理密码。
本地可选 `network_mode=direct`；生产接口拒绝直连。粘贴和刷新仅操作本地存储，任务开始前才上传当前代理池到自己的服务会话，
不在粘贴时发起代理或认证请求。池版本变化时明确报错，不能自动沿用其他页面更新后的路由。
