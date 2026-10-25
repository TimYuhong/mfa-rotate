# 来源与许可

这是应用源码仓库，不是 UI 组件再分发包。各目录的原有许可与来源说明均保留。

| 内容 | 来源及许可记录 |
|---|---|
| shadcn/ui 基础组件 | `frontend/src/components/ui/SOURCES.json` 与同目录 `LICENSE`；MIT |
| Radix UI | 使用 npm 锁定包；按对应包的许可使用 |
| Lucide React / 钥匙标识 | `lucide-react` v0.511.0；ISC，SVG 中保留声明 |
| DialogGlass 的折射实现 | React Bits 的 GlassSurface，固定提交及定制见 `frontend/src/components/GLASS-SOURCE.json`；许可原文位于 `frontend/public/assets/licenses/react-bits.txt` |
| 协议模块快照 | `vendor/SOURCE.json` 记录源文件与修改后的 SHA-256；不包含原项目账号库、配置或运行数据 |

React Bits 保留其 MIT + Commons Clause 条款，不应将本应用中的适配实现作为独立组件包重新发布。
本仓库没有为整套源码新增统一许可证，也不替第三方或协议快照声明未提供的授权。
公开可读不等于所有内容都获得同一种再许可；依赖的各自许可证继续适用。
