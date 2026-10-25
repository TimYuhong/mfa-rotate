"""最小化 Config（仅 browser_register.py 用到的字段）。

剥离自原 CTF-reg/config.py，去掉 card / billing / stripe / captcha 等支付相关字段，
仅保留注册阶段必需的 proxy 字段。
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass
class Config:
    """ChatGPT 注册最小配置。"""
    # 出口代理 URL，例：socks5://user:pass@host:port  或  socks5://127.0.0.1:18899
    # 留 None 走系统直连
    proxy: Optional[str] = None
    # 前置代理：先连接该代理，再连接 proxy。用于 Clash -> 代理商原始代理。
    pre_proxy: Optional[str] = None
    # App-validated proxy DNS mappings, frozen for the complete task.
    proxy_resolve: tuple[str, ...] = ()
