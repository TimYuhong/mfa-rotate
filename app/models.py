import base64
import re
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator


class Credentials(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: str = Field(min_length=3, max_length=254)
    password: SecretStr = Field(min_length=1, max_length=512)
    totp_secret: SecretStr = Field(min_length=16, max_length=128)
    operation_id: str = Field(pattern=r"^[A-Za-z0-9_-]{16,80}$")
    storage_ready: Literal[True]
    authorized: Literal[True]
    action: Literal["rotate", "verify"] = "rotate"
    factor_id: str = Field(default="", max_length=128)
    initial_state: Literal["activation_unknown", "enabled_unverified"] = "activation_unknown"
    network_mode: Literal["direct", "pool"] | None = None
    proxy_pool_version: str = Field(default="", max_length=80)

    @field_validator("email")
    @classmethod
    def email_valid(cls, value):
        value = value.strip()
        if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", value):
            raise ValueError("invalid_email")
        return value

    @field_validator("totp_secret")
    @classmethod
    def secret_valid(cls, value):
        text = value.get_secret_value().replace(" ", "").upper().rstrip("=")
        if not re.fullmatch(r"[A-Z2-7]{16,104}", text):
            raise ValueError("invalid_totp_secret")
        try:
            decoded = base64.b32decode(text + "=" * (-len(text) % 8))
        except Exception:
            raise ValueError("invalid_totp_secret") from None
        if not 10 <= len(decoded) <= 64:
            raise ValueError("invalid_totp_secret")
        return SecretStr(text)


class Login(BaseModel):
    model_config = ConfigDict(extra="forbid")
    access_key: SecretStr = Field(max_length=256)


class ProxyPoolInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    proxies: list[SecretStr] = Field(min_length=1, max_length=50)


class Receipt(BaseModel):
    model_config = ConfigDict(extra="forbid")
    receipt: str = Field(min_length=20, max_length=128)


class EventPoll(BaseModel):
    model_config = ConfigDict(extra="forbid")
    cursors: dict[str, int] = Field(min_length=1, max_length=50)

    @field_validator("cursors")
    @classmethod
    def valid_cursors(cls, value):
        if any(not 1 <= len(key) <= 80 or cursor < 0 for key, cursor in value.items()):
            raise ValueError("invalid_cursor")
        return value


MESSAGES = {
    "proxy_invalid": "代理格式不正确，请检查对应行。",
    "proxy_address_blocked": "代理地址不允许，请使用公网代理。",
    "proxy_required": "请先填写代理池。",
    "proxy_dns_failed": "代理域名无法解析，请检查代理地址。",
    "proxy_pool_changed": "代理池已更新，请刷新代理状态后重试。",
    "proxy_pool_busy": "请先结束任务，再修改代理池。",
    "proxy_test_busy": "代理测试正在进行，请稍后再试。",
    "direct_forbidden": "本站必须使用代理，请先配置代理池。",
    "disabled": "服务尚未开放真实轮换，请勿提交真实账号。",
    "login_failed": "登录失败，请检查密码及当前 TOTP 密钥。",
    "auth_entry_failed": "认证入口访问失败，请检查当前网络出口；尚未验证密码和 TOTP。",
    "email_required": "服务端要求邮箱验证码，本任务已停止，未主动发码。",
    "challenge_required": "上游需要人工安全验证，本任务已停止。",
    "rate_limited": "上游限流，请稍后核对状态，不要重复提交。",
    "factor_ambiguous": "未找到唯一的 TOTP 因子，未进行移除。",
    "identity_mismatch": "登录账号身份不匹配，任务已停止。",
    "upstream_error": "上游接口返回异常，请根据当前阶段处理。",
    "network_error": "网络连接失败或超时，请检查当前出口；若已开始更换，请先核对状态。",
    "cancelled": "已在变更前安全停止。",
    "receipt_timeout": "浏览器未确认保存新密钥，未继续激活。",
    "deadline": "任务超时，若已开始变更请先核对账户状态。",
    "worker_failed": "工作进程异常退出，请按最后已确认阶段处理。",
    "verified": "新密钥已启用，并通过独立登录验证。",
    "busy": "当前执行名额已满，请稍后提交。",
    "account_busy": "此账号已有任务正在执行，请先等待其完成。",
    "unsafe_retry": "密钥可能已经变更，不能重新执行更换；请核对或仅验证新密钥。",
    "verification_cancelled": "已取消后续验证；请保留新密钥，不要用旧密钥再次更换。",
}
