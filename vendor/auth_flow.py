"""
注册/登录流程 - 协议直连方式
完整链路:
  chatgpt_csrf -> chatgpt_signin_openai -> auth_oauth_init -> sentinel
  -> signup -> send_otp -> verify_otp -> create_account
  -> redirect_chain -> auth_session -> (optional) oauth_token_exchange
"""
import json
import base64
import copy
import hashlib
import hmac
import logging
import os
import random
import re
import secrets
import struct
import subprocess
import time
import uuid
from datetime import datetime
from typing import Optional, Any
from urllib.parse import urlparse, parse_qs, parse_qsl, urljoin, urlencode, urlunparse
from config import Config
from fingerprint import generate_fingerprint
from mail_providers import MailProvider
from http_client import create_http_session, USER_AGENT
from registration_context import RegistrationContext
from session_cookie import session_token_from_cookie_pairs
from protocol_session import RegistrationSessionError, establish_registration_session, response_evidence
logger = logging.getLogger(__name__)

def _signal_feature_enabled(name: str) -> bool:
    """信号层特性开关（默认关闭；任何异常视为关闭）。"""
    try:
        from signal_runtime import config as _cfg
        return bool(_cfg.feature_enabled(name))
    except Exception:
        return False

def _hotp(secret_b32: str, counter: int, digits: int=6) -> str:
    """HOTP 算法（RFC 4226）"""
    key = base64.b32decode(secret_b32 + '=' * (-len(secret_b32) % 8))
    msg = struct.pack('>Q', counter)
    h = hmac.new(key, msg, hashlib.sha1).digest()
    o = h[-1] & 15
    code = (struct.unpack('>I', h[o:o + 4])[0] & 2147483647) % 10 ** digits
    return str(code).zfill(digits)

def _totp_now(secret_b32: str) -> str:
    """当前 30 秒窗口的 6 位 TOTP 码"""
    return _hotp(secret_b32, int(time.time()) // 30)

class AuthResult:
    """认证结果"""

    def __init__(self):
        self.email: str = ''
        self.password: str = ''
        self.session_token: str = ''
        self.access_token: str = ''
        self.device_id: str = ''
        self.csrf_token: str = ''
        self.id_token: str = ''
        self.refresh_token: str = ''
        self.cookie_header: str = ''
        self.totp_secret: str = ''
        self.session_json: str = ''
        self.storage_state_json: str = ''
        self.auth_flow: str = ''
        self.registration_context: dict[str, Any] = {}
        self.fingerprint_hash: str = ''
        self.registration_route: str = 'unknown'
        self.password_registration_state: str = 'not_attempted'

    def is_valid(self) -> bool:
        return bool(self.session_token and self.access_token)

    def to_dict(self) -> dict:
        return {'email': self.email, 'password': self.password, 'session_token': self.session_token, 'access_token': self.access_token, 'device_id': self.device_id, 'csrf_token': self.csrf_token, 'id_token': self.id_token, 'refresh_token': self.refresh_token, 'cookie_header': self.cookie_header, 'totp_secret': self.totp_secret, 'session_json': self.session_json, 'storage_state_json': self.storage_state_json, 'auth_flow': self.auth_flow, 'registration_context': self.registration_context, 'fingerprint_hash': self.fingerprint_hash, 'registration_route': self.registration_route, 'password_registration_state': self.password_registration_state}

class AuthFlow:
    """注册/登录协议流"""

    def __init__(self, config: Config, sms_callback: Optional[Any]=None, env_overrides: Optional[dict]=None, on_password: Optional[Any]=None, on_session_ready: Optional[Any]=None, account_callback: Optional[Any]=None, registration_context: Optional[Any]=None, context_reason: str=''):
        self._env_overrides = dict(env_overrides or {})
        self.config = config
        self._country_code = ''
        if isinstance(registration_context, RegistrationContext):
            base_context = registration_context
        elif isinstance(registration_context, dict):
            base_context = RegistrationContext.from_snapshot(registration_context)
        elif registration_context is None:
            base_context = RegistrationContext.create()
        else:
            raise ValueError('registration_context_invalid')
        self._registration_context = base_context.fork(reason=context_reason, route_type=context_reason) if str(context_reason or '').strip() else base_context
        self._country_code = self._registration_context.country_code
        self._fingerprint = self._registration_context.fingerprint
        self._ua = self._fingerprint['user_agent']
        self._impersonate_candidates = self._fingerprint.get('fallback_impersonates', [self._fingerprint['impersonate'], 'safari17_0', 'safari15_5'])
        self._impersonate_idx = 0
        self._tls_attempted_targets = {self._fingerprint['impersonate']}
        self.result = AuthResult()
        self.result.device_id = self._registration_context.device_id
        self.session = create_http_session(proxy=config.proxy, pre_proxy=getattr(config, 'pre_proxy', None), impersonate=self._impersonate_candidates[self._impersonate_idx], user_agent=self._ua, proxy_resolve=getattr(config, 'proxy_resolve', ()))
        self._arm_signal_layer()
        self._capture_context_cookies('session_created')
        self._sync_context_result()
        self.cookie_refresh_validation: dict[str, Any] = {}
        self._sms_callback = sms_callback
        self._on_password = on_password
        self._on_session_ready = on_session_ready
        self._account_callback = account_callback
        self._http_trace_enabled = False
        self._is_existing_account = False
        self._existing_email_verification_mode = ''
        self._existing_page_type = ''
        self._manual_login_verifier = (os.getenv('LOGIN_VERIFIER', '') or '').strip()
        self._captured_login_verifier = ''
        self._oauth_client_secret = (os.getenv('OAUTH_CLIENT_SECRET', '') or '').strip()
        self._oauth_client_id = 'YOUR_OPENAI_WEB_CLIENT_ID'
        self._oauth_redirect_uri = 'https://chatgpt.com/api/auth/callback/openai'
        self._oauth_scope = ''
        self._oauth_state = ''
        self._oauth_auth_url = ''
        self._client_auth_session_dump: dict[str, Any] = {}
        self._client_auth_session_id: str = ''
        self._dump_login_verifier: str = ''
        self._codex_rt_attempted: bool = False
        self._last_sentinel_token = ''
        self._last_sentinel_so_token = ''
        self._last_sentinel_request_so_token = ''
        self._sentinel_contexts: dict[str, dict[str, str]] = {}
        self._sentinel_token_records: dict[tuple[str, str], dict[str, str]] = {}
        self._sentinel_request_ps: dict[str, str] = {}
        self._csrf_token_cache = ''
        self._csrf_cache_context_id = ''
        self._auth_url_cache_key: tuple[str, str, str] | None = None
        self._auth_url_cache = ''
        self._auth_init_cache_key: tuple[str, str] | None = None
        self._auth_init_device_id = ''
        self._authorize_continue_cache: dict[tuple[str, str, str, str], dict] = {}
        self._registration_callback_attempts: set[str] = set()
        self.registration_session_evidence: dict[str, Any] = {}
        self._trace_dump_enabled = False
        self._trace_include_cookie = False
        self._trace_dump_path = ''
        logger.debug(f'指纹: impersonate={self._fingerprint['impersonate']} screen={self._fingerprint['screen']} lang={self._fingerprint['lang']} ua={self._ua}')

    def _ensure_registration_context(self) -> RegistrationContext:
        """Lazily adapt legacy/test-created AuthFlow instances."""
        context = getattr(self, '_registration_context', None)
        if isinstance(context, RegistrationContext):
            return context
        fp = getattr(self, '_fingerprint', None)
        if not isinstance(fp, dict) or not fp:
            fp = generate_fingerprint(country_code=getattr(self, '_country_code', ''))
        device_id = str(getattr(getattr(self, 'result', None), 'device_id', '') or '')
        context = RegistrationContext(fingerprint=fp, country_code=str(getattr(self, '_country_code', '') or ''), context_reason='legacy_context_adaptation', device_id=device_id or str(uuid.uuid4()))
        self._registration_context = context
        self._fingerprint = context.fingerprint
        self._ua = str(getattr(self, '_ua', '') or context.user_agent)
        return context

    def _sync_context_result(self) -> None:
        """Expose the canonical context through AuthResult for persistence."""
        context = self._ensure_registration_context()
        result = getattr(self, 'result', None)
        if context is None or result is None:
            return
        snapshot = context.snapshot()
        result.device_id = context.device_id
        result.registration_context = snapshot
        result.fingerprint_hash = str(snapshot.get('fingerprint_hash') or '')
        result.registration_route = context.route_type

    @staticmethod
    def _sentinel_context_name(flow: str) -> str:
        """Map a Sentinel flow to the browser context that owns its SID."""
        return 'password' if str(flow or '').strip() == 'username_password_create' else 'top_level'

    def _sentinel_context_state(self, context_name: str) -> dict[str, str]:
        """Return one stable Sentinel context state for this registration attempt."""
        name = str(context_name or 'top_level').strip().lower() or 'top_level'
        if name not in {'top_level', 'password'}:
            name = 'top_level'
        contexts = getattr(self, '_sentinel_contexts', None)
        if not isinstance(contexts, dict):
            contexts = {}
            self._sentinel_contexts = contexts
        state = contexts.get(name)
        if isinstance(state, dict) and str(state.get('sid') or '').strip():
            return state
        context = self._ensure_registration_context()
        sid = str(uuid.uuid5(uuid.NAMESPACE_URL, f'openai-register:{context.context_id}:sentinel:{name}'))
        state = {'name': name, 'sid': sid, 'context_id': context.context_id}
        contexts[name] = state
        return state

    def _clear_authorization_caches(self) -> None:
        """Invalidate only transaction-scoped OAuth request caches."""
        self._csrf_token_cache = ''
        self._csrf_cache_context_id = ''
        self._auth_url_cache_key = None
        self._auth_url_cache = ''
        self._auth_init_cache_key = None
        self._auth_init_device_id = ''
        self._authorize_continue_cache = {}
        self._registration_callback_attempts = set()
        self.registration_session_evidence = {}

    def _clear_sentinel_state(self) -> None:
        """Drop token/p caches when the whole OAuth transaction is rebuilt."""
        self._sentinel_contexts = {}
        self._sentinel_token_records = {}
        self._sentinel_request_ps = {}
        self._last_sentinel_token = ''
        self._last_sentinel_so_token = ''
        self._last_sentinel_request_so_token = ''

    def _remember_sentinel_record(self, *, context_name: str, flow: str, token: str, so_token: str, request_p: str='') -> None:
        record = {'context': str(context_name or 'top_level'), 'flow': str(flow or ''), 'token': str(token or ''), 'so_token': str(so_token or ''), 'request_p': str(request_p or ''), 'sid': str(self._sentinel_context_state(context_name).get('sid') or '')}
        records = getattr(self, '_sentinel_token_records', None)
        if not isinstance(records, dict):
            records = {}
            self._sentinel_token_records = records
        records[record['context'], record['flow']] = record
        try:
            from signal_runtime.request_headers import remember_sentinel_result
            remember_sentinel_result(self.session, main_token=record['token'], so_token=record['so_token'], flow=record['flow'])
        except Exception:
            pass

    def _sentinel_record_for(self, flow: str, *, context_name: str='', token: str='') -> dict[str, str] | None:
        name = str(context_name or self._sentinel_context_name(flow)).strip().lower()
        records = getattr(self, '_sentinel_token_records', None)
        record = records.get((name, str(flow or ''))) if isinstance(records, dict) else None
        if not isinstance(record, dict):
            return None
        if token and str(record.get('token') or '') != str(token):
            return None
        return record

    def _apply_sentinel_headers(self, headers: dict, *, flow: str, context_name: str='', token: str='', allow_legacy_token: bool=False) -> dict:
        """Attach only the token/SO pair generated for the requested flow."""
        record = self._sentinel_record_for(flow, context_name=context_name, token=token)
        effective_token = str(token or (record or {}).get('token') or '')
        if not effective_token:
            return headers
        headers['openai-sentinel-token'] = effective_token
        if record is not None:
            so_token = str(record.get('so_token') or '')
            if so_token:
                headers['openai-sentinel-so-token'] = so_token
        elif allow_legacy_token and effective_token == str(getattr(self, '_last_sentinel_token', '') or ''):
            so_token = str(getattr(self, '_last_sentinel_so_token', '') or '')
            if so_token:
                headers['openai-sentinel-so-token'] = so_token
        return headers

    def _capture_context_cookies(self, phase: str) -> None:
        try:
            self._ensure_registration_context().capture_cookies(self.session, phase)
            self._sync_context_result()
        except Exception:
            logger.debug('注册上下文 Cookie 摘要失败（忽略）', exc_info=True)

    def _record_sdk_evidence(self, evidence: dict[str, Any]) -> None:
        try:
            self._ensure_registration_context().record_sdk_execution(evidence)
            self._sync_context_result()
        except Exception:
            logger.debug('Sentinel SDK 执行证据记录失败（忽略）', exc_info=True)

    def _replace_registration_context(self, context: RegistrationContext, *, preserve_email: str='', preserve_password: str='', preserve_totp_secret: str='') -> None:
        """Atomically replace transport, browser fields, IDs, and live session."""
        old_session = getattr(self, 'session', None)
        self._registration_context = context
        self._country_code = context.country_code
        self._fingerprint = context.fingerprint
        self._ua = context.user_agent
        self._impersonate_candidates = self._fingerprint.get('fallback_impersonates', [context.tls_target])
        if context.tls_target in self._impersonate_candidates:
            self._impersonate_idx = self._impersonate_candidates.index(context.tls_target)
        else:
            self._impersonate_candidates.insert(0, context.tls_target)
            self._impersonate_idx = 0
        self.session = create_http_session(proxy=self.config.proxy, pre_proxy=getattr(self.config, 'pre_proxy', None), impersonate=context.tls_target, user_agent=context.user_agent, proxy_resolve=getattr(self.config, 'proxy_resolve', ()))
        self.result = AuthResult()
        self.result.email = str(preserve_email or '')
        self.result.password = str(preserve_password or '')
        self.result.totp_secret = str(preserve_totp_secret or '')
        self.result.device_id = context.device_id
        self._arm_signal_layer()
        self._capture_context_cookies('context_rebuilt')
        self._clear_authorization_caches()
        self._clear_sentinel_state()
        close = getattr(old_session, 'close', None)
        if callable(close):
            try:
                close()
            except Exception:
                pass

    def registration_context_snapshot(self) -> dict[str, Any]:
        self._sync_context_result()
        return dict(self.result.registration_context)

    def _build_chatgpt_cookie_header(self) -> str:
        """
        导出当前会话中的 chatgpt.com 相关 cookie。

        说明：
        - `/backend-api/payments/checkout` 的 modern/custom 入口不仅依赖
          `__Secure-next-auth.session-token`，还会校验若干同域 cookie
          （如 csrf / oai-sc / Cloudflare 相关 cookie 等）。
        - 因此这里不能只回传 session_token，需要尽量保留当前会话里已经拿到的
          `chatgpt.com` 域 cookie 集合。
        """
        cookie_pairs: list[tuple[str, str]] = []
        seen: set[str] = set()
        try:
            jar_iter = list(getattr(self.session.cookies, 'jar', self.session.cookies))
        except Exception:
            jar_iter = []
        for cookie in jar_iter:
            try:
                name = (getattr(cookie, 'name', '') or '').strip()
                value = getattr(cookie, 'value', '') or ''
                domain = (getattr(cookie, 'domain', '') or '').strip().lower()
            except Exception:
                continue
            if not name or not value:
                continue
            if domain and 'chatgpt.com' not in domain:
                continue
            if name in seen:
                continue
            seen.add(name)
            cookie_pairs.append((name, value))
        critical_names = ['__Secure-next-auth.session-token', '__Host-next-auth.csrf-token', '__Secure-next-auth.callback-url', 'oai-did', 'oai-sc', 'cf_clearance', '__cf_bm', '_cfuvid', '__cflb', '__stripe_mid', '__stripe_sid', 'oai-client-auth-info', 'oai-gn', 'oai-nav-state', 'oai-hlib', '_account_is_fedramp', 'oai_consent_analytics', 'oai_consent_marketing', 'oai-allow-ne', '_ga', '_ga_9SHBSK2D9J', '_gcl_au', '_fbp', '_puid', '_dd_s', 'g_state']
        for name in critical_names:
            if name in seen:
                continue
            try:
                value = self.session.cookies.get(name, '')
            except Exception:
                value = ''
            if value:
                seen.add(name)
                cookie_pairs.append((name, value))
        return '; '.join((f'{name}={value}' for name, value in cookie_pairs if name and value))
        if self._trace_dump_enabled:
            try:
                os.makedirs('outputs', exist_ok=True)
                ts = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
                self._trace_dump_path = os.path.join('outputs', f'auth_trace_{ts}_{os.getpid()}.jsonl')
                logger.info(f'HTTP 明文抓包已启用: {self._trace_dump_path}')
            except Exception as e:
                logger.warning(f'初始化 HTTP 抓包文件失败: {e}')
                self._trace_dump_enabled = False

    def export_storage_state(self) -> dict:
        """把协议会话 Cookie 导出为 Playwright 兼容的 storage_state 结构。"""
        cookies: list[dict[str, Any]] = []
        try:
            jar_iter = list(getattr(self.session.cookies, 'jar', self.session.cookies))
        except Exception:
            jar_iter = []
        for cookie in jar_iter:
            try:
                name = str(getattr(cookie, 'name', '') or '').strip()
                value = str(getattr(cookie, 'value', '') or '')
                if not name:
                    continue
                domain = str(getattr(cookie, 'domain', '') or '')
                path = str(getattr(cookie, 'path', '/') or '/')
                expires = getattr(cookie, 'expires', None)
                rest = getattr(cookie, '_rest', {}) or {}
                item: dict[str, Any] = {'name': name, 'value': value, 'domain': domain, 'path': path, 'expires': float(expires) if expires is not None else -1, 'httpOnly': 'HttpOnly' in rest or 'httponly' in rest, 'secure': bool(getattr(cookie, 'secure', False))}
                same_site = str(rest.get('SameSite') or rest.get('samesite') or '').strip().capitalize()
                if same_site in {'Strict', 'Lax', 'None'}:
                    item['sameSite'] = same_site
                cookies.append(item)
            except Exception:
                continue
        return {'cookies': cookies, 'origins': []}

    def import_storage_state(self, storage_state: dict | str) -> int:
        """导入保存的 Cookie 登录态，返回成功写入 Cookie Jar 的数量。"""
        state: Any = storage_state
        if isinstance(state, str):
            text = state.strip()
            if not text:
                return 0
            try:
                state = json.loads(text)
            except json.JSONDecodeError:
                return self.import_cookie_header(text)
        if isinstance(state, list):
            state = {'cookies': state, 'origins': []}
        if not isinstance(state, dict):
            return 0
        cookies = state.get('cookies') or []
        if not isinstance(cookies, list):
            return 0
        try:
            self.session.cookies.clear()
        except Exception:
            pass
        imported = 0
        for cookie in cookies:
            if not isinstance(cookie, dict):
                continue
            name = str(cookie.get('name') or '').strip()
            value = str(cookie.get('value') or '')
            if not name:
                continue
            domain = str(cookie.get('domain') or '.chatgpt.com').strip()
            path = str(cookie.get('path') or '/').strip() or '/'
            secure = bool(cookie.get('secure', domain.endswith('chatgpt.com')))
            try:
                self.session.cookies.set(name, value, domain=domain, path=path, secure=secure)
                imported += 1
            except Exception:
                continue
        return imported

    def import_cookie_header(self, cookie_header: str) -> int:
        """兼容旧数据库：把 ``name=value; ...`` Cookie Header 导入会话。"""
        imported = 0
        try:
            self.session.cookies.clear()
        except Exception:
            pass
        for part in str(cookie_header or '').split(';'):
            item = part.strip()
            if not item or '=' not in item:
                continue
            name, value = item.split('=', 1)
            name = name.strip()
            if not name:
                continue
            try:
                self.session.cookies.set(name, value.strip(), domain='.chatgpt.com', path='/', secure=True)
                imported += 1
            except Exception:
                continue
        return imported

    @staticmethod
    def _decode_access_token_payload(access_token: str) -> dict:
        parts = str(access_token or '').split('.')
        if len(parts) != 3:
            return {}
        try:
            data = parts[1] + '=' * (-len(parts[1]) % 4)
            payload = json.loads(base64.urlsafe_b64decode(data.encode('ascii')).decode('utf-8'))
            return payload if isinstance(payload, dict) else {}
        except Exception:
            return {}

    @staticmethod
    def _collect_token_claims(value: Any, accepted_keys: set[str]) -> list[str]:
        found: list[str] = []

        def walk(item: Any) -> None:
            if isinstance(item, dict):
                for key, nested in item.items():
                    normalized = re.sub('[^a-z0-9]', '', str(key).lower())
                    if normalized in accepted_keys and nested is not None:
                        text = str(nested).strip()
                        if text and text not in found:
                            found.append(text)
                    if isinstance(nested, (dict, list)):
                        walk(nested)
            elif isinstance(item, list):
                for nested in item:
                    walk(nested)
        walk(value)
        return found

    def _validate_cookie_refresh_access_token(self, access_token: str, *, expected_email: str='', previous_access_token: str='') -> dict:
        payload = self._decode_access_token_payload(access_token)
        if not payload:
            raise RuntimeError('Cookie 强制刷新返回的 AT 格式无效')
        try:
            expires_at = int(payload.get('exp'))
        except (TypeError, ValueError):
            raise RuntimeError('Cookie 强制刷新返回的 AT 缺少有效过期时间')
        if expires_at <= int(time.time()):
            raise RuntimeError('Cookie 强制刷新返回的 AT 已过期')
        token_emails = self._collect_token_claims(payload, {'email', 'useremail', 'upn', 'preferredusername'})
        if not token_emails:
            raise RuntimeError('Cookie 强制刷新返回的 AT 缺少邮箱标识')
        expected = str(expected_email or '').strip().lower()
        normalized_emails = {email.lower() for email in token_emails}
        if expected and expected not in normalized_emails:
            raise RuntimeError('Cookie 强制刷新返回的 AT 与当前账号邮箱不一致')
        identity_keys = {'accountid', 'chatgptaccountid', 'workspaceid', 'organizationid', 'orgid'}
        identities = self._collect_token_claims(payload, identity_keys)
        if not identities:
            raise RuntimeError('Cookie 强制刷新返回的 AT 缺少账号或工作区标识')
        previous_payload = self._decode_access_token_payload(previous_access_token)
        previous_identities = self._collect_token_claims(previous_payload, identity_keys)
        if previous_identities and set(previous_identities).isdisjoint(identities):
            raise RuntimeError('Cookie 强制刷新返回的 AT 账号或工作区不一致')
        try:
            session_data = json.loads(self.result.session_json or '{}')
        except Exception:
            session_data = {}
        session_user = session_data.get('user') if isinstance(session_data, dict) else None
        session_email = ''
        if isinstance(session_user, dict):
            session_email = str(session_user.get('email') or '').strip().lower()
        if expected and session_email and (session_email != expected):
            raise RuntimeError('Cookie 强制刷新返回的 Session 与当前账号邮箱不一致')
        session_expires = session_data.get('expires') if isinstance(session_data, dict) else None
        if session_expires:
            try:
                session_expires_at = int(datetime.fromisoformat(str(session_expires).replace('Z', '+00:00')).timestamp())
            except (TypeError, ValueError):
                raise RuntimeError('Cookie 强制刷新返回的 Session 过期时间无效')
            if session_expires_at <= int(time.time()):
                raise RuntimeError('Cookie 强制刷新返回的 Session 已过期')
        return {'email': expected or token_emails[0], 'account_id': identities[0], 'expires_at': expires_at}

    def refresh_from_storage_state(self, storage_state: dict | str, *, expected_email: str='', previous_access_token: str='') -> AuthResult:
        """导入 Cookie，普通 Session 预热后强制刷新并校验新的 AT。"""
        context = self._ensure_registration_context()
        if context.context_reason == 'registration':
            context.context_reason = 'cookie_refresh_new_context'
        context.set_route('cookie_refresh')
        self._sync_context_result()
        imported = self.import_storage_state(storage_state)
        if imported <= 0:
            raise RuntimeError('当前账号没有可复用的 Cookie 登录态')
        self.result.auth_flow = 'cookie_refresh'
        self.cookie_refresh_validation = {}
        self.get_auth_session()
        session_token, access_token = self.get_auth_session(refresh=True)
        if not access_token:
            raise RuntimeError('Cookie 登录态已过期，强制刷新未返回新的 accessToken')
        self.cookie_refresh_validation = self._validate_cookie_refresh_access_token(access_token, expected_email=expected_email, previous_access_token=previous_access_token)
        if not session_token:
            logger.warning('Cookie 刷新已取得 access_token，但未发现 session_token')
        try:
            session_data = json.loads(self.result.session_json or '{}')
            user = session_data.get('user') if isinstance(session_data, dict) else None
            if isinstance(user, dict):
                self.result.email = str(user.get('email') or '')
        except Exception:
            pass
        self._capture_context_cookies('cookie_refresh_complete')
        self._sync_context_result()
        return self.result

    def _arm_signal_layer(self) -> None:
        """Attach the canonical context; protocol telemetry remains request-only."""
        try:
            from signal_runtime import bridge as signal_bridge
            try:
                setattr(self.session, '_signal_auth_context_headers', self._env_flag('OPENAI_SIGNAL_AUTH_CONTEXT_HEADERS', '0'))
            except Exception:
                pass
            signal_bridge.arm(self.session, proxy=str(getattr(self.config, 'proxy', '') or ''), user_agent=str(getattr(self, '_ua', '') or ''), registration_context=getattr(self, '_registration_context', None))
            if signal_bridge.enabled():
                signal_bridge.attach(self.session, did=str(getattr(self._registration_context, 'device_id', '') or ''), registration_context=getattr(self, '_registration_context', None))
        except Exception:
            logger.debug('信号层挂载失败（忽略）', exc_info=True)

    def _signal_page_get(self, url: str) -> None:
        """Protocol mode never pretends an HTML fetch executed browser JS/DOM."""
        if _signal_feature_enabled('PAGE_REPLAY'):
            logger.info('[signal] 已跳过协议页面回放（无真实浏览器 JS/DOM）: %s', url)

    def _signal_fresh_sentinel(self, flow: str='authorize_continue') -> bool:
        """信号层：为当前步骤取一枚新 Sentinel（失败沿用旧值，fail-soft）。

        返回 True 表示已成功刷新并写入 `_last_sentinel_token` /
        `_last_sentinel_so_token`（调用方可据此决定是否对请求附加该步 token）。
        """
        if not _signal_feature_enabled('FRESH_SENTINEL'):
            return False
        try:
            device_id = str(getattr(self.result, 'device_id', '') or '').strip()
            if not device_id:
                device_id = str(self.session.cookies.get('oai-did') or '').strip()
            if not device_id:
                return False
            token = self.get_sentinel_token(device_id, flow=flow)
            if token:
                self._last_sentinel_token = token
                return True
            return False
        except Exception:
            logger.debug('信号层新 Sentinel 获取失败（忽略）', exc_info=True)
            return False

    def _trace_http(self, step: str, resp, extra_request: dict | None=None):
        pass

    def _sniff_login_verifier(self, text: str, source: str=''):
        """从任意文本中提取 login_verifier/code_verifier。"""
        if not text:
            return
        try:
            patterns = ['(?:login_verifier|code_verifier|verifier)=([A-Za-z0-9._~-]{8,})', '"(?:login_verifier|code_verifier|verifier)"\\s*:\\s*"([^"]{8,})"']
            for p in patterns:
                m = re.search(p, text)
                if not m:
                    continue
                v = (m.group(1) or '').strip()
                if not v:
                    continue
                if v != self._captured_login_verifier:
                    self._captured_login_verifier = v
                    logger.info('捕获 login_verifier 来源=%s len=%s', source or 'unknown', len(v))
                return
        except Exception:
            return

    @staticmethod
    def _walk_collect_str_fields(obj: Any, wanted_keys: set[str], out: dict[str, str], depth: int=0, max_depth: int=6):
        """递归收集目标字段（仅字符串值）。"""
        if depth > max_depth or obj is None:
            return
        if isinstance(obj, dict):
            for k, v in obj.items():
                kk = (str(k) or '').strip().lower()
                if kk in wanted_keys and isinstance(v, str) and v.strip():
                    out[kk] = v.strip()
                AuthFlow._walk_collect_str_fields(v, wanted_keys, out, depth + 1, max_depth)
        elif isinstance(obj, list):
            for it in obj:
                AuthFlow._walk_collect_str_fields(it, wanted_keys, out, depth + 1, max_depth)

    def fetch_client_auth_session_dump(self, stage: str='') -> dict:
        return {}

    @staticmethod
    def _is_tls_error(exc: Exception) -> bool:
        msg = str(exc).lower()
        markers = ['curl: (35)', 'tls connect error', 'openssl_internal', 'sslerror']
        return any((m in msg for m in markers))

    @staticmethod
    def _is_registration_disallowed_error(exc: Exception) -> bool:
        msg = str(exc).lower()
        return 'registration_disallowed' in msg

    def _get_cookie_value_by_name(self, name: str) -> str:
        """按 cookie 名称获取值（忽略 domain 冲突）。"""
        try:
            jar = getattr(self.session.cookies, 'jar', None)
            if jar is None:
                return ''
            target = (name or '').strip().lower()
            for c in jar:
                if (getattr(c, 'name', '') or '').strip().lower() == target:
                    return (getattr(c, 'value', '') or '').strip()
        except Exception:
            pass
        return ''

    def _extract_login_challenge_from_cookie(self) -> str:
        """
        从 login_session cookie 中提取 login_challenge。
        login_session 的第一段通常是 base64url(JSON)。
        """
        raw = self._get_cookie_value_by_name('login_session')
        if not raw:
            return ''
        try:
            p0 = raw.split('.')[0]
            p0 += '=' * (-len(p0) % 4)
            payload = json.loads(base64.urlsafe_b64decode(p0.encode('utf-8')).decode('utf-8'))
            return (payload.get('login_challenge', '') or '').strip()
        except Exception:
            return ''

    @staticmethod
    def _extract_query_first(url: str, keys: list[str]) -> str:
        if not url:
            return ''
        try:
            qs = parse_qs(urlparse(url).query)
        except Exception:
            return ''
        for k in keys:
            val = qs.get(k, [None])[0]
            if val:
                return val
        return ''

    @staticmethod
    def _extract_page_type(resp_json: dict | None) -> str:
        if not isinstance(resp_json, dict):
            return ''
        page = resp_json.get('page', {})
        if not isinstance(page, dict):
            return ''
        return (page.get('type', '') or '').strip()

    @staticmethod
    def _extract_continue_url_from_step(resp_json: dict | None) -> str:
        """
        从 auth step 响应提取 continue_url：
        - 顶层 continue_url
        - page.type=external_url 时 payload.url
        """
        if not isinstance(resp_json, dict):
            return ''
        continue_url = (resp_json.get('continue_url', '') or '').strip()
        if continue_url:
            return continue_url
        page = resp_json.get('page', {})
        if not isinstance(page, dict):
            return ''
        if (page.get('type', '') or '').strip() != 'external_url':
            return ''
        payload = page.get('payload', {})
        if not isinstance(payload, dict):
            return ''
        return (payload.get('url', '') or '').strip()

    def _get_env(self, name: str, default: str='') -> str:
        """读配置：本次流程的 env_overrides 优先，回退进程环境变量。

        registrar 通过 AuthFlow(env_overrides=...) 传入，不再写 os.environ，
        所以并发跑多个号时互不干扰。命令行入口（register_outlook.py）没传
        overrides，行为跟以前完全一样。
        """
        v = self._env_overrides.get(name)
        return os.getenv(name, default) if v is None else str(v)

    def _env_flag(self, name: str, default: str='0') -> bool:
        return self._get_env(name, default).lower() in ('1', 'true', 'yes', 'on')

    @staticmethod
    def _b64url_no_pad(raw: bytes) -> str:
        return base64.urlsafe_b64encode(raw).decode('utf-8').rstrip('=')

    def _remember_oauth_params(self, auth_url: str):
        """从 authorize URL 记住 OAuth 参数，供后续 token exchange 使用。"""
        if not auth_url:
            return
        self._oauth_auth_url = auth_url
        try:
            qs = parse_qs(urlparse(auth_url).query)
            self._oauth_client_id = (qs.get('client_id', [self._oauth_client_id])[0] or self._oauth_client_id).strip()
            self._oauth_redirect_uri = (qs.get('redirect_uri', [self._oauth_redirect_uri])[0] or self._oauth_redirect_uri).strip()
            self._oauth_scope = (qs.get('scope', [''])[0] or '').strip()
            self._oauth_state = (qs.get('state', [''])[0] or '').strip()
        except Exception:
            return

    def _build_pkce_pair(self, raw_bytes: int=64) -> tuple[str, str]:
        """生成 (code_verifier, code_challenge)。"""
        verifier = self._b64url_no_pad(secrets.token_bytes(max(32, int(raw_bytes))))
        if len(verifier) < 43:
            verifier = (verifier + 'A' * 43)[:43]
        if len(verifier) > 128:
            verifier = verifier[:128]
        challenge = self._b64url_no_pad(hashlib.sha256(verifier.encode('utf-8')).digest())
        return (verifier, challenge)

    def _build_codex_authorize(self, prompt_override: Optional[str]=None) -> tuple[str, str, str, str, str]:
        """
        构建用于获取 refresh_token 的 Codex OAuth 授权 URL。
        参考 any-auto-register 的实现：独立 client_id + redirect_uri + 可控 PKCE。
        """
        client_id = (os.getenv('OAUTH_CODEX_CLIENT_ID', '') or '').strip() or 'app_EMoamEEZ73f0CkXaXp7hrann'
        redirect_uri = (os.getenv('OAUTH_CODEX_REDIRECT_URI', '') or '').strip() or 'http://localhost:1455/auth/callback'
        scope = (os.getenv('OAUTH_CODEX_SCOPE', '') or '').strip() or 'openid email profile offline_access'
        state = self._b64url_no_pad(secrets.token_bytes(24))
        verifier, challenge = self._build_pkce_pair()
        prompt = (os.getenv('OAUTH_CODEX_PROMPT', 'login') or '').strip() if prompt_override is None else (prompt_override or '').strip()
        params = {'client_id': client_id, 'response_type': 'code', 'redirect_uri': redirect_uri, 'scope': scope, 'state': state, 'code_challenge': challenge, 'code_challenge_method': 'S256', 'id_token_add_organizations': 'true', 'codex_cli_simplified_flow': 'true'}
        if prompt:
            params['prompt'] = prompt
        auth_url = f'https://auth.openai.com/oauth/authorize?{urlencode(params)}'
        return (auth_url, state, verifier, redirect_uri, client_id)

    @staticmethod
    def _callback_has_code(url: str, redirect_uri: str) -> bool:
        if not url:
            return False
        try:
            cb_base = (redirect_uri or '').split('?', 1)[0].rstrip('/')
            target = url.split('?', 1)[0].rstrip('/')
            if cb_base and target == cb_base:
                qs = parse_qs(urlparse(url).query)
                return bool((qs.get('code', [''])[0] or '').strip())
        except Exception:
            return False
        return False

    def _follow_authorize_for_callback(self, start_url: str, redirect_uri: str, trace_prefix: str) -> tuple[str, str]:
        """
        跟随 auth.openai.com 授权链路，捕获 callback（不消费 callback）。
        返回 (callback_url, final_url)。
        """
        current = start_url
        callback_url = ''
        chose_account = False
        for i in range(12):
            if self._callback_has_code(current, redirect_uri):
                callback_url = current
                break
            resp = self.session.get(current, headers={'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8', 'Referer': 'https://chatgpt.com/', 'User-Agent': self._ua}, timeout=30, allow_redirects=False)
            self._trace_http(f'{trace_prefix}_hop_{i + 1}', resp)
            if resp.status_code == 200:
                is_workspace_like = '/workspace' in current or '/sign-in-with-chatgpt/' in current or '/consent' in current
                if is_workspace_like:
                    workspace_id = self._extract_workspace_id() or self._extract_workspace_id_from_html(resp.text or '')
                    if workspace_id:
                        next_url = self._workspace_select(workspace_id)
                        if next_url:
                            if next_url.startswith('/'):
                                next_url = urljoin('https://auth.openai.com', next_url)
                            current = next_url
                            continue
                if '/choose-an-account' in current and (not chose_account):
                    chose_account = True
                    next_url = self._choose_account_select(resp.text or '', current)
                    if next_url:
                        if next_url.startswith('/'):
                            next_url = urljoin('https://auth.openai.com', next_url)
                        current = next_url
                        continue
            if resp.status_code not in (301, 302, 303, 307, 308):
                break
            loc = (resp.headers.get('Location', '') or '').strip()
            if not loc:
                break
            if loc.startswith('/'):
                loc = urljoin(current, loc)
            if self._callback_has_code(loc, redirect_uri):
                callback_url = loc
                current = loc
                break
            current = loc
        return (callback_url, current)

    @staticmethod
    def _drop_query_keys(url: str, drop_keys: set[str]) -> str:
        if not url:
            return ''
        try:
            parsed = urlparse(url)
            params = parse_qsl(parsed.query, keep_blank_values=True)
            kept = [(k, v) for k, v in params if (k or '').strip() not in drop_keys]
            return urlunparse(parsed._replace(query=urlencode(kept)))
        except Exception:
            return url

    def _exchange_codex_callback_code(self, callback_url: str, expected_state: str, verifier: str, redirect_uri: str, client_id: str) -> bool:
        qs = parse_qs(urlparse(callback_url).query)
        code = (qs.get('code', [''])[0] or '').strip()
        got_state = (qs.get('state', [''])[0] or '').strip()
        if not code:
            logger.warning('Codex callback 缺少 code')
            return False
        if expected_state and got_state and (got_state != expected_state):
            logger.warning('Codex callback state 不匹配，期望=%s 实际=%s', expected_state[:20], got_state[:20])
            return False
        headers = {'Content-Type': 'application/x-www-form-urlencoded', 'Accept': 'application/json', 'Origin': 'https://auth.openai.com', 'Referer': 'https://auth.openai.com/sign-in-with-chatgpt/codex/consent', 'User-Agent': self._ua}
        form = {'grant_type': 'authorization_code', 'client_id': client_id, 'code': code, 'redirect_uri': redirect_uri, 'code_verifier': verifier}
        encoded_form = urlencode(form)
        resp = self.session.post('https://auth.openai.com/oauth/token', headers=headers, data=encoded_form, timeout=30)
        self._trace_http('oauth_token_exchange_codex_pkce', resp, extra_request={'method': 'POST', 'url': 'https://auth.openai.com/oauth/token', 'body': encoded_form, 'headers': headers})
        if resp.status_code != 200:
            logger.warning('Codex oauth/token 失败: %s - %s', resp.status_code, (resp.text or '')[:220])
            return False
        data = resp.json() if resp is not None else {}
        self.result.id_token = data.get('id_token', self.result.id_token)
        self.result.access_token = data.get('access_token', self.result.access_token)
        self.result.refresh_token = data.get('refresh_token', self.result.refresh_token)
        logger.info('Codex OAuth 交换成功: access=%s refresh=%s', '有' if self.result.access_token else '无', '有' if self.result.refresh_token else '无')
        return True

    def _codex_drive_login_from_log_in(self, mail_provider: Optional[MailProvider]=None) -> str:
        """
        当 Codex 授权回落到 /log-in 时，补走一次纯协议登录推进状态机。
        返回可继续跟随的 continue_url（若无则返回空字符串）。
        """
        email = (self.result.email or '').strip()
        if not email:
            logger.warning('Codex 登录推进缺少 email')
            return ''
        password, _password_is_guess = self._login_password_candidate(email)
        device_id = (self.result.device_id or '').strip() or (self.session.cookies.get('oai-did', '') or '').strip()
        if not device_id:
            device_id = str(uuid.uuid4())
            self.result.device_id = device_id
        sentinel = self.get_sentinel_token(device_id)
        step = self.authorize_continue(email=email, sentinel_token=sentinel, screen_hint='login', referer='https://auth.openai.com/log-in', trace_step='authorize_continue_login_codex')
        page_type = self._extract_page_type(step)
        continue_url = self._normalize_continue_url(self._extract_continue_url_from_step(step))
        if page_type == 'login_password' or '/log-in/password' in continue_url:
            step = self.login_password_verify(password)
            self.result.password = password
            page_type = self._extract_page_type(step)
            continue_url = self._normalize_continue_url(self._extract_continue_url_from_step(step))
        if self._is_mfa_challenge_state(page_type, continue_url):
            totp_secret = (self.result.totp_secret or '').strip()
            if not totp_secret and self._account_callback:
                try:
                    cred = self._account_callback(email)
                    if cred and cred.get('totp_secret'):
                        totp_secret = cred['totp_secret']
                        self.result.totp_secret = totp_secret
                        logger.info('已从数据库加载 totp_secret')
                except Exception as e:
                    logger.warning(f'account_callback 异常: {e}')
            if not totp_secret:
                logger.warning('进入 mfa-challenge 但没有 totp_secret，无法继续')
                return continue_url or ''
            challenge_id = continue_url.split('/')[-1] if '/mfa-challenge/' in continue_url else ''
            if not challenge_id:
                logger.warning('无法从 continue_url 提取 challenge_id')
                return continue_url or ''
            totp_code = _totp_now(totp_secret)
            logger.info(f'提交 TOTP 码进行 2FA 验证（challenge_id={challenge_id[:16]}...）')
            mfa_resp = self.submit_mfa_totp(totp_code, challenge_id)
            continue_url = self._normalize_continue_url(self._extract_continue_url_from_step(mfa_resp))
        need_otp = page_type == 'email_otp_verification' or '/email-verification' in (continue_url or '')
        if need_otp:
            if mail_provider is None:
                logger.warning('Codex 登录推进需要 OTP，但未提供 mail_provider')
                return continue_url or ''
            try:
                otp_timeout = max(10, int(self._get_env('OTP_TIMEOUT', '60')))
            except Exception:
                otp_timeout = 180
            otp_sent_at = time.time()
            if not self.kickoff_otp_delivery('codex_login_need_otp'):
                self.send_otp()
            otp_code = mail_provider.wait_for_otp(email, timeout=otp_timeout, issued_after=otp_sent_at)
            otp_resp = self.verify_otp(otp_code)
            continue_url = self._normalize_continue_url(self._extract_continue_url_from_step(otp_resp))
        if self._is_add_phone_state(page_type='', continue_url=continue_url):
            next_url = self._handle_add_phone_verification(continue_url=continue_url)
            if next_url:
                continue_url = self._normalize_continue_url(next_url)
        return continue_url or ''

    @staticmethod
    def _is_add_phone_state(page_type: str='', continue_url: str='') -> bool:
        pt = (page_type or '').strip().lower()
        cu = (continue_url or '').strip().lower()
        return pt == 'add_phone' or 'add-phone' in cu

    @staticmethod
    def _is_mfa_challenge_state(page_type: str='', continue_url: str='') -> bool:
        """判断是否进入 mfa-challenge 状态（已有账号启用 2FA，密码验证后需要 TOTP 码）。"""
        pt = (page_type or '').strip().lower()
        cu = (continue_url or '').strip().lower()
        return pt == 'mfa_challenge' or '/mfa-challenge/' in cu

    def _phone_headers(self, referer: str) -> dict:
        headers = self._common_headers(referer)
        headers['Accept'] = 'application/json'
        headers['Content-Type'] = 'application/json'
        headers['Origin'] = 'https://auth.openai.com'
        device_id = (self.result.device_id or '').strip() or (self.session.cookies.get('oai-did', '') or '').strip()
        if device_id:
            headers['oai-device-id'] = device_id
        return headers

    def _add_phone_send(self, phone_number: str) -> dict:
        headers = self._phone_headers('https://auth.openai.com/add-phone')
        try:
            resp = self.session.post('https://auth.openai.com/api/accounts/add-phone/send', headers=headers, json={'phone_number': phone_number}, timeout=30)
        except Exception as e:
            logger.warning('[add-phone] 网络异常: %s (phone=%s)', e, phone_number)
            raise
        self._trace_http('add_phone_send', resp)
        if resp.status_code != 200:
            try:
                data = resp.json()
                msg = data.get('error', {}).get('message', '')
                code = data.get('error', {}).get('code', '')
            except Exception:
                msg = resp.text[:150]
                code = ''
            raise RuntimeError(msg or f'HTTP {resp.status_code}')
        try:
            return resp.json() if resp is not None else {}
        except Exception:
            return {}

    def _phone_otp_resend(self) -> bool:
        headers = self._phone_headers('https://auth.openai.com/phone-verification')
        resp = self.session.post('https://auth.openai.com/api/accounts/phone-otp/resend', headers=headers, timeout=30)
        self._trace_http('phone_otp_resend', resp)
        return resp.status_code == 200

    def _phone_otp_validate(self, code: str) -> dict:
        headers = self._phone_headers('https://auth.openai.com/phone-verification')
        resp = self.session.post('https://auth.openai.com/api/accounts/phone-otp/validate', headers=headers, json={'code': code}, timeout=30)
        self._trace_http('phone_otp_validate', resp)
        if resp.status_code != 200:
            raise RuntimeError(f'phone-otp/validate 失败: {resp.status_code} - {(resp.text or '')[:220]}')
        try:
            return resp.json() if resp is not None else {}
        except Exception:
            return {}

    @staticmethod
    def _extract_otp6(text: str) -> str:
        if not text:
            return ''
        m = re.search('(?<!\\d)(\\d{6})(?!\\d)', text)
        return (m.group(1) if m else '').strip()

    def _read_phone_otp_from_cmd(self) -> str:
        """
        从环境变量 OPENAI_PHONE_OTP_CMD 指定的命令读取手机验证码（stdout）。
        命令输出中只要出现 6 位数字即视为命中。
        """
        cmd = (os.getenv('OPENAI_PHONE_OTP_CMD', '') or '').strip()
        if not cmd:
            return ''
        try:
            out = subprocess.check_output(cmd, shell=True, text=True, timeout=20)
            return self._extract_otp6(out or '')
        except Exception:
            return ''

    def _wait_phone_otp(self, timeout: int=180) -> str:
        static_otp = self._extract_otp6(os.getenv('OPENAI_PHONE_OTP', '') or '')
        if static_otp:
            return static_otp
        deadline = time.time() + max(20, int(timeout))
        while time.time() < deadline:
            code = self._read_phone_otp_from_cmd()
            if code:
                return code
            time.sleep(4)
        raise TimeoutError(f'等待手机 OTP 超时 ({timeout}s)')

    def _handle_add_phone_verification(self, continue_url: str='') -> str:
        """
        处理 add-phone 验证分支：
        - 优先使用 self._sms_callback（SMS 接码 controller，自动租号 + 接码）
        - 回退到环境变量路径：OPENAI_PHONE_NUMBER + OPENAI_PHONE_OTP_CMD/OPENAI_PHONE_OTP
        """
        if self._sms_callback is not None:
            try:
                return self._handle_add_phone_via_sms(continue_url)
            except Exception as e:
                logger.warning('SMS 接码流程失败，回退环境变量路径: %s', e)
                try:
                    self._sms_callback.cleanup()
                except Exception:
                    pass
        return self._handle_add_phone_via_env(continue_url)

    def _handle_add_phone_via_sms(self, continue_url: str='') -> str:
        """走 SMS 接码 controller：租号 → add-phone/send → 等 SMS → validate。

        支持平台：SmsBower（smsbower.page）。
        单号窗口 80s（每 20s × 3 触发一次 OpenAI 端 resend）；失败自动 cancel + 换新号。
        最多换号次数默认 3，主人可在 WebUI / 环境变量 OPENAI_PHONE_MAX_ATTEMPTS 自定义。
        """
        ctrl = self._sms_callback
        try:
            ctrl.set_resend_callback(self._phone_otp_resend)
        except Exception:
            pass
        try:
            return self._do_sms_loop(ctrl)
        finally:
            try:
                ctrl.cleanup()
            except Exception:
                pass
            try:
                ctrl._release_lock()
            except Exception:
                pass

    def _do_sms_loop(self, ctrl) -> str:
        """SMS 接码循环逻辑（for 0..max_attempts）。"""
        provider_key = (getattr(ctrl, 'provider_key', '') or '').lower()
        ctrl_cfg = getattr(ctrl, 'config', None) or {}

        def _read_int(cfg_key: str, env_key: str, default: str, min_v: int=1) -> int:
            raw = str(ctrl_cfg.get(cfg_key) or '').strip()
            if not raw:
                raw = os.getenv(env_key, default)
            try:
                return max(min_v, int(raw))
            except Exception:
                return int(default)
        per_phone_timeout = max(40, _read_int('sms_per_phone_timeout', 'OPENAI_PHONE_OTP_TIMEOUT', '80', min_v=40))
        max_phone_attempts = _read_int('sms_max_phone_attempts', 'OPENAI_PHONE_MAX_ATTEMPTS', '3')
        max_code_retries_per_phone = _read_int('sms_code_retries_per_phone', 'OPENAI_PHONE_OTP_CODE_RETRIES', '2')
        logger.info('[sms] 配置: provider=%s 单号窗口=%ds 最多换号=%d 单号内验证重试=%d', provider_key, per_phone_timeout, max_phone_attempts, max_code_retries_per_phone)
        _PHONE_REJECTED_PATTERNS = ('phone_number_already_in_use', 'already_in_use', 'already_taken', 'phone_already_verified', 'already_verified', 'disallowed_phone', 'invalid_phone_number', 'phone_number_invalid', 'blocked_phone', 'phone_number_blocked', 'suspicious behavior from phone')

        def _is_phone_rejected(s: str) -> bool:
            sl = (s or '').lower()
            return any((p in sl for p in _PHONE_REJECTED_PATTERNS))
        last_err: Optional[Exception] = None
        for phone_attempt in range(1, max_phone_attempts + 1):
            logger.info('[sms] 🔁 第 %d/%d 个号尝试...', phone_attempt, max_phone_attempts)
            try:
                phone = ctrl.get_phone()
            except Exception as e:
                last_err = e
                logger.warning('[sms] 第 %d 个号租号失败: %s', phone_attempt, e)
                continue
            if not phone:
                last_err = RuntimeError('SMS 接码 controller 未返回手机号')
                continue
            send_resp = None
            try:
                logger.info('[sms] 📤 准备 POST add-phone/send (phone=%s) ...', phone)
                send_resp = self._add_phone_send(phone)
                logger.info('[sms] ✅ POST add-phone/send 成功 (phone=%s)', phone)
            except Exception as e:
                err_text = str(e)
                if 'too many phone verification' in err_text.lower() or 'phone_verification_rate_limit' in err_text.lower():
                    logger.warning('⚠️ OpenAI 频控: 这个 outlook 号/IP 已累积太多 add-phone 请求，建议换 outlook 号或换代理 IP 后重试。本次放弃 add-phone（session_token 仍可保留）')
                    ctrl.mark_send_failed(err_text)
                    last_err = e
                    break
                if _is_phone_rejected(err_text):
                    logger.warning('[sms] 号 %s 被 OpenAI 拒（已用过/不允许）: %s', phone, err_text[:200])
                    ctrl.mark_send_failed(err_text)
                    last_err = e
                    continue
                logger.warning('[sms] 号 %s POST add-phone/send 失败（未识别错误）: %s', phone, err_text[:300])
                ctrl.mark_send_failed(err_text)
                last_err = e
                continue
            send_page_type = self._extract_page_type(send_resp)
            send_continue = self._normalize_continue_url(self._extract_continue_url_from_step(send_resp))
            if send_page_type not in ('phone_otp_verification', 'external_url') and 'phone-verification' not in (send_continue or ''):
                logger.warning('add-phone/send 未进入手机验证码页: page=%s continue=%s', send_page_type or '(empty)', (send_continue or '')[:180])
                ctrl.mark_send_failed('did not enter phone-verification page')
                last_err = RuntimeError(f'add-phone/send 未进入 phone-verification: page={send_page_type}')
                continue
            ctrl.mark_send_succeeded()
            phone_start = time.time()
            seen_codes: set[str] = set()
            code_attempt = 0
            phone_used = False
            while time.time() - phone_start < per_phone_timeout and code_attempt < max_code_retries_per_phone:
                remaining = per_phone_timeout - (time.time() - phone_start)
                if remaining < 10:
                    break
                code_attempt += 1
                logger.info('[sms] 号 %s 第 %d/%d 次等 SMS (剩余 %ds)', phone, code_attempt, max_code_retries_per_phone, int(remaining))
                code = ctrl.get_code(timeout=int(remaining))
                if not code:
                    break
                if code in seen_codes:
                    logger.warning('[sms] 收到重复 code=%s，跳过', code)
                    continue
                seen_codes.add(code)
                phone_used = True
                try:
                    validate_resp = self._phone_otp_validate(code)
                    next_url = self._normalize_continue_url(self._extract_continue_url_from_step(validate_resp))
                    logger.info('[sms] ✅ phone-otp/validate 通过 (phone=%s code=%s) next=%s', phone, code, (next_url or '')[:160])
                    ctrl.report_success()
                    return next_url or continue_url or ''
                except Exception as e:
                    last_err = e
                    err_text = str(e)
                    logger.warning('[sms] validate 失败 (phone=%s code=%s): %s', phone, code, err_text[:200])
                    ctrl.mark_code_failed(err_text)
            logger.warning('[sms] 号 %s 已用尽 %ds 窗口', phone, per_phone_timeout)
            try:
                ctrl.cleanup()
            except Exception:
                pass
        if last_err:
            raise last_err
        raise RuntimeError(f'SMS 接码 {max_phone_attempts} 个号均失败')

    def _handle_add_phone_via_env(self, continue_url: str='') -> str:
        """
        处理 add-phone 验证分支（环境变量路径，旧用法）：
        - 需要通过环境变量提供号码与验证码来源：
          - OPENAI_PHONE_NUMBER=+1...
          - OPENAI_PHONE_OTP_CMD='...返回短信内容...' 或 OPENAI_PHONE_OTP=123456
        """
        phone_raw = (os.getenv('OPENAI_PHONE_NUMBER', '') or '').strip()
        phone_candidates = [x.strip() for x in phone_raw.split(',') if x.strip()]
        if not phone_candidates:
            logger.warning('命中 add-phone，但未配置 SMS 接码 / OPENAI_PHONE_NUMBER，无法继续推进')
            return continue_url or ''
        try:
            otp_timeout = max(30, int(os.getenv('OPENAI_PHONE_OTP_TIMEOUT', '180')))
        except Exception:
            otp_timeout = 180
        last_err = ''
        for idx, phone in enumerate(phone_candidates, 1):
            try:
                logger.info('add-phone 尝试号码 %s/%s: %s', idx, len(phone_candidates), phone)
                send_resp = self._add_phone_send(phone)
                send_page_type = self._extract_page_type(send_resp)
                send_continue = self._normalize_continue_url(self._extract_continue_url_from_step(send_resp))
                if send_page_type not in ('phone_otp_verification', 'external_url') and 'phone-verification' not in (send_continue or ''):
                    logger.warning('add-phone/send 未进入手机验证码页: page=%s continue=%s', send_page_type or '(empty)', (send_continue or '')[:180])
                    continue
                phone_code = self._wait_phone_otp(timeout=otp_timeout)
                validate_resp = self._phone_otp_validate(phone_code)
                next_url = self._normalize_continue_url(self._extract_continue_url_from_step(validate_resp))
                logger.info('add-phone 验证通过，next=%s', (next_url or '')[:180])
                return next_url or continue_url or ''
            except Exception as e:
                last_err = str(e)
                logger.warning('add-phone 号码 %s 失败: %s', phone, e)
                try:
                    self._phone_otp_resend()
                except Exception:
                    pass
        if last_err:
            logger.warning('add-phone 阶段未成功: %s', last_err)
        return continue_url or ''

    def _codex_refresh_retry_after_add_phone(self, auth_url: str, redirect_uri: str, attempts: int=3, sleep_seconds: float=1.2) -> tuple[str, str]:
        """
        当命中 add-phone 时，按“刷新重试”策略重复发起 authorize，
        期望命中不需要 add-phone 的分支并直接拿 callback code。
        """
        callback_url = ''
        final_url = ''
        start_url = self._drop_query_keys(auth_url, {'prompt'}) or auth_url
        rounds = max(1, int(attempts))
        wait_s = max(0.0, float(sleep_seconds))
        for i in range(rounds):
            callback_url, final_url = self._follow_authorize_for_callback(start_url, redirect_uri, f'codex_add_phone_refresh_retry_{i + 1}')
            if callback_url:
                return (callback_url, final_url)
            if i < rounds - 1 and wait_s > 0:
                time.sleep(wait_s)
        return (callback_url, final_url)

    def oauth_codex_rt_exchange(self, mail_provider: Optional[MailProvider]=None) -> bool:
        """
        纯协议方式获取 RT（参考 any-auto-register）：
        - 使用独立 Codex OAuth 参数重新授权（可控 PKCE）
        - 捕获 callback code（不消费）
        - 直接调 /oauth/token 交换 access_token + refresh_token
        """
        allow_retry = self._env_flag('OAUTH_CODEX_RT_ALLOW_RETRY', '0')
        if self._codex_rt_attempted and (not allow_retry):
            logger.debug('Codex RT 本轮已尝试过，跳过重复尝试')
            return False
        self._codex_rt_attempted = True
        logger.info('尝试 Codex OAuth 直连换取 refresh_token ...')
        try:
            auth_url, state, verifier, redirect_uri, client_id = self._build_codex_authorize()
            self._oauth_auth_url = auth_url
            self._oauth_client_id = client_id
            self._oauth_redirect_uri = redirect_uri
            self._oauth_state = state
            self._manual_login_verifier = verifier
            self._captured_login_verifier = verifier
            callback_url, final_url = self._follow_authorize_for_callback(auth_url, redirect_uri, 'codex_authorize')
            if not callback_url and '/log-in' in (final_url or ''):
                logger.info('Codex 授权回落到 /log-in，尝试协议推进登录状态...')
                continue_url = ''
                try:
                    continue_url = self._codex_drive_login_from_log_in(mail_provider=mail_provider)
                except Exception as e:
                    logger.warning(f'Codex 登录推进失败，改走 no-prompt 兜底: {e}')
                if continue_url:
                    if self._is_add_phone_state(page_type='', continue_url=continue_url) and self._env_flag('OAUTH_CODEX_ADD_PHONE_REFRESH_RETRY', '1'):
                        try:
                            retry_count = max(1, int(os.getenv('OAUTH_CODEX_ADD_PHONE_REFRESH_RETRY_COUNT', '3')))
                        except Exception:
                            retry_count = 3
                        try:
                            retry_sleep = max(0.0, float(os.getenv('OAUTH_CODEX_ADD_PHONE_REFRESH_SLEEP', '1.2')))
                        except Exception:
                            retry_sleep = 1.2
                        logger.info('命中 add-phone，执行 authorize 刷新重试: count=%s sleep=%.1fs', retry_count, retry_sleep)
                        callback_url, final_url = self._codex_refresh_retry_after_add_phone(auth_url=auth_url, redirect_uri=redirect_uri, attempts=retry_count, sleep_seconds=retry_sleep)
                    else:
                        callback_url, final_url = self._follow_authorize_for_callback(continue_url, redirect_uri, 'codex_post_login')
            if not callback_url and self._is_add_phone_state(page_type='', continue_url=final_url or '') and (self._sms_callback is not None):
                logger.info('Codex 授权直接落到 /add-phone，尝试 SMS 接码绑号 ...')
                try:
                    self._handle_add_phone_via_sms(continue_url=final_url)
                    callback_url, final_url = self._follow_authorize_for_callback(auth_url, redirect_uri, 'codex_authorize_after_add_phone')
                    if not callback_url:
                        no_prompt_url = self._drop_query_keys(auth_url, {'prompt'})
                        if no_prompt_url and no_prompt_url != auth_url:
                            callback_url, final_url = self._follow_authorize_for_callback(no_prompt_url, redirect_uri, 'codex_authorize_noprompt_after_add_phone')
                except Exception as e:
                    logger.warning(f'SMS 接码绑号失败: {e}')
            if not callback_url:
                no_prompt_url = self._drop_query_keys(auth_url, {'prompt'})
                if no_prompt_url and no_prompt_url != auth_url:
                    callback_url, final_url = self._follow_authorize_for_callback(no_prompt_url, redirect_uri, 'codex_authorize_noprompt')
            if not callback_url:
                logger.debug('Codex OAuth 未捕获 callback code, final=%s', (final_url or '')[:180])
                return False
            return self._exchange_codex_callback_code(callback_url=callback_url, expected_state=state, verifier=verifier, redirect_uri=redirect_uri, client_id=client_id)
        except Exception as e:
            logger.warning(f'Codex OAuth 交换异常: {e}')
            return False

    def _inject_pkce_into_auth_url(self, auth_url: str) -> str:
        """为 authorize URL 注入 PKCE 参数（可选）。"""
        if not auth_url:
            return auth_url
        if not self._env_flag('OAUTH_SECONDARY_PKCE', '0'):
            return auth_url
        try:
            parsed = urlparse(auth_url)
            params = dict(parse_qsl(parsed.query, keep_blank_values=True))
            if params.get('code_challenge') and params.get('code_challenge_method'):
                return auth_url
            verifier, challenge = self._build_pkce_pair()
            params['code_challenge'] = challenge
            params['code_challenge_method'] = 'S256'
            new_url = urlunparse(parsed._replace(query=urlencode(params)))
            if not self._manual_login_verifier:
                self._manual_login_verifier = verifier
            logger.info('已启用二次 PKCE 注入: verifier_len=%s challenge=%s...', len(verifier), challenge[:16])
            return new_url
        except Exception as e:
            logger.warning(f'注入 PKCE 参数失败，回退原始 auth_url: {e}')
            return auth_url

    @staticmethod
    def _safe_b64url_decode_text(data: str) -> str:
        if not data:
            return ''
        try:
            s = data + '=' * (-len(data) % 4)
            return base64.urlsafe_b64decode(s.encode('utf-8')).decode('utf-8', errors='replace')
        except Exception:
            return ''

    def _extract_hydra_redirect_values(self) -> list[str]:
        """从 hydra_redirect cookie 中提取可能的会话值。"""
        raw = self._get_cookie_value_by_name('hydra_redirect')
        if not raw:
            return []
        out: list[str] = []
        try:
            p0 = (raw.split('.', 1)[0] or '').strip()
            text = self._safe_b64url_decode_text(p0)
            if text:
                obj = json.loads(text)
                if isinstance(obj, dict):
                    for v in obj.values():
                        if isinstance(v, str) and v.strip():
                            vv = v.strip()
                            out.append(vv)
                            if '|' in vv:
                                out.extend([x for x in vv.split('|') if isinstance(x, str) and x.strip()])
        except Exception:
            return out
        return out

    def _collect_code_verifier_candidates(self, callback_url: str, continue_url: str) -> list[tuple[str, str]]:
        """收集 code_verifier 候选（来源 + 值）。"""
        raw_candidates: list[tuple[str, str]] = [('query', self._extract_query_first(continue_url, ['login_verifier', 'code_verifier', 'verifier'])), ('query_callback', self._extract_query_first(callback_url, ['login_verifier', 'code_verifier', 'verifier'])), ('dump', self._dump_login_verifier), ('captured', self._captured_login_verifier), ('manual', self._manual_login_verifier), ('cookie_login_verifier', self._get_cookie_value_by_name('login_verifier')), ('cookie_code_verifier', self._get_cookie_value_by_name('code_verifier')), ('cookie_login_challenge', self._extract_login_challenge_from_cookie()), ('cookie_nextauth_state', self._get_cookie_value_by_name('__Secure-next-auth.state'))]
        for i, hv in enumerate(self._extract_hydra_redirect_values()):
            raw_candidates.append((f'hydra_{i}', hv))
        out: list[tuple[str, str]] = []
        seen: set[str] = set()
        max_len = max(128, int(os.getenv('OAUTH_MAX_VERIFIER_LEN', '4096')))
        for src, val in raw_candidates:
            v = (val or '').strip()
            if not v:
                continue
            if len(v) > max_len:
                v = v[:max_len]
            if v not in seen:
                seen.add(v)
                out.append((src, v))
            if len(v) > 128:
                v128 = v[:128]
                if v128 not in seen:
                    seen.add(v128)
                    out.append((f'{src}_trunc128', v128))
        return out

    def _rotate_impersonate_session(self) -> bool:
        """Rebuild the entire OAuth transaction for the next TLS target."""
        attempted = set(getattr(self, '_tls_attempted_targets', set()) or set())
        candidates = [value for value in self._impersonate_candidates if value and value not in attempted]
        if not candidates:
            return False
        imp = candidates[0]
        previous = self.result
        rebuilt = self._ensure_registration_context().rebuild_for_tls(imp)
        self._replace_registration_context(rebuilt, preserve_email=previous.email, preserve_password=previous.password, preserve_totp_secret=previous.totp_secret)
        attempted.add(imp)
        self._tls_attempted_targets = attempted
        self._is_existing_account = False
        self._existing_email_verification_mode = ''
        self._existing_page_type = ''
        self._captured_login_verifier = ''
        self._oauth_state = ''
        self._oauth_auth_url = ''
        self._client_auth_session_dump = {}
        self._client_auth_session_id = ''
        self._last_sentinel_token = ''
        self._last_sentinel_so_token = ''
        self._last_sentinel_request_so_token = ''
        self._clear_authorization_caches()
        self._clear_sentinel_state()
        logger.warning('TLS 异常，已原子重建 OAuth 事务: impersonate=%s context=%s ua=%s...', imp, rebuilt.context_id, self._ua[:60])
        self.warmup()
        return True

    def _reset_authorization_session(self, email: str) -> None:
        """丢弃已失效的 OAuth 状态，使用同一代理路由和全新浏览器身份重建。"""
        previous_impersonate = self._impersonate_candidates[self._impersonate_idx]
        previous = self.result
        context = RegistrationContext.create(country_code=self._country_code, reason=f'{self._ensure_registration_context().context_reason}:invalid_state_oauth_rebuild')
        context.supersedes_context_id = self._ensure_registration_context().context_id
        self._replace_registration_context(context, preserve_email=email or previous.email, preserve_password=previous.password, preserve_totp_secret=previous.totp_secret)
        self._tls_attempted_targets = {context.tls_target}
        logger.info('OAuth 状态重建已刷新浏览器身份: %s -> %s', previous_impersonate, context.tls_target)
        self.cookie_refresh_validation: dict[str, Any] = {}
        self._is_existing_account = False
        self._existing_email_verification_mode = ''
        self._existing_page_type = ''
        self._captured_login_verifier = ''
        self._oauth_state = ''
        self._oauth_auth_url = ''
        self._client_auth_session_dump = {}
        self._client_auth_session_id = ''
        self._last_sentinel_token = ''
        self._last_sentinel_so_token = ''
        self._last_sentinel_request_so_token = ''
        self._clear_authorization_caches()
        self._clear_sentinel_state()

    def _begin_registration_authorization(self, email: str) -> bool:
        """初始化注册状态机；invalid_state 时最多重建两次完整会话。"""
        for attempt in range(3):
            try:
                if attempt == 0:
                    self._protocol_har_bootstrap(email)
                self._protocol_prelude(email)
                csrf_token = self.get_csrf_token()
                auth_url = self.get_auth_url(csrf_token, email=email)
                device_id = self.auth_oauth_init(auth_url)
                sentinel = self.get_sentinel_token(device_id)
                return self.signup(email, sentinel)
            except RuntimeError as e:
                is_invalid_state = getattr(e, 'error_code', '') == 'invalid_state' or 'invalid_state' in str(e).lower() or '登录状态已失效' in str(e)
                if attempt < 2 and is_invalid_state:
                    logger.warning('登录状态已失效，正在重建完整会话并重试（第 %s/2 次）', attempt + 1)
                    self._reset_authorization_session(email)
                    self.warmup()
                    continue
                raise
        raise RuntimeError('OAuth 状态重建后仍未完成授权初始化')

    def _continue_existing_login_authorization(self, email: str, auth_url: str, sentinel_token: str, check_stopped: Optional[Any]=None) -> tuple[str, str, dict]:
        """继续已有账号登录；invalid_state 时完整重建会话并仅重试一次。"""
        for attempt in range(2):
            try:
                login_step = self.authorize_continue(email=email, sentinel_token=sentinel_token, screen_hint='login', referer='https://auth.openai.com/log-in', trace_step='authorize_continue_login_protocol')
                return (auth_url, sentinel_token, login_step)
            except RuntimeError as e:
                is_invalid_state = getattr(e, 'error_code', '') == 'invalid_state' or 'invalid_state' in str(e).lower()
                if attempt == 0 and is_invalid_state:
                    password = self.result.password
                    totp_secret = self.result.totp_secret
                    logger.warning('登录状态已失效，正在自动重建会话并重试一次')
                    self._reset_authorization_session(email)
                    self.result.email = email
                    self.result.password = password
                    self.result.totp_secret = totp_secret
                    self._is_existing_account = True
                    self.warmup()
                    if check_stopped:
                        check_stopped('OAuth 状态重建后')
                    csrf_token = self.get_csrf_token()
                    auth_url = self.get_auth_url(csrf_token, email=email)
                    device_id = self.auth_oauth_init(auth_url)
                    if check_stopped:
                        check_stopped('OAuth 重新初始化后')
                    sentinel_token = self.get_sentinel_token(device_id)
                    if check_stopped:
                        check_stopped('Sentinel 重取后')
                    continue
                raise
        raise RuntimeError('已有账号登录 OAuth 状态重建后仍未完成授权初始化')

    @staticmethod
    def _datadog_trace_headers() -> dict:
        """生成 Datadog RUM 追踪头（对齐 gptfree-register 格式）。"""
        tid = f'{random.getrandbits(64):016x}'
        sid = str(random.getrandbits(63))
        pid = str(random.getrandbits(63))
        ts_hex = f'{int(time.time()):08x}'
        return {'traceparent': f'00-0000000000000000{tid}-{random.getrandbits(64):016x}-01', 'x-datadog-trace-id': sid, 'x-datadog-parent-id': pid, 'x-datadog-sampling-priority': '1', 'x-datadog-origin': 'rum', 'x-datadog-tags': f'_dd.p.id={tid},_dd.p.tid={ts_hex}00000000,_dd.b.sr=1'}

    def _common_headers(self, referer: str='https://chatgpt.com/') -> dict:
        """
        构造通用请求头。

        关键点：
        - Origin 必须与 Referer 同源（尤其 auth.openai.com 的状态机接口），
          否则容易触发 invalid_state / 风控分支。
        - 在 auth.openai.com 域下，尽量补充 oai-device-id，提升状态机连续性。
        - 协议链不伪装浏览器 RUM；只发送接口本身需要的请求头。
        """
        origin = 'https://chatgpt.com'
        try:
            parsed = urlparse(referer or '')
            if parsed.scheme and parsed.netloc:
                origin = f'{parsed.scheme}://{parsed.netloc}'
        except Exception:
            pass
        fp = self._fingerprint
        headers = {'Accept': 'application/json', 'Referer': referer, 'Origin': origin, 'User-Agent': self._ua, 'Accept-Language': fp['lang_full'], 'Accept-Encoding': 'gzip, deflate, br, zstd', 'Sec-Fetch-Dest': 'empty', 'Sec-Fetch-Mode': 'cors', 'Sec-Fetch-Site': 'same-origin', 'priority': 'u=1, i'}
        if fp.get('sec_ch_ua'):
            headers['sec-ch-ua'] = fp['sec_ch_ua']
            headers['sec-ch-ua-mobile'] = fp.get('sec_ch_ua_mobile') or '?0'
            headers['sec-ch-ua-platform'] = fp['sec_ch_ua_platform']
            if fp.get('sec_ch_ua_full_version_list'):
                headers['sec-ch-ua-full-version-list'] = fp['sec_ch_ua_full_version_list']
            if fp.get('sec_ch_ua_arch'):
                headers['sec-ch-ua-arch'] = fp['sec_ch_ua_arch']
            if fp.get('sec_ch_ua_bitness'):
                headers['sec-ch-ua-bitness'] = fp['sec_ch_ua_bitness']
            if fp.get('sec_ch_ua_model'):
                headers['sec-ch-ua-model'] = fp['sec_ch_ua_model']
            if fp.get('sec_ch_ua_platform_version'):
                headers['sec-ch-ua-platform-version'] = fp['sec_ch_ua_platform_version']
        try:
            host = (urlparse(origin).netloc or '').lower()
        except Exception:
            host = ''
        if 'auth.openai.com' in host:
            device_id = (self.result.device_id or '').strip() or (self.session.cookies.get('oai-did', '') or '').strip()
            if device_id:
                headers['oai-device-id'] = device_id
        return headers

    def warmup(self) -> bool:
        """GET chatgpt.com 首页获取 __cf_bm cookie（Cloudflare 预热 + 连通性验证）。"""
        try:
            resp = self.session.get('https://chatgpt.com', headers={'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8', 'sec-fetch-dest': 'document', 'sec-fetch-mode': 'navigate', 'sec-fetch-site': 'none', 'sec-fetch-user': '?1', 'upgrade-insecure-requests': '1', 'User-Agent': self._ua}, timeout=15)
            logger.info('chatgpt.com warmup 完成')
            pinned = self._pinned_device_id_from_cookies('chatgpt.com')
            if pinned:
                self._ensure_registration_context().bind_device_id(pinned, source='chatgpt_warmup_cookie')
                self.result.device_id = pinned
                logger.debug('设备 ID 固定为首页 cookie: %s', pinned)
            self._capture_context_cookies('post_warmup')
            return True
        except Exception as e:
            logger.warning(f'Cloudflare warmup 失败: {e}')
            return False

    def _device_cookie_for(self, domain: str) -> str:
        """读取指定域名的 oai-did；多域同名时 curl_cffi 必须显式 domain 才不会冲突。"""
        try:
            value = str(self.session.cookies.get('oai-did', domain=domain) or '').strip()
        except Exception:
            value = ''
        if value:
            return value
        try:
            for cookie in self.session.cookies:
                if getattr(cookie, 'name', '') != 'oai-did':
                    continue
                cookie_domain = str(getattr(cookie, 'domain', '') or '').lstrip('.')
                if cookie_domain.endswith(domain):
                    raw = str(getattr(cookie, 'value', '') or '').strip()
                    if raw:
                        return raw
        except Exception:
            pass
        return ''

    def _pinned_device_id_from_cookies(self, domain: str='') -> str:
        """从会话 cookie 读取 oai-did；带 domain 时优先该域（浏览器同源行为）。"""
        if domain:
            value = self._device_cookie_for(domain)
            if value:
                return value
        try:
            for cookie in self.session.cookies:
                if getattr(cookie, 'name', '') == 'oai-did':
                    raw = str(getattr(cookie, 'value', '') or '').strip()
                    if raw:
                        return raw
        except Exception:
            pass
        try:
            return str(self.session.cookies.get('oai-did') or '').strip()
        except Exception:
            return ''

    def _pin_device_cookie(self, device_id: str, domains=('chatgpt.com', 'auth.openai.com')) -> None:
        """仅在目标域缺少 oai-did 时补写；服务端已下发的值一律不覆盖。

        URL 参数（ext-oai-did）/ 请求头（oai-device-id）/ cookie 的关联要正确，
        但服务端轮换 Set-Cookie 是权威状态，不能被本地固定值回写覆盖。
        """
        if not device_id:
            return
        for domain in domains:
            if self._device_cookie_for(domain):
                continue
            try:
                self.session.cookies.set('oai-did', device_id, domain=domain, path='/')
            except Exception:
                pass

    def _settle_device_id(self, observed: str='') -> str:
        """服务端 cookie > 已固定值 > observed/uuid，并把结果写回实例与缺失的域。"""
        pinned = str(getattr(self.result, 'device_id', '') or '').strip()
        chosen = self._device_cookie_for('auth.openai.com') or self._device_cookie_for('chatgpt.com') or pinned or str(observed or '').strip() or str(uuid.uuid4())
        if pinned and chosen != pinned:
            logger.debug('oai-did：采用服务端 cookie %s（本地固定值 %s 不再回写）', chosen, pinned)
        self._pin_device_cookie(chosen, domains=('auth.openai.com',))
        self._ensure_registration_context().bind_device_id(chosen, source='server_cookie_settle')
        self.result.device_id = chosen
        self._arm_signal_layer()
        self._capture_context_cookies('device_id_settled')
        return chosen

    def _pre_oauth_dump_needed(self) -> bool:
        """Codex/二次授权流程才需要 client_auth_session_dump；两者都关（协议注册默认）时不发。"""
        return self._env_flag('OAUTH_CODEX_RT_EXCHANGE', '1') or self._env_flag('OAUTH_SECONDARY_AUTHORIZE_EXCHANGE', '0')

    def _ensure_device_id(self) -> str:
        """确保设备 ID 存在（优先 cookie，其次生成并写回），供 signin 与先导序列共用。"""
        cookie_did = self._pinned_device_id_from_cookies('chatgpt.com')
        context = self._ensure_registration_context()
        if cookie_did:
            context.bind_device_id(cookie_did, source='ensure_device_cookie')
        self.result.device_id = cookie_did or context.device_id
        self._pin_device_cookie(self.result.device_id)
        self._sync_context_result()
        return self.result.device_id

    def _ensure_auth_session_logging_id(self) -> str:
        """每次注册事务一个 auth_session_logging_id：先导序列与 signin 共用同一个值。"""
        value = str(self._ensure_registration_context().auth_session_logging_id or '').strip()
        self._auth_session_logging_id = value
        self._sync_context_result()
        return value

    def _bootstrap_requirements_p(self, *, context_name: str='top_level', page_url: str='https://chatgpt.com/') -> str:
        """Generate one SDK requirements p for a ChatGPT bootstrap endpoint."""
        device_id = self._ensure_device_id()
        context_state = self._sentinel_context_state(context_name)
        try:
            from sentinel_quickjs import get_sentinel_requirements_via_quickjs
            return str(get_sentinel_requirements_via_quickjs(self.session, device_id, flow='authorize_continue', sentinel_sid=str(context_state.get('sid') or device_id), sentinel_context=context_name, sentinel_version=self._get_env('OPENAI_SENTINEL_VERSION', ''), page_url=page_url, sdk_evidence_callback=self._record_sdk_evidence, **self._sentinel_fp_kwargs()) or '')
        except Exception as exc:
            logger.debug('bootstrap requirements p 获取失败（忽略）: %s', exc)
            return ''

    def _protocol_bootstrap_request(self, label: str, method: str, url: str, *, referer: str, json_body: Any=None, timeout: float=20):
        """Run one observed bootstrap request without creating synthetic RUM."""
        try:
            headers = self._common_headers(referer)
            kwargs: dict[str, Any] = {'headers': headers, 'timeout': timeout}
            if json_body is not None:
                headers['Content-Type'] = 'application/json'
                kwargs['json'] = json_body
            response = getattr(self.session, method.lower())(url, **kwargs)
            self._trace_http(label, response)
            return response
        except Exception as exc:
            logger.debug('%s 失败（忽略）: %s', label, exc)
            return None

    def _protocol_har_bootstrap(self, email: str) -> None:
        """Selective anonymous bootstrap observed in the supplied HAR."""
        del email
        if not self._env_flag('OPENAI_PROTOCOL_BOOTSTRAP', '0'):
            return
        base = 'https://chatgpt.com'
        referer = f'{base}/auth/login'
        self._protocol_bootstrap_request('protocol_bootstrap_connectivity_probe', 'HEAD', f'{base}/unauth-mweb/connectivity-probe', referer=referer, timeout=10)
        self._protocol_bootstrap_request('protocol_bootstrap_beacons_home', 'GET', f'{base}/backend-anon/beacons/home', referer=referer)
        self._protocol_bootstrap_request('protocol_bootstrap_handoff_assets', 'GET', f'{base}/_mobile/handoff-assets', referer=referer)
        p = self._bootstrap_requirements_p(page_url=referer)
        if p:
            self._protocol_bootstrap_request('protocol_bootstrap_chat_requirements_prepare', 'POST', f'{base}/unauth-mweb/sentinel/chat-requirements/prepare', referer=referer, json_body={'p': p})
        logging_id = self._ensure_auth_session_logging_id()
        self._protocol_bootstrap_request('protocol_bootstrap_auth_handoff', 'POST', f'{base}/unauth-mweb/auth/handoff', referer=f'{base}/', json_body={'authSessionLoggingId': logging_id, 'authenticationStarted': True})
        self._protocol_bootstrap_request('protocol_bootstrap_ces_settings', 'GET', f'{base}/ces/v1/projects/oai/settings', referer=referer)
        self._protocol_bootstrap_request('protocol_bootstrap_anon_accounts_check', 'GET', f'{base}/backend-anon/accounts/check/v4-2023-04-27', referer=referer)
        self._protocol_bootstrap_request('protocol_bootstrap_anon_me', 'GET', f'{base}/backend-anon/me', referer=referer)
        self._protocol_bootstrap_request('protocol_bootstrap_providers', 'GET', f'{base}/api/auth/providers', referer=referer)

    def _protocol_authenticated_bootstrap(self) -> None:
        """Small authenticated ChatGPT bootstrap after NextAuth session exists."""
        if not self._env_flag('OPENAI_PROTOCOL_BOOTSTRAP', '0'):
            return
        base = 'https://chatgpt.com'
        referer = f'{base}/'
        for path in ('/backend-api/accounts/optimized/check', '/backend-api/me', '/backend-api/accounts/check/v4-2023-04-27', '/backend-api/settings/user', '/backend-api/system_hints?mode=basic', '/backend-api/models'):
            self._protocol_bootstrap_request('protocol_authenticated_bootstrap' + path.split('?', 1)[0].replace('/', '_'), 'GET', f'{base}{path}', referer=referer)
        p = self._bootstrap_requirements_p(page_url=referer)
        if not p:
            return
        prepare = self._protocol_bootstrap_request('protocol_authenticated_chat_requirements_prepare', 'POST', f'{base}/backend-api/sentinel/chat-requirements/prepare', referer=referer, json_body={'p': p})
        try:
            data = prepare.json() if prepare is not None else {}
        except Exception:
            data = {}
        if not isinstance(data, dict):
            return
        prepare_token = data.get('prepare_token') or data.get('token') or data.get('c')
        if not prepare_token:
            return
        payload: dict[str, Any] = {'prepare_token': prepare_token}
        for key in ('proofofwork', 'turnstile'):
            if data.get(key):
                payload[key] = data[key]
        self._protocol_bootstrap_request('protocol_authenticated_chat_requirements_finalize', 'POST', f'{base}/backend-api/sentinel/chat-requirements/finalize', referer=referer, json_body=payload)

    def _protocol_prelude(self, email: str) -> None:
        """对齐 email-protocol-register 的页面入口先导（OPENAI_PROTOCOL_PRELUDE=1 开启）。

        顺序与参考实现一致：auth handoff → /auth/login_with 页面 →
        匿名会话链（obi sync-token / handoff-assets / backend-anon check /
        anon me / chat-requirements prepare）→ /api/auth/providers。
        全部 fail-soft：任何一步失败只记 debug，不阻断注册主流程。
        """
        if not self._env_flag('OPENAI_PROTOCOL_PRELUDE', '0'):
            return
        base = 'https://chatgpt.com'
        did = self._ensure_device_id()
        logging_id = self._ensure_auth_session_logging_id()
        try:
            handoff_headers = self._common_headers(f'{base}/')
            handoff_headers['Content-Type'] = 'application/json'
            handoff = self.session.post(f'{base}/unauth-mweb/auth/handoff', headers=handoff_headers, json={'authSessionLoggingId': logging_id, 'authenticationStarted': True}, timeout=20, allow_redirects=False)
            self._trace_http('protocol_prelude_handoff', handoff)
        except Exception as e:
            logger.debug('protocol prelude handoff 失败（忽略）: %s', e)
        login_page_url = f'{base}/auth/login_with?' + urlencode({'callback_path': '/', 'screen_hint': 'login_or_signup', 'login_hint': email, 'auth_session_logging_id': logging_id, 'ext-oai-did': did})
        try:
            nav_headers = self._common_headers(f'{base}/')
            nav_headers.update({'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8', 'Sec-Fetch-Dest': 'document', 'Sec-Fetch-Mode': 'navigate', 'Sec-Fetch-Site': 'same-origin', 'Upgrade-Insecure-Requests': '1', 'priority': 'u=0, i'})
            login_resp = self.session.get(login_page_url, headers=nav_headers, timeout=25)
            self._trace_http('protocol_prelude_login_with', login_resp)
        except Exception as e:
            logger.debug('protocol prelude login_with 失败（忽略）: %s', e)
        check_url = f'{base}/backend-anon/accounts/check/v4-2023-04-27'
        tz_name = str((getattr(self, '_fingerprint', {}) or {}).get('timezone') or '').strip()
        if tz_name:
            try:
                from datetime import datetime as _dt
                from datetime import timedelta as _td
                from zoneinfo import ZoneInfo
                offset_min = int((_dt.now(ZoneInfo(tz_name)).utcoffset() or _td()).total_seconds() // 60)
                check_url += f'?timezone_offset_min={offset_min}'
            except Exception:
                pass
        anon_calls = (('POST', f'{base}/backend-anon/bazaar/obi/sync-token', 'protocol_prelude_obi'), ('GET', f'{base}/_mobile/handoff-assets', 'protocol_prelude_handoff_assets'), ('GET', check_url, 'protocol_prelude_accounts_check'), ('GET', f'{base}/backend-anon/me', 'protocol_prelude_anon_me'), ('POST', f'{base}/backend-anon/sentinel/chat-requirements/prepare', 'protocol_prelude_chat_requirements'))
        for method, url, step in anon_calls:
            try:
                headers = self._common_headers(login_page_url)
                kwargs = {'headers': headers, 'timeout': 20}
                if method == 'POST':
                    headers['Content-Type'] = 'application/json'
                    resp = self.session.post(url, **kwargs)
                else:
                    resp = self.session.get(url, **kwargs)
                self._trace_http(step, resp)
            except Exception as e:
                logger.debug('%s 失败（忽略）: %s', step, e)
        try:
            providers = self.session.get(f'{base}/api/auth/providers', headers=self._common_headers(login_page_url), timeout=20)
            self._trace_http('protocol_prelude_providers', providers)
        except Exception as e:
            logger.debug('protocol prelude providers 失败（忽略）: %s', e)

    def check_proxy(self) -> bool:
        logger.info('检查网络连通性...')
        try:
            resp = self.session.get('https://cloudflare.com/cdn-cgi/trace', timeout=15)
            if resp.status_code == 200:
                loc = re.search('loc=(\\w+)', resp.text)
                ip = re.search('ip=([^\\n]+)', resp.text)
                country_code = loc.group(1) if loc else ''
                logger.info(f'网络正常 - IP: {(ip.group(1) if ip else 'N/A')}, 地区: {country_code or 'N/A'}')
                if country_code and country_code != self._country_code:
                    previous = self.result
                    context = RegistrationContext.create(country_code=country_code, reason=f'{self._ensure_registration_context().context_reason}:proxy_country_resolution')
                    context.supersedes_context_id = self._ensure_registration_context().context_id
                    self._replace_registration_context(context, preserve_email=previous.email, preserve_password=previous.password, preserve_totp_secret=previous.totp_secret)
                    self._tls_attempted_targets = {context.tls_target}
                    logger.info('出口国家确定后已原子重建注册上下文: country=%s tls=%s', country_code, context.tls_target)
            else:
                logger.warning(f'网络探测异常: cloudflare trace {resp.status_code}')
            return True
        except Exception as e:
            logger.error(f'网络检查失败: {e}')
        return False

    def check_credential_login_route(self, expected_ip: str='') -> dict:
        """在同一个登录 session 上严格验证 Cloudflare、cleanip、ChatGPT 与 Auth。"""
        logger.info('登录线路预检：Cloudflare → cleanip；随后直接进入 CSRF/OAuth/Sentinel 实际接口')
        trace = self.session.get('https://cloudflare.com/cdn-cgi/trace', timeout=15)
        if trace.status_code != 200:
            raise RuntimeError(f'登录线路预检失败：Cloudflare HTTP {trace.status_code}')
        loc_match = re.search('loc=(\\w+)', trace.text or '')
        ip_match = re.search('ip=([^\\n]+)', trace.text or '')
        actual_ip = (ip_match.group(1) if ip_match else '').strip()
        country_code = (loc_match.group(1) if loc_match else '').strip().upper()
        if not actual_ip:
            raise RuntimeError('登录线路预检失败：Cloudflare 未返回出口 IP')
        quality_grade = ''
        quality_score = None
        ip_changed = bool(str(expected_ip or '').strip() and actual_ip != str(expected_ip).strip())
        if ip_changed:
            logger.warning('代理出口已变化：缓存=%s 当前=%s，正在通过 cleanip 重新评分', expected_ip, actual_ip)
            clean = self.session.get('https://cleanip.io/api/v2/me', timeout=15)
            if clean.status_code != 200:
                raise RuntimeError(f'代理出口变化后 cleanip 重评分失败：HTTP {clean.status_code}')
            try:
                payload = clean.json()
                purity = payload.get('purity') or {}
                quality_grade = str(purity.get('grade') or '').strip().upper()
                quality_score = float(purity.get('score'))
                clean_ip = str(payload.get('ip') or '').strip()
            except Exception as exc:
                raise RuntimeError(f'代理出口变化后 cleanip 响应无效：{exc}') from exc
            if clean_ip != actual_ip:
                raise RuntimeError(f'代理出口不稳定：Cloudflare={actual_ip} cleanip={clean_ip or '空'}')
            if quality_score < 93:
                raise RuntimeError(f'代理出口变化后质量低于 93：{quality_grade or '未知'} {quality_score:g} 分')
        logger.info('登录线路网络预检通过 - IP: %s 地区: %s%s；开始实际登录接口', actual_ip, country_code or 'N/A', f' cleanip={quality_grade} {quality_score:g}' if quality_score is not None else '')
        return {'ip': actual_ip, 'country': country_code, 'ip_changed': ip_changed, 'quality_grade': quality_grade, 'quality_score': quality_score}

    def get_csrf_token(self) -> str:
        logger.info('[1/10] 获取 CSRF Token...')
        context_id = str(self._ensure_registration_context().context_id or '')
        cached = str(getattr(self, '_csrf_token_cache', '') or '')
        if cached and str(getattr(self, '_csrf_cache_context_id', '') or '') == context_id:
            logger.debug('复用当前注册上下文的 CSRF Token，跳过重复请求')
            self.result.csrf_token = cached
            return cached
        for attempt in range(3):
            headers = self._common_headers('https://chatgpt.com/auth/login')
            try:
                resp = self.session.get('https://chatgpt.com/api/auth/csrf', headers=headers, timeout=30)
            except Exception as e:
                if self._is_tls_error(e) and self._rotate_impersonate_session():
                    continue
                if self._is_tls_error(e):
                    raise RuntimeError('chatgpt.com TLS 握手失败，当前网络无法建立到 /api/auth/csrf 的 HTTPS 连接。请切换可直连 chatgpt.com 的网络或在界面中配置可用代理后重试。') from e
                raise
            if resp.status_code == 403 and attempt < 2:
                wait = (attempt + 1) * 5
                logger.warning(f'Cloudflare 403, {wait}s 后重试 ({attempt + 1}/3)...')
                import time
                time.sleep(wait)
                continue
            resp.raise_for_status()
            break
        self._trace_http('chatgpt_csrf', resp)
        csrf = resp.json().get('csrfToken', '')
        if not csrf:
            raise RuntimeError('CSRF Token 获取失败')
        self._csrf_token_cache = str(csrf)
        self._csrf_cache_context_id = str(self._ensure_registration_context().context_id or '')
        self.result.csrf_token = csrf
        logger.debug(f'CSRF Token: {csrf[:20]}...')
        return csrf

    def get_auth_url(self, csrf_token: str, email: str='') -> str:
        logger.info('[2/10] 获取 OpenAI 授权地址...')
        context_id = str(self._ensure_registration_context().context_id or '')
        cache_key = (context_id, str(csrf_token or ''), str(email or '').strip().lower())
        cached_auth_url = str(getattr(self, '_auth_url_cache', '') or '')
        if email and cached_auth_url and (getattr(self, '_auth_url_cache_key', None) == cache_key):
            logger.debug('复用当前注册上下文的 signin/openai URL，跳过重复请求')
            return cached_auth_url
        headers = self._common_headers('https://chatgpt.com/auth/login')
        headers['Content-Type'] = 'application/x-www-form-urlencoded'
        self._ensure_device_id()
        query_params: dict[str, str] = {'prompt': 'login', 'screen_hint': 'login_or_signup', 'ext-oai-did': self.result.device_id, 'auth_session_logging_id': self._ensure_auth_session_logging_id(), 'ext-passkey-client-capabilities': '1111'}
        if email:
            query_params['login_hint'] = email
        signin_url = f'https://chatgpt.com/api/auth/signin/openai?{urlencode(query_params)}'
        resp = self.session.post(signin_url, headers=headers, data={'csrfToken': csrf_token, 'callbackUrl': 'https://chatgpt.com/', 'json': 'true'}, timeout=30)
        resp.raise_for_status()
        self._trace_http('chatgpt_signin_openai', resp)
        auth_url = resp.json().get('url', '')
        if not auth_url:
            raise RuntimeError('Auth URL 获取失败')
        self._remember_oauth_params(auth_url)
        auth_url = self._inject_pkce_into_auth_url(auth_url)
        self._remember_oauth_params(auth_url)
        if email:
            self._auth_url_cache_key = cache_key
            self._auth_url_cache = auth_url
        logger.debug(f'Auth URL: {auth_url[:80]}...')
        return auth_url

    def auth_oauth_init(self, auth_url: str) -> str:
        logger.info('[3/10] OAuth 初始化...')
        context_id = str(self._ensure_registration_context().context_id or '')
        init_key = (context_id, str(auth_url or ''))
        if getattr(self, '_auth_init_cache_key', None) == init_key and str(getattr(self, '_auth_init_device_id', '') or '').strip():
            logger.debug('复用当前注册上下文的 authorize 初始化结果，跳过重复请求')
            return str(self._auth_init_device_id)
        headers = {'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8', 'Referer': 'https://chatgpt.com/auth/login', 'User-Agent': self._ua}
        resp = self.session.get(auth_url, headers=headers, timeout=30, allow_redirects=True)
        self._trace_http('auth_oauth_init', resp)
        device_id = ''
        for cookie in self.session.cookies:
            if hasattr(cookie, 'name'):
                if cookie.name == 'oai-did':
                    device_id = cookie.value
                    break
            elif isinstance(cookie, str) and cookie == 'oai-did':
                device_id = self.session.cookies.get('oai-did', '')
                break
        if not device_id:
            try:
                device_id = self.session.cookies.get('oai-did', '')
            except Exception:
                pass
        if not device_id:
            m = re.search('oai-did["\\s:=]+([a-f0-9-]{36})', resp.text)
            if m:
                device_id = m.group(1)
        if not device_id:
            device_id = str(uuid.uuid4())
            logger.warning(f'未从响应中获取 device_id，使用生成值: {device_id}')
        device_id = self._settle_device_id(device_id)
        self._auth_init_cache_key = init_key
        self._auth_init_device_id = device_id
        logger.debug(f'Device ID: {device_id}')
        return device_id

    def _sentinel_fp_kwargs(self) -> dict:
        """从 self._fingerprint 抽出 sentinel 需要的指纹/硬件字段。

        保证 4 处 sentinel 调用（authorize_continue / username_password_create /
        create_account 等）用的是同一套一致画像——UA↔platform↔vendor↔硬件全程不变。
        """
        fp = self._fingerprint or {}
        runtime_profile = getattr(self.session, '_open_protocol_fingerprint_profile', {})
        if not isinstance(runtime_profile, dict):
            runtime_profile = {}
        runtime_screen = runtime_profile.get('screen')
        if not isinstance(runtime_screen, dict):
            raw_screen = str(fp.get('screen') or '1920x1080')
            try:
                screen_w, screen_h = (int(v) for v in raw_screen.lower().split('x', 1))
            except Exception:
                screen_w, screen_h = (1920, 1080)
            runtime_screen = {'width': screen_w, 'height': screen_h, 'availWidth': screen_w, 'availHeight': max(0, screen_h - 40), 'innerWidth': max(320, screen_w - 17), 'innerHeight': max(240, screen_h - 111), 'outerWidth': screen_w, 'outerHeight': screen_h, 'devicePixelRatio': float(fp.get('device_pixel_ratio') or 1.0), 'colorDepth': 24}
        navigator_profile = runtime_profile.get('navigator')
        if not isinstance(navigator_profile, dict):
            navigator_profile = {}
        languages = runtime_profile.get('languages') or navigator_profile.get('languages')
        if not isinstance(languages, list):
            languages = []
        return {'user_agent': self._ua, 'sec_ch_ua': fp.get('sec_ch_ua', ''), 'sec_ch_ua_platform': fp.get('sec_ch_ua_platform', ''), 'sec_ch_ua_mobile': fp.get('sec_ch_ua_mobile', ''), 'sec_ch_ua_full_version_list': fp.get('sec_ch_ua_full_version_list', ''), 'sec_ch_ua_arch': fp.get('sec_ch_ua_arch', ''), 'sec_ch_ua_bitness': fp.get('sec_ch_ua_bitness', ''), 'sec_ch_ua_model': fp.get('sec_ch_ua_model', ''), 'sec_ch_ua_platform_version': fp.get('sec_ch_ua_platform_version', ''), 'screen': fp.get('screen', ''), 'lang': fp.get('lang', ''), 'lang_full': fp.get('lang_full', ''), 'browser_type': fp.get('browser_type', ''), 'navigator_platform': fp.get('navigator_platform', ''), 'navigator_vendor': fp.get('navigator_vendor'), 'hardware_concurrency': fp.get('hardware_concurrency', 0), 'device_memory': fp.get('device_memory'), 'max_touch_points': fp.get('max_touch_points', 0), 'device_pixel_ratio': fp.get('device_pixel_ratio', 0.0), 'timezone': fp.get('timezone', ''), 'screen_width': runtime_screen.get('width', 1920), 'screen_height': runtime_screen.get('height', 1080), 'screen_avail_width': runtime_screen.get('availWidth', runtime_screen.get('width', 1920)), 'screen_avail_height': runtime_screen.get('availHeight', runtime_screen.get('height', 1080)), 'inner_width': runtime_screen.get('innerWidth', runtime_screen.get('width', 1920)), 'inner_height': runtime_screen.get('innerHeight', runtime_screen.get('height', 1080)), 'outer_width': runtime_screen.get('outerWidth', runtime_screen.get('width', 1920)), 'outer_height': runtime_screen.get('outerHeight', runtime_screen.get('height', 1080)), 'color_depth': runtime_screen.get('colorDepth', 24), 'js_heap_size_limit': runtime_profile.get('js_heap_size_limit', 4294967296), 'navigator_languages': languages}

    def get_sentinel_token(self, device_id: str, flow: str='authorize_continue', *, require_so_token: bool=True, context_name: str='', request_p: str='') -> str:
        logger.info('[4/10] 获取 Sentinel Token (PoW)...')
        from sentinel import get_sentinel_token
        flow_name = str(flow or 'authorize_continue').strip()
        sentinel_context = str(context_name or self._sentinel_context_name(flow_name)).strip().lower()
        context_state = self._sentinel_context_state(sentinel_context)
        token_key = (sentinel_context, flow_name)
        records = getattr(self, '_sentinel_token_records', None)
        if not isinstance(records, dict):
            records = {}
            self._sentinel_token_records = records
        records.pop(token_key, None)
        page_url = {'authorize_continue': 'https://auth.openai.com/create-account', 'username_password_create': 'https://auth.openai.com/create-account/password', 'email_otp_validate': 'https://auth.openai.com/email-verification', 'oauth_create_account': 'https://auth.openai.com/about-you', 'create_account': 'https://auth.openai.com/about-you'}.get(flow_name, 'https://auth.openai.com/')
        result = get_sentinel_token(self.session, device_id=device_id, flow=flow_name, sentinel_sid=str(context_state.get('sid') or device_id or ''), request_p=str(request_p or ''), sentinel_context=sentinel_context, sentinel_version=self._get_env('OPENAI_SENTINEL_VERSION', ''), sentinel_sdk_url=self._get_env('OPENAI_SENTINEL_SDK_URL', ''), require_so_token=require_so_token, page_url=page_url, sdk_evidence_callback=self._record_sdk_evidence, **self._sentinel_fp_kwargs())
        token, so_token = result
        request_p_map = getattr(self.session, '_open_protocol_sentinel_request_p', {})
        if isinstance(request_p_map, dict):
            effective_request_p = str(request_p_map.get(sentinel_context) or request_p or '')
        else:
            effective_request_p = str(request_p or '')
        if effective_request_p:
            request_ps = getattr(self, '_sentinel_request_ps', None)
            if not isinstance(request_ps, dict):
                request_ps = {}
                self._sentinel_request_ps = request_ps
            request_ps[sentinel_context] = effective_request_p
        self._last_sentinel_token = token or ''
        self._last_sentinel_request_so_token = so_token or ''
        self._last_sentinel_so_token = so_token or ''
        self._remember_sentinel_record(context_name=sentinel_context, flow=flow_name, token=token or '', so_token=so_token or '', request_p=effective_request_p)
        logger.debug('Sentinel Token 获取成功')
        return token

    def _prepare_password_sentinel_bundle(self, device_id: str) -> dict[str, str]:
        """Initialize the password iframe context with one p and three flows.

        The top-level authorize context keeps its own SID.  The password page
        owns a second SID; its email_otp_validate, username_password_create,
        and authorize_continue probes deliberately reuse one request_p.
        Only the username_password_create record is returned for user/register.
        """
        context_name = 'password'
        first_flow = 'email_otp_validate'
        self.get_sentinel_token(device_id, flow=first_flow, context_name=context_name, require_so_token=False)
        shared_p = str(getattr(self, '_sentinel_request_ps', {}).get(context_name) or '')
        if not shared_p:
            raise RuntimeError('密码页 Sentinel bundle 未取得共享 request_p')
        self.get_sentinel_token(device_id, flow='username_password_create', context_name=context_name, request_p=shared_p, require_so_token=False)
        self.get_sentinel_token(device_id, flow='authorize_continue', context_name=context_name, request_p=shared_p, require_so_token=False)
        record = self._sentinel_record_for('username_password_create', context_name=context_name) or {}
        return {'token': str(record.get('token') or ''), 'so_token': str(record.get('so_token') or ''), 'request_p': shared_p, 'sid': str(self._sentinel_context_state(context_name).get('sid') or '')}

    def authorize_continue(self, email: str, sentinel_token: str, screen_hint: str='signup', referer: str='https://auth.openai.com/create-account', trace_step: str='') -> dict:
        """调用 /api/accounts/authorize/continue，返回 JSON。"""
        context_id = str(self._ensure_registration_context().context_id or '')
        cache_key = (context_id, str(email or '').strip().lower(), str(screen_hint or 'signup').strip().lower(), str(getattr(self, '_oauth_state', '') or getattr(self, '_oauth_auth_url', '') or ''))
        cache = getattr(self, '_authorize_continue_cache', None)
        if not isinstance(cache, dict):
            cache = {}
            self._authorize_continue_cache = cache
        cached = cache.get(cache_key)
        if isinstance(cached, dict):
            logger.debug('复用 authorize/continue 结果，跳过重复请求: screen_hint=%s', screen_hint)
            return copy.deepcopy(cached)
        headers = self._common_headers(referer)
        headers['Content-Type'] = 'application/json'
        self._apply_sentinel_headers(headers, flow='authorize_continue', context_name='top_level', token=sentinel_token, allow_legacy_token=True)
        payload = {'username': {'value': email, 'kind': 'email'}, 'screen_hint': screen_hint}
        resp = self.session.post('https://auth.openai.com/api/accounts/authorize/continue', headers=headers, json=payload, timeout=30)
        self._trace_http(trace_step or f'authorize_continue_{screen_hint}', resp)
        if resp.status_code != 200:
            body = (resp.text or '')[:360]
            req_id = (resp.headers.get('x-request-id', '') or '')[:80]
            ct = (resp.headers.get('Content-Type', '') or '')[:60]
            logger.debug('authorize/continue 非 200: status=%s screen_hint=%s req_id=%s content_type=%s body=%r', resp.status_code, screen_hint, req_id, ct, body)
            error_code = ''
            try:
                error_data = resp.json() or {}
                if isinstance(error_data, dict):
                    error_obj = error_data.get('error') or {}
                    if isinstance(error_obj, dict):
                        error_code = str(error_obj.get('code') or '').strip().lower()
            except Exception:
                pass
            if error_code == 'invalid_state' or 'invalid_state' in body.lower():
                error = RuntimeError('登录状态已失效，请重新开始')
                error.error_code = 'invalid_state'
                raise error
            raise RuntimeError(f'登录请求未通过（HTTP {resp.status_code}）')
        try:
            data = resp.json() if resp is not None else {}
            if isinstance(data, dict):
                cache[cache_key] = copy.deepcopy(data)
            return data
        except Exception:
            return {}

    def signup(self, email: str, sentinel_token: str) -> bool:
        raise RuntimeError('unsupported_action')

    def register_password(self, email: str) -> bool:
        raise RuntimeError('unsupported_action')

    def send_otp(self, referer: str='https://auth.openai.com/create-account/password'):
        raise RuntimeError('unsupported_action')

    def send_passwordless_otp(self, referer: str='https://auth.openai.com/create-account/password') -> bool:
        raise RuntimeError('unsupported_action')

    def resend_otp(self, referer: str='https://auth.openai.com/email-verification') -> bool:
        raise RuntimeError('unsupported_action')

    def kickoff_otp_delivery(self, mode: str='') -> bool:
        raise RuntimeError('unsupported_action')

    @staticmethod
    def _default_password_from_email(email: str) -> str:
        pwd = (email or '').replace('@', '')
        if len(pwd) < 8:
            pwd = f'{pwd}2026OpenAI'
        return pwd

    def _login_password_candidate(self, email: str, supplied: str='') -> tuple[str, bool]:
        """返回登录候选密码和“是否为邮箱规则猜测值”。

        已确认来源优先级：显式传入 → 当前 flow → 本地凭证回调。只有三者都为空
        才使用历史兼容的邮箱规则猜测；猜测值必须等 password/verify 成功后才能落入
        result，避免一次 401 覆盖数据库里的真实密码。
        """
        known = (supplied or '').strip() or (self.result.password or '').strip()
        if not known and self._account_callback:
            try:
                cred = self._account_callback(email)
                known = str((cred or {}).get('password') or '').strip()
                if known:
                    logger.info('已从本地凭证加载登录密码')
            except Exception as e:
                logger.warning(f'account_callback 加载密码异常: {e}')
        if known:
            return (known, False)
        return (self._default_password_from_email(email), True)

    @staticmethod
    def _random_password(length: int=16) -> str:
        import string
        upper = string.ascii_uppercase
        lower = string.ascii_lowercase
        digits = string.digits
        special = '!@#$%^&*'
        must = [random.choice(upper), random.choice(lower), random.choice(digits), random.choice(special)]
        all_chars = upper + lower + digits + special
        rest = random.choices(all_chars, k=length - len(must))
        pwd_list = must + rest
        random.shuffle(pwd_list)
        return ''.join(pwd_list)

    def login_password_verify(self, password: str) -> dict:
        """已有账号密码登录一步（/password/verify）。"""
        headers = self._common_headers('https://auth.openai.com/log-in/password')
        headers['Content-Type'] = 'application/json'
        if self._last_sentinel_token:
            headers['openai-sentinel-token'] = self._last_sentinel_token
        if getattr(self, '_last_sentinel_so_token', ''):
            headers['openai-sentinel-so-token'] = self._last_sentinel_so_token
        resp = self.session.post('https://auth.openai.com/api/accounts/password/verify', headers=headers, json={'password': password}, timeout=30)
        self._trace_http('login_password_verify', resp)
        if resp.status_code != 200:
            body = (resp.text or '')[:260]
            raise RuntimeError(f'密码登录失败: {resp.status_code} - {body}')
        try:
            return resp.json()
        except Exception:
            return {}

    def submit_mfa_totp(self, totp_code: str, challenge_id: str) -> dict:
        """提交 TOTP 2FA 验证码（已有账号登录时，密码验证后进入 mfa-challenge 状态）。

        Args:
            totp_code: 6 位 TOTP 动态码
            challenge_id: 从 continue_url 提取的 challenge ID（如 /mfa-challenge/6a76f2e8...）

        Returns:
            服务端响应 dict，包含 continue_url 指向 callback
        """
        headers = self._common_headers('https://auth.openai.com/mfa-challenge')
        headers['Content-Type'] = 'application/json'
        if self._last_sentinel_token:
            headers['openai-sentinel-token'] = self._last_sentinel_token
        if getattr(self, '_last_sentinel_so_token', ''):
            headers['openai-sentinel-so-token'] = self._last_sentinel_so_token
        resp = self.session.post('https://auth.openai.com/api/accounts/mfa/verify', headers=headers, json={'code': totp_code, 'type': 'totp', 'id': challenge_id}, timeout=30)
        self._trace_http('submit_mfa_totp', resp)
        if resp.status_code != 200:
            body = (resp.text or '')[:260]
            raise RuntimeError(f'TOTP 验证失败: {resp.status_code} - {body}')
        try:
            return resp.json()
        except Exception:
            return {}

    def verify_otp(self, otp_code: str) -> dict:
        raise RuntimeError('unsupported_action')

    def create_account(self) -> str:
        raise RuntimeError('unsupported_action')

    def _extract_workspace_id(self) -> str:
        """从 cookie 中提取 workspace_id"""
        try:
            auth_session = self.session.cookies.get('oai-client-auth-session', '')
            if auth_session:
                parts = auth_session.split('.')
                for idx in range(min(2, len(parts))):
                    segment = (parts[idx] or '').strip()
                    if not segment:
                        continue
                    payload_b64 = segment + '=' * (-len(segment) % 4)
                    decoded = json.loads(base64.urlsafe_b64decode(payload_b64.encode('utf-8')).decode('utf-8'))
                    if not isinstance(decoded, dict):
                        continue
                    wid = (decoded.get('workspace_id', '') or '').strip()
                    if wid:
                        return wid
                    workspaces = decoded.get('workspaces', [])
                    if isinstance(workspaces, list):
                        for it in workspaces:
                            if isinstance(it, dict):
                                wid = (it.get('id', '') or '').strip()
                                if wid:
                                    return wid
        except Exception:
            pass
        return ''

    def _workspace_select(self, workspace_id: str) -> str:
        logger.info('执行 workspace 选择...')
        headers = self._common_headers('https://auth.openai.com/sign-in-with-chatgpt/codex/consent')
        headers['Content-Type'] = 'application/json'
        resp = self.session.post('https://auth.openai.com/api/accounts/workspace/select', headers=headers, json={'workspace_id': workspace_id}, timeout=30)
        self._trace_http('workspace_select', resp)
        return resp.json().get('continue_url', '') if resp.status_code == 200 else ''

    def _choose_account_select(self, html_text: str, current_url: str) -> str:
        """处理 /choose-an-account 多账号选择页（react-router SSR）。

        HTML 里 streamController.enqueue 注入 `unified_sessions[].id` (us_*) 和
        `session_id` (authsess_*)。这里 regex 抽 us_*，按 react-router action 惯例
        POST 回 /choose-an-account，并 fallback 试几个候选 JSON endpoint。
        返回 next continue_url 或空串。
        """
        m = re.search('us_[A-Za-z0-9]{16,}', html_text or '')
        if not m:
            logger.warning('/choose-an-account HTML 里没找到 us_* session id, 跳过')
            return ''
        session_id = m.group(0)
        logger.debug(f'/choose-an-account 选 session_id={session_id}')
        headers = self._common_headers('https://auth.openai.com/choose-an-account')
        headers['Origin'] = 'https://auth.openai.com'
        candidates = [('POST', 'https://auth.openai.com/api/accounts/session/select', {'session_id': session_id}, 'json'), ('POST', 'https://auth.openai.com/choose-an-account', {'intent': 'select', 'session_id': session_id}, 'form')]
        for method, url, body, kind in candidates:
            try:
                h = dict(headers)
                if kind == 'json':
                    h['Content-Type'] = 'application/json'
                    h['Accept'] = 'application/json'
                    resp = self.session.post(url, headers=h, json=body, timeout=30)
                else:
                    h['Content-Type'] = 'application/x-www-form-urlencoded'
                    h['Accept'] = 'application/json, text/html;q=0.9'
                    body_str = '&'.join((f'{k}={v}' for k, v in body.items()))
                    resp = self.session.post(url, headers=h, data=body_str, timeout=30)
                self._trace_http(f'choose_account_try_{kind}_{url.rsplit('/', 1)[-1][:30]}', resp)
                status = getattr(resp, 'status_code', 0)
                snippet = (getattr(resp, 'text', '') or '')[:240].replace('\n', ' ')
                loc = (getattr(resp, 'headers', {}) or {}).get('Location', '') or (getattr(resp, 'headers', {}) or {}).get('location', '') or ''
                pass
                if status in (200, 201, 302, 303):
                    next_url = ''
                    try:
                        j = resp.json() if resp is not None else {}
                        next_url = j.get('continue_url', '') if isinstance(j, dict) else ''
                    except Exception:
                        pass
                    if not next_url and loc:
                        next_url = loc
                    if next_url:
                        logger.debug(f'choose-an-account 选号成功 endpoint={url} next={next_url[:120]}')
                        return next_url
                    if status == 200:
                        logger.debug(f'choose-an-account POST {url} 200 OK 无 continue_url，假定 cookie 已 set')
                        return current_url
            except Exception as e:
                pass
                continue
        logger.warning('/choose-an-account 全部候选 endpoint 都失败')
        return ''

    def _normalize_continue_url(self, continue_url: str) -> str:
        """
        标准化 continue_url：
        1) 相对路径 -> 绝对路径
        2) workspace 页面 -> 调用 workspace/select 取下一跳
        """
        if not continue_url:
            return ''
        out = continue_url.strip()
        if out.startswith('/'):
            out = urljoin('https://auth.openai.com', out)
        if '/workspace' in out:
            workspace_id = self._extract_workspace_id() or self._extract_query_first(out, ['workspace_id', 'id'])
            if workspace_id:
                logger.info('检测到 workspace 页面，尝试 workspace/select: workspace_id=%s', workspace_id)
                next_url = self._workspace_select(workspace_id)
                if next_url:
                    out = next_url
        return out

    @staticmethod
    def _extract_workspace_id_from_html(html_text: str) -> str:
        """从 workspace 页面 HTML 文本中提取 workspace_id（兜底）。"""
        if not html_text:
            return ''
        try:
            text = html_text.replace('\\"', '"')
            patterns = ['workspaces".{0,1600}?"id","([0-9a-fA-F-]{36})"', '"workspace_id"\\s*:\\s*"([0-9a-fA-F-]{36})"', '"workspaceId"\\s*:\\s*"([0-9a-fA-F-]{36})"']
            for p in patterns:
                m = re.search(p, text, flags=re.DOTALL | re.IGNORECASE)
                if m:
                    return (m.group(1) or '').strip()
        except Exception:
            return ''
        return ''

    def follow_redirect_chain(self, start_url: str, *, defer_callback: bool=False) -> tuple[str, str]:
        """手动跟踪重定向，返回 (callback_url, final_url)"""
        logger.info('[9/10] 跟踪重定向链...')
        current_url = start_url
        callback_url = ''
        max_hops = 12
        referer = 'https://auth.openai.com/'
        for i in range(max_hops):
            if defer_callback:
                target = urlparse(current_url)
                if target.hostname == 'chatgpt.com' and target.path == '/api/auth/callback/openai':
                    callback_url = current_url
                    self._sniff_login_verifier(current_url, f'redirect_hop_{i + 1}_callback_url')
                    logger.info('捕获直接 callback URL（未消费）')
                    break
            headers = {'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8', 'Referer': referer, 'User-Agent': self._ua}
            resp = self.session.get(current_url, headers=headers, timeout=30, allow_redirects=False)
            self._trace_http(f'redirect_hop_{i + 1}', resp)
            referer = current_url
            if '/api/auth/callback/openai' in current_url:
                callback_url = current_url
                self._sniff_login_verifier(current_url, f'redirect_hop_{i + 1}_callback_url')
            if '/workspace' in current_url and resp.status_code == 200:
                workspace_id = self._extract_workspace_id() or self._extract_workspace_id_from_html(resp.text or '')
                if workspace_id:
                    logger.info('workspace 页面提取到 workspace_id=%s，尝试继续授权', workspace_id)
                    next_url = self._workspace_select(workspace_id)
                    if next_url:
                        if next_url.startswith('/'):
                            next_url = urljoin('https://auth.openai.com', next_url)
                        current_url = next_url
                        continue
            if resp.status_code in (301, 302, 303, 307, 308):
                location = resp.headers.get('Location', '')
                if not location:
                    break
                if defer_callback:
                    location = urljoin(current_url, location)
                elif location.startswith('/'):
                    parsed = urlparse(current_url)
                    location = f'{parsed.scheme}://{parsed.netloc}{location}'
                target = urlparse(location)
                is_callback = target.hostname == 'chatgpt.com' and target.path == '/api/auth/callback/openai' if defer_callback else '/api/auth/callback/openai' in location and 'code=' in location
                if is_callback:
                    callback_url = location
                    current_url = location
                    self._sniff_login_verifier(location, f'redirect_hop_{i + 1}_location_callback')
                    logger.info('捕获 callback URL（未消费）')
                    break
                current_url = location
                logger.debug(f'  重定向 {i + 1}: {current_url[:80]}...')
            else:
                break
        if not callback_url and (not current_url.rstrip('/').endswith('chatgpt.com')):
            self.session.get('https://chatgpt.com/', headers={'Referer': current_url}, timeout=30)
        logger.info(f'重定向链完成, callback: {('有' if callback_url else '无')}')
        return (callback_url, current_url)

    def _reauthorize_for_session(self, original_auth_url: str) -> str | None:
        """已有账号 OTP 验证后，重新发起 authorize 获取 callback URL"""
        if not str(original_auth_url or '').strip():
            raise RuntimeError('本轮授权地址缺失，已停止 Session 恢复')
        logger.info('[9.5/10] 重新 authorize 获取 session ...')
        try:
            from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
            parsed = urlparse(original_auth_url)
            params = parse_qs(parsed.query, keep_blank_values=True)
            params.pop('prompt', None)
            new_query = urlencode({k: v[0] for k, v in params.items()})
            authorize_url = urlunparse(parsed._replace(query=new_query))
            resp = self.session.get(authorize_url, allow_redirects=False, timeout=15)
            self._trace_http('reauthorize_start', resp)
            logger.info(f'reauthorize status={resp.status_code}')
            current_url = resp.headers.get('Location', '')
            logger.info(f'reauthorize Location: {current_url[:150]}')
            if resp.status_code in (301, 302, 303, 307, 308) and current_url:
                for hop in range(10):
                    logger.debug(f'reauthorize redirect hop {hop + 1}: {current_url[:100]}')
                    if 'code=' in current_url and 'state=' in current_url:
                        logger.info('reauthorize: 找到 callback URL')
                        return current_url
                    try:
                        hop_resp = self.session.get(current_url, allow_redirects=False, timeout=15)
                        self._trace_http(f'reauthorize_hop_{hop + 1}', hop_resp)
                        next_loc = hop_resp.headers.get('Location', '')
                        if hop_resp.status_code not in (301, 302, 303, 307, 308) or not next_loc:
                            final_url = str(getattr(hop_resp, 'url', current_url))
                            if 'code=' in final_url:
                                return final_url
                            break
                        current_url = next_loc
                        if not current_url.startswith('http'):
                            from urllib.parse import urljoin
                            current_url = urljoin(authorize_url, current_url)
                    except Exception:
                        break
            logger.warning('reauthorize: 未能获取 callback URL')
            return None
        except Exception as e:
            logger.warning(f'reauthorize 失败: {e}')
            return None

    def _extract_session_cookie(self) -> str:
        """多路兜底提取 __Secure-next-auth.session-token cookie。

        curl_cffi 在某些情况下按 domain 隔离 cookie，session.cookies.get(name) 拿不到，
        所以这里把所有 cookie 都遍历一遍，按名字精确匹配。
        """
        target = '__Secure-next-auth.session-token'
        try:
            v = self.session.cookies.get(target, '')
            if v:
                return v
        except Exception:
            pass
        try:
            for c in self.session.cookies:
                name = getattr(c, 'name', '') if hasattr(c, 'name') else str(c)
                if name == target:
                    val = getattr(c, 'value', '') or ''
                    if val:
                        return val
        except Exception:
            pass
        try:
            value = self._get_cookie_value_by_name(target)
            if value:
                return value
        except Exception:
            pass
        try:
            jar = getattr(self.session.cookies, 'jar', None)
            pairs = []
            for c in jar if jar is not None else self.session.cookies:
                pairs.append((getattr(c, 'name', ''), getattr(c, 'value', '') or ''))
            value = session_token_from_cookie_pairs(pairs)
            if value:
                logger.info('session-token 命中 NextAuth 分片 cookie，已按 .0/.1 拼接 (len=%s)', len(value))
                return value
        except Exception:
            pass
        return ''

    def get_auth_session(self, refresh: bool=False, *, observation: dict | None=None) -> tuple[str, str]:
        """获取 session_token 和 access_token。

        session_token 三路兜底（按优先级）：
          1. cookie `__Secure-next-auth.session-token`（NextAuth 数据库 session 策略）
          2. JSON 响应里的 `sessionToken` 字段（NextAuth JWT session 策略，某些路径）
          3. 兼容大小写 / 下划线变体
        access_token 取 JSON 响应里的 `accessToken`。
        """
        first_call = not getattr(self, '_auth_session_fetched', False)
        self._auth_session_fetched = True
        if first_call:
            logger.info('[10/10] 获取认证 Session...')
        headers = self._common_headers('https://chatgpt.com/')
        session_url = 'https://chatgpt.com/api/auth/session'
        if refresh:
            session_url += '?refresh=true'
        resp = self.session.get(session_url, headers=headers, timeout=30, allow_redirects=observation is None)
        if observation is not None:
            observation.update(response_evidence(resp, session_url, self.session))
            if resp.status_code != 200:
                raise RuntimeError(f'Session 接口返回 HTTP {resp.status_code}')
        self._trace_http('chatgpt_auth_session_refresh' if refresh else 'chatgpt_auth_session', resp)
        resp.raise_for_status()
        try:
            sess_json = resp.json() if resp is not None else {}
        except Exception:
            sess_json = {}
        if not isinstance(sess_json, dict):
            sess_json = {}
        cookie_st = self._extract_session_cookie()
        json_st = sess_json.get('sessionToken', '') or sess_json.get('session_token', '') or ''
        session_token = cookie_st or json_st
        access_token = sess_json.get('accessToken', '') or sess_json.get('access_token', '') or ''
        if session_token:
            self.result.session_token = session_token
        if access_token:
            self.result.access_token = access_token
        self.result.cookie_header = self._build_chatgpt_cookie_header()
        self.result.session_json = json.dumps(sess_json, ensure_ascii=False, indent=2)
        self.result.storage_state_json = json.dumps(self.export_storage_state(), ensure_ascii=False, separators=(',', ':'))
        if not self.result.auth_flow:
            self.result.auth_flow = 'protocol'
        try:
            from signal_runtime import bridge as signal_bridge
            signal_bridge.authenticated(self.session)
        except Exception:
            pass
        _log = logger.info if first_call else logger.debug
        _log(f'session: st={('有' if session_token else '无')} at={('有' if access_token else '无')}')
        return (session_token, access_token)

    def _consume_callback_for_session(self, callback_url: str) -> bool:
        """主动 GET callback URL 让 chatgpt.com NextAuth 设 session cookie。

        协议层 follow_redirect_chain 故意不消费 callback（为后续 OAuth token exchange 留 code），
        但这导致 NextAuth 永远不会写 __Secure-next-auth.session-token cookie。
        在拿不到 session_token 时主动消费一次 callback：跟随到 chatgpt.com 主页，
        服务器会 Set-Cookie session-token。
        """
        if not callback_url or 'code=' not in callback_url:
            return False
        try:
            current = callback_url
            for hop in range(8):
                resp = self.session.get(current, headers={'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8', 'Referer': 'https://auth.openai.com/', 'User-Agent': self._ua}, timeout=30, allow_redirects=False)
                self._trace_http(f'consume_callback_hop_{hop + 1}', resp)
                if resp.status_code not in (301, 302, 303, 307, 308):
                    break
                loc = (resp.headers.get('Location', '') or '').strip()
                if not loc:
                    break
                if loc.startswith('/'):
                    loc = urljoin(current, loc)
                current = loc
                parsed = urlparse(current)
                if 'chatgpt.com' in (parsed.netloc or '') and '/api/auth/callback' not in current:
                    try:
                        self.session.get(current, timeout=20, allow_redirects=True)
                    except Exception:
                        pass
                    break
            try:
                jar = getattr(self.session.cookies, 'jar', None)
                pairs = []
                for c in jar if jar is not None else self.session.cookies:
                    pairs.append((getattr(c, 'name', ''), getattr(c, 'value', '') or ''))
                return bool(session_token_from_cookie_pairs(pairs))
            except Exception:
                return bool(self.session.cookies.get('__Secure-next-auth.session-token', ''))
        except Exception as e:
            logger.warning(f'消费 callback 失败: {e}')
            return False

    def oauth_token_exchange(self, callback_url: str, continue_url: str) -> bool:
        raise RuntimeError('unsupported_action')

    def oauth_secondary_authorize_exchange(self) -> bool:
        raise RuntimeError('unsupported_action')

    def run_register(self, mail_provider: MailProvider) -> AuthResult:
        raise RuntimeError('unsupported_action')

    def run_protocol_login(self, mail_provider: Optional[MailProvider], email: str, password: str='', *, credentials_only: bool=False, should_stop: Optional[Any]=None, route_prechecked: bool=False) -> AuthResult:
        """
        纯协议登录（不创建随机邮箱）：
        - 适配 passwordless / login_password 两类已有账号入口
        - 可配合 OAUTH_EXCHANGE_BEFORE_CALLBACK / OAUTH_REFRESH_ONLY 尝试优先拿 refresh_token
        - credentials_only=True 时只接受密码/TOTP 分支，不发邮箱验证码、不注册新账号
        """

        def check_stopped(stage: str) -> None:
            if should_stop and should_stop():
                raise RuntimeError(f'用户已停止登录取凭证任务（{stage}）')
        if not (email or '').strip():
            raise RuntimeError('run_protocol_login 缺少邮箱')
        if credentials_only and (not (password or '')):
            raise RuntimeError('密码+2FA 登录缺少密码')
        context = self._ensure_registration_context()
        context.context_reason = 'protocol_login'
        context.set_route('existing_login_pending')
        self._sync_context_result()
        if not route_prechecked:
            check_stopped('网络预检查前')
            if not self.check_proxy():
                logger.warning('网络预检查未通过，继续尝试登录链路以获取精确错误...')
            check_stopped('网络预检查后')
            self.warmup()
            check_stopped('预热后')
        self._is_existing_account = True
        email = email.strip()
        self.result.email = email
        login_password, login_password_is_guess = self._login_password_candidate(email, supplied=password)
        if not login_password_is_guess:
            self.result.password = login_password
        self._protocol_prelude(email)
        csrf_token = self.get_csrf_token()
        check_stopped('CSRF 后')
        auth_url = self.get_auth_url(csrf_token, email=email)
        device_id = self.auth_oauth_init(auth_url)
        check_stopped('OAuth 初始化后')
        sentinel = self.get_sentinel_token(device_id)
        check_stopped('Sentinel 后')
        continue_url = ''
        try:
            otp_timeout = max(10, int(self._get_env('OTP_TIMEOUT', '60')))
        except Exception:
            otp_timeout = 180
        page_type = ''
        mode = ''
        prefer_login_screen_first = str(os.getenv('LOCALAUTH_EXISTING_LOGIN_USE_LOGIN_HINT', '1')).lower() in ('1', 'true', 'yes', 'on')
        if prefer_login_screen_first:
            try:
                logger.info('已有账号协议登录：优先走 login screen_hint 探测 password/otp 分支')
                auth_url, sentinel, login_step = self._continue_existing_login_authorization(email, auth_url, sentinel, check_stopped=check_stopped)
                check_stopped('登录分支探测后')
                page_type = (self._extract_page_type(login_step) or '').lower()
                continue_url = self._normalize_continue_url(self._extract_continue_url_from_step(login_step))
                page = login_step.get('page') or {} if isinstance(login_step, dict) else {}
                payload = page.get('payload') or {} if isinstance(page, dict) else {}
                mode = (payload.get('email_verification_mode', '') or '').lower()
                self._existing_page_type = page_type
                self._existing_email_verification_mode = mode
                if page_type == 'login_password' or '/log-in/password' in (continue_url or ''):
                    logger.info('登录分支: login_password -> password/verify')
                    self._is_existing_account = True
                    login_resp = self.login_password_verify(login_password)
                    check_stopped('密码验证后')
                    self.result.password = login_password
                    page_type = (self._extract_page_type(login_resp) or '').lower()
                    continue_url = self._normalize_continue_url(self._extract_continue_url_from_step(login_resp))
                    if self._is_mfa_challenge_state(page_type, continue_url):
                        totp_secret = (self.result.totp_secret or '').strip()
                        if not totp_secret and self._account_callback:
                            try:
                                cred = self._account_callback(email)
                                if cred and cred.get('totp_secret'):
                                    totp_secret = cred['totp_secret']
                                    self.result.totp_secret = totp_secret
                                    logger.info('已从数据库加载 totp_secret')
                            except Exception as e:
                                logger.warning(f'account_callback 异常: {e}')
                        if not totp_secret:
                            logger.warning('进入 mfa-challenge 但没有 totp_secret，无法继续')
                        else:
                            challenge_id = continue_url.split('/')[-1] if '/mfa-challenge/' in continue_url else ''
                            if challenge_id:
                                totp_code = _totp_now(totp_secret)
                                logger.info(f'提交 TOTP 码进行 2FA 验证（challenge_id={challenge_id[:16]}...）')
                                mfa_resp = self.submit_mfa_totp(totp_code, challenge_id)
                                check_stopped('TOTP 验证后')
                                page_type = (self._extract_page_type(mfa_resp) or '').lower()
                                continue_url = self._normalize_continue_url(self._extract_continue_url_from_step(mfa_resp))
                            else:
                                logger.warning('无法从 continue_url 提取 challenge_id')
                elif page_type == 'email_otp_verification' or '/email-verification' in (continue_url or ''):
                    if credentials_only:
                        raise RuntimeError('账号进入邮箱验证码分支，密码+2FA 登录未发送邮件验证码')
                    logger.info('登录分支: email_otp_verification')
                    self._is_existing_account = True
                else:
                    if credentials_only:
                        raise RuntimeError(f'账号未进入密码登录分支: page_type={page_type or '(empty)'}')
                    logger.info('login screen_hint 未直接命中已有账号完成态: page_type=%s continue_url=%s', page_type or '(empty)', (continue_url or '')[:180] or '(empty)')
            except Exception as e:
                if credentials_only:
                    raise
                logger.warning(f'login screen_hint 探测失败，回退 signup 探测: {e}')
                continue_url = ''
                page_type = ''
                mode = ''
        if not continue_url and page_type not in ('login_password', 'email_otp_verification'):
            if credentials_only:
                raise RuntimeError('密码+2FA 登录未取得继续地址，已停止且未尝试注册')
            is_new = self.signup(email, sentinel)
            if is_new:
                logger.warning('目标邮箱未命中已有账号分支，回退到注册链路')
                self.register_password(email)
                otp_sent_at = time.time()
                self.send_otp()
                otp_code = mail_provider.wait_for_otp(email, timeout=otp_timeout, issued_after=otp_sent_at)
                self.verify_otp(otp_code)
                continue_url = self.create_account()
            else:
                page_type = (self._existing_page_type or '').lower()
                mode = (self._existing_email_verification_mode or '').lower()
        else:
            page_type = (page_type or self._existing_page_type or '').lower()
            mode = (mode or self._existing_email_verification_mode or '').lower()
        if not continue_url or '/email-verification' in continue_url:
            if credentials_only:
                raise RuntimeError('密码+2FA 登录需要邮箱验证码，已停止且未发送验证码')
            otp_sent_at = time.time()
            resend_ok = self.kickoff_otp_delivery('protocol_need_otp')
            if not resend_ok and mode not in ('passwordless_signup', 'passwordless_login'):
                self.send_otp()
                otp_sent_at = time.time()
            otp_code = mail_provider.wait_for_otp(email, timeout=otp_timeout, issued_after=otp_sent_at)
            try:
                otp_resp = self.verify_otp(otp_code)
                self.fetch_client_auth_session_dump('post_verify_otp_protocol')
            except RuntimeError as e:
                if any((code in str(e) for code in ('401', '409'))):
                    logger.warning(f'OTP 首次验证失败，重发重试: {e}')
                    otp_sent_at = time.time()
                    if not self.kickoff_otp_delivery('protocol_verify_retry'):
                        self.send_otp()
                    otp_code = mail_provider.wait_for_otp(email, timeout=otp_timeout, issued_after=otp_sent_at)
                    otp_resp = self.verify_otp(otp_code)
                    self.fetch_client_auth_session_dump('post_verify_otp_retry_protocol')
                else:
                    raise
            continue_url = self._extract_continue_url_from_step(otp_resp)
            continue_url = self._normalize_continue_url(continue_url)
            if self._is_add_phone_state(page_type=self._extract_page_type(otp_resp), continue_url=continue_url):
                continue_url = self._normalize_continue_url(self._handle_add_phone_verification(continue_url=continue_url))
        continue_url = self._normalize_continue_url(continue_url)
        check_stopped('重定向前')
        if not continue_url:
            continue_url = self._reauthorize_for_session(auth_url) or ''
        refresh_only_mode = self._env_flag('OAUTH_REFRESH_ONLY', '0')
        callback_url = ''
        if continue_url:
            continue_url = self._normalize_continue_url(continue_url)
            if not credentials_only and (not self.result.refresh_token) and self._env_flag('OAUTH_CODEX_RT_BEFORE_CALLBACK', '1'):
                self.oauth_codex_rt_exchange(mail_provider=mail_provider)
            pre_exchange_default = '1' if refresh_only_mode else '0'
            pre_exchange = self._env_flag('OAUTH_EXCHANGE_BEFORE_CALLBACK', pre_exchange_default)
            if pre_exchange and (not credentials_only):
                self.oauth_token_exchange(continue_url, continue_url)
            callback_url, final_url = self.follow_redirect_chain(continue_url)
            check_stopped('重定向后')
            if not callback_url and final_url and ('/workspace' in final_url):
                normalized = self._normalize_continue_url(final_url)
                if normalized and normalized != final_url:
                    callback_url, final_url = self.follow_redirect_chain(normalized)
        if not refresh_only_mode:
            self.get_auth_session()
            check_stopped('Session 获取后')
        session_credentials_ready = credentials_only and (not refresh_only_mode) and self.result.is_valid()
        if session_credentials_ready:
            logger.info('已取得 access/session 凭证，跳过可选 refresh_token 交换')
        elif callback_url or continue_url:
            self.fetch_client_auth_session_dump('pre_oauth_exchange_protocol')
            self.oauth_token_exchange(callback_url or '', continue_url or '')
            check_stopped('OAuth Token 交换后')
            if not self.result.refresh_token and self._env_flag('OAUTH_CODEX_RT_EXCHANGE', '1'):
                self.oauth_codex_rt_exchange(mail_provider=mail_provider)
            if not self.result.refresh_token and self._env_flag('OAUTH_SECONDARY_AUTHORIZE_EXCHANGE', '0'):
                self.oauth_secondary_authorize_exchange()
            if not refresh_only_mode:
                self.get_auth_session()
        if refresh_only_mode:
            if not (self.result.refresh_token or self.result.access_token):
                raise RuntimeError('协议登录完成，但未拿到 refresh_token/access_token')
        elif not self.result.is_valid():
            raise RuntimeError('协议登录完成，但未拿到有效 session/access token')
        logger.info('纯协议登录流程完成')
        return self.result

    def from_existing_credentials(self, session_token: str, access_token: str, device_id: str) -> AuthResult:
        """使用已有凭证（跳过注册）"""
        self.result.device_id = device_id or str(uuid.uuid4())
        self.session.cookies.set('oai-did', self.result.device_id, domain='.chatgpt.com')
        detected_email = ''
        if session_token:
            self.session.cookies.set('__Secure-next-auth.session-token', session_token, domain='.chatgpt.com')
            logger.info('使用 session_token 刷新 access_token...')
            try:
                headers = self._common_headers('https://chatgpt.com/')
                resp = self.session.get('https://chatgpt.com/api/auth/session', headers=headers, timeout=30)
                session_data = resp.json() if resp is not None else {}
                new_access_token = session_data.get('accessToken', '')
                user_obj = session_data.get('user', {}) if isinstance(session_data, dict) else {}
                if isinstance(user_obj, dict):
                    detected_email = detected_email or (user_obj.get('email', '') or '')
                new_session_token = self.session.cookies.get('__Secure-next-auth.session-token', '')
                if new_access_token:
                    access_token = new_access_token
                    logger.info('access_token 刷新成功')
                else:
                    logger.warning(f'access_token 刷新失败 (status={resp.status_code}), 使用原 token')
                if new_session_token:
                    session_token = new_session_token
            except Exception as e:
                logger.warning(f'刷新 access_token 失败: {e}, 使用原 token')
        elif access_token:
            logger.info('未提供 session_token, 尝试通过 access_token 获取...')
            try:
                headers = self._common_headers('https://chatgpt.com/')
                headers['Authorization'] = f'Bearer {access_token}'
                resp = self.session.get('https://chatgpt.com/api/auth/session', headers=headers, timeout=30)
                session_data = resp.json() if resp is not None else {}
                user_obj = session_data.get('user', {}) if isinstance(session_data, dict) else {}
                if isinstance(user_obj, dict):
                    detected_email = detected_email or (user_obj.get('email', '') or '')
                session_token = self.session.cookies.get('__Secure-next-auth.session-token', '')
                if session_token:
                    logger.info('通过 access_token 获取 session_token 成功')
                else:
                    logger.warning('未能获取 session_token, 可能需要手动提供')
            except Exception as e:
                logger.warning(f'获取 session_token 失败: {e}')
        self.result.access_token = access_token
        self.result.session_token = session_token
        if session_token:
            self.session.cookies.set('__Secure-next-auth.session-token', session_token, domain='.chatgpt.com')
        self.result.cookie_header = self._build_chatgpt_cookie_header()
        if not detected_email and access_token and (access_token.count('.') >= 2):
            try:
                payload_b64 = access_token.split('.')[1]
                payload_b64 += '=' * (-len(payload_b64) % 4)
                payload = json.loads(base64.urlsafe_b64decode(payload_b64.encode('utf-8')).decode('utf-8'))
                prof = payload.get('https://api.openai.com/profile', {}) if isinstance(payload, dict) else {}
                if isinstance(prof, dict):
                    detected_email = detected_email or (prof.get('email', '') or '')
            except Exception:
                pass
        self.result.email = detected_email or ''
        logger.info('使用已有凭证初始化完成')
        return self.result
