"""AstrBot development adapter for the isolated Sylanne 3 foundation."""
from __future__ import annotations

import asyncio
import json
import math
from pathlib import Path
from typing import Any

from astrbot.api import logger
from astrbot.api.event import AstrMessageEvent, MessageChain, filter
from astrbot.api.star import Context, Star, StarTools

from .rewrite.sylanne3.application import Application
from .rewrite.sylanne3.contracts import EventConflict, Scope
from .rewrite.sylanne3.delivery import DeliveryFailed
from .rewrite.sylanne3.native import NativeKernel
from .rewrite.sylanne3.scheduler import BoundedScheduler
from .rewrite.sylanne3.semantics import Envelope, render_action
from .rewrite.sylanne3.store import Store


PLUGIN_NAME = "astrbot_plugin_sylanne"
INGRESS_PERSONA = "__sylanne3_ingress__"
SETUP_MESSAGE = "Sylanne 3 开发适配器未启用；请先在插件配置中开启 enabled。"
BUSY_MESSAGE = "Sylanne 3 当前繁忙，请稍后再试。"
UNAVAILABLE_MESSAGE = "Sylanne 3 当前不可用，请检查插件启动日志。"
USAGE_MESSAGE = "用法：/sylanne3 <消息>"


def _canonical_array(*values: str) -> str:
    return json.dumps(list(values), ensure_ascii=True, separators=(",", ":"))


def _identity(value: object, label: str) -> str:
    if not isinstance(value, str) or not value or value == "[%None]":
        raise ValueError(f"missing {label}")
    return value


def _parse_config(config: object) -> tuple[bool, int, float]:
    values = config if isinstance(config, dict) else {}
    enabled = values.get("enabled", False)
    capacity = values.get("capacity", 8)
    timeout = values.get("timeout", 30)
    if type(enabled) is not bool:
        raise ValueError("enabled must be boolean")
    if type(capacity) is not int or not 1 <= capacity <= 64:
        raise ValueError("capacity must be an integer from 1 to 64")
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
        raise ValueError("timeout must be numeric")
    timeout = float(timeout)
    if not math.isfinite(timeout) or not 1 <= timeout <= 120:
        raise ValueError("timeout must be from 1 to 120 seconds")
    return enabled, capacity, timeout


def _command_text(raw: object) -> str | None:
    if not isinstance(raw, str):
        return None
    for prefix in ("/sylanne3", "sylanne3"):
        if raw == prefix:
            return ""
        if raw.startswith(prefix) and len(raw) > len(prefix) and raw[len(prefix)].isspace():
            # Consume only the command delimiter. Any further leading or internal
            # whitespace belongs to the source text and must remain byte-for-byte.
            return raw[len(prefix) + 1 :]
    return None


def _open_resources(data_dir: Path | None = None) -> tuple[Store, NativeKernel]:
    data_dir = data_dir or StarTools.get_data_dir(PLUGIN_NAME)
    data_dir.mkdir(parents=True, exist_ok=True)
    store = Store(data_dir / "sylanne3.sqlite3")
    try:
        return store, NativeKernel()
    except BaseException:
        store.close()
        raise


async def _join(task: asyncio.Task[Any]) -> tuple[Any, asyncio.CancelledError | None]:
    """Join owned work even if its caller is cancelled more than once."""
    cancellation = None
    while not task.done():
        try:
            await asyncio.shield(task)
        except asyncio.CancelledError as exc:
            cancellation = cancellation or exc
    return task.result(), cancellation


class _ActionTransport:
    def __init__(
        self,
        plugin: "Sylanne3Plugin",
        event: AstrMessageEvent,
        expected_scope: Scope,
    ) -> None:
        self._plugin = plugin
        self._event = event
        self._expected_scope = expected_scope

    async def send(self, action: object) -> None:
        if getattr(action, "scope", None) != self._expected_scope:
            raise DeliveryFailed("action scope does not match delivery owner")
        sending = False
        try:
            async with asyncio.timeout(self._plugin._timeout):
                current_scope, _ = await self._plugin._resolve_scope(self._event)
                if current_scope != self._expected_scope:
                    raise DeliveryFailed("scope ownership changed before delivery")
                text = render_action(action)
                chain = MessageChain().message(text)
                sending = True
                await self._event.send(chain)
        except asyncio.CancelledError:
            raise
        except TimeoutError as exc:
            if not sending:
                raise DeliveryFailed("scope resolution timed out before delivery") from exc
            # Once send starts, timeout means external acceptance is unknown.
            raise
        except DeliveryFailed:
            raise
        except Exception as exc:
            if sending:
                raise RuntimeError(
                    "platform send failed; acceptance unknown"
                ) from None
            raise DeliveryFailed("scope unavailable before delivery") from exc


class Sylanne3Plugin(Star):
    """Explicit `/sylanne3` development command; disabled by default."""

    def __init__(self, context: Context, config: dict | None = None) -> None:
        super().__init__(context, config)
        self._config_error = False
        try:
            self._enabled, self._capacity, self._timeout = _parse_config(config)
        except ValueError:
            self._enabled, self._capacity, self._timeout = False, 8, 30.0
            self._config_error = True
        self._app: Application | None = None
        self._startup_failed = False
        self._closing = False
        self._entry_count = 0
        self._entry_tasks: set[asyncio.Task[Any]] = set()
        self._initialization: asyncio.Task[Any] | None = None
        self._close_lock = asyncio.Lock()

    async def initialize(self) -> None:
        if self._config_error:
            self._startup_failed = True
            logger.error("Sylanne3 startup rejected: invalid bounded configuration")
            return
        if not self._enabled:
            logger.info("Sylanne3 development adapter is disabled")
            return
        if self._closing:
            return
        if self._initialization is None:
            self._initialization = asyncio.create_task(self._initialize_owned())
        _, cancellation = await _join(self._initialization)
        if cancellation is not None:
            self._closing = True
            await self._close_application()
            raise cancellation

    async def _initialize_owned(self) -> None:
        resource_task = asyncio.create_task(asyncio.to_thread(_open_resources, None))
        try:
            resources, _ = await _join(resource_task)
        except Exception:
            self._startup_failed = True
            logger.error("Sylanne3 startup failed: local resources unavailable")
            return
        store, kernel = resources
        scheduler = None
        app = None
        try:
            scheduler = BoundedScheduler(
                workers=min(2, self._capacity), capacity=self._capacity
            )
            app = Application(
                store,
                scheduler,
                kernel,
                capacity=self._capacity,
                proposal_timeout=self._timeout,
            )
            if self._closing:
                close_task = asyncio.create_task(app.close())
                await _join(close_task)
                return
            self._app = app
        except BaseException:
            if app is not None:
                close_task = asyncio.create_task(app.close())
                await _join(close_task)
            else:
                if scheduler is not None:
                    close_scheduler = asyncio.create_task(scheduler.close())
                    await _join(close_scheduler)
                close_store = asyncio.create_task(asyncio.to_thread(store.close))
                await _join(close_store)
            self._startup_failed = True
            logger.error("Sylanne3 startup failed: application unavailable")

    async def _close_application(self) -> asyncio.CancelledError | None:
        async with self._close_lock:
            app, self._app = self._app, None
            if app is None:
                return None
            close_task = asyncio.create_task(app.close())
            _, cancellation = await _join(close_task)
            return cancellation

    async def terminate(self) -> None:
        self._closing = True
        cancellation = None
        if self._initialization is not None:
            _, cancellation = await _join(self._initialization)
        current = asyncio.current_task()
        handlers = tuple(task for task in self._entry_tasks if task is not current)
        for task in handlers:
            task.cancel()
        if handlers:
            join_handlers = asyncio.ensure_future(
                asyncio.gather(*handlers, return_exceptions=True)
            )
            _, handler_cancellation = await _join(join_handlers)
            cancellation = cancellation or handler_cancellation
        close_cancellation = await self._close_application()
        cancellation = cancellation or close_cancellation
        if cancellation is not None:
            raise cancellation

    async def _send_text(self, event: AstrMessageEvent, text: str) -> None:
        try:
            await asyncio.wait_for(
                event.send(MessageChain().message(text)), timeout=self._timeout
            )
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.warning("Sylanne3 command response delivery failed")

    async def _resolve_scope(self, event: AstrMessageEvent) -> tuple[Scope, Scope]:
        umo = _identity(event.unified_msg_origin, "unified message origin")
        platform_id = _identity(event.get_platform_id(), "platform id")
        self_id = _identity(event.get_self_id(), "self id")
        sender_id = _identity(event.get_sender_id(), "sender id")
        platform_name = _identity(event.get_platform_name(), "platform name")
        manager = self.context.conversation_manager
        cid = _identity(
            await manager.get_curr_conversation_id(umo), "conversation id"
        )
        conversation = await manager.get_conversation(
            umo, cid, create_if_not_exists=False
        )
        if conversation is None:
            raise ValueError("conversation is absent")
        selected = await self.context.persona_manager.resolve_selected_persona(
            umo=umo,
            conversation_persona_id=getattr(conversation, "persona_id", None),
            platform_name=platform_name,
            provider_settings=self.context.get_config(umo),
        )
        persona_id = _identity(selected[0], "effective persona id")
        # Detect `/new` or another owner transition during persona resolution.
        if await manager.get_curr_conversation_id(umo) != cid:
            raise ValueError("conversation ownership changed")
        bot = _canonical_array(platform_id, self_id)
        destination = Scope(bot, persona_id, _canonical_array(umo, cid, sender_id))
        ingress = Scope(
            bot,
            INGRESS_PERSONA,
            _canonical_array("host-ingress", umo, sender_id),
        )
        return destination, ingress

    async def _propose(self, event: AstrMessageEvent, prompt: str) -> str:
        umo = _identity(event.unified_msg_origin, "unified message origin")
        provider_id = _identity(
            await self.context.get_current_chat_provider_id(umo), "provider id"
        )
        response = await self.context.llm_generate(
            chat_provider_id=provider_id,
            prompt=prompt,
            contexts=[],
            tools=None,
        )
        if (
            getattr(response, "role", None) != "assistant"
            or bool(getattr(response, "is_chunk", False))
            or getattr(response, "tools_call_extra_content", None)
            or getattr(response, "tools_call_args", None)
            or getattr(response, "tools_call_name", None)
            or getattr(response, "tools_call_ids", None)
        ):
            raise ValueError("tool calls are forbidden")
        text = getattr(response, "completion_text", None)
        if not isinstance(text, str) or not text.strip():
            raise ValueError("provider returned no text")
        return text

    @filter.command("sylanne3")
    async def sylanne3(self, event: AstrMessageEvent) -> None:
        event.stop_event()
        task = asyncio.current_task()
        if self._closing or self._entry_count >= self._capacity:
            logger.warning("Sylanne3 command not admitted: status=busy_or_closing")
            return
        self._entry_count += 1
        if task is not None:
            self._entry_tasks.add(task)
        try:
            if not self._enabled:
                await self._send_text(
                    event, UNAVAILABLE_MESSAGE if self._startup_failed else SETUP_MESSAGE
                )
                return
            if self._app is None:
                await self._send_text(event, UNAVAILABLE_MESSAGE)
                return
            text = _command_text(event.get_message_str())
            if text is None or not text:
                await self._send_text(event, USAGE_MESSAGE)
                return
            message_obj = getattr(event, "message_obj", None)
            message_id = _identity(
                getattr(message_obj, "message_id", None), "message id"
            )
            timestamp = getattr(message_obj, "timestamp", None)
            if (
                isinstance(timestamp, bool)
                or not isinstance(timestamp, (int, float))
                or not math.isfinite(timestamp)
                or timestamp <= 1
            ):
                raise ValueError("invalid source timestamp")
            scope, ingress_scope = await asyncio.wait_for(
                self._resolve_scope(event), timeout=self._timeout
            )
            envelope = Envelope(scope, message_id, text, timestamp - 1, timestamp)
            transport = _ActionTransport(self, event, scope)
            result = await self._app.handle(
                envelope,
                lambda prompt: self._propose(event, prompt),
                transport,
                ingress_scope=ingress_scope,
            )
            if result.status == "duplicate":
                return
            if result.status == "busy":
                await self._send_text(event, BUSY_MESSAGE)
                return
            if result.status not in {"committed", "abstained"}:
                logger.warning("Sylanne3 request rejected: status=%s", result.status)
        except asyncio.CancelledError:
            raise
        except EventConflict:
            logger.warning("Sylanne3 request rejected: status=event_conflict")
        except Exception:
            logger.warning("Sylanne3 request rejected: status=invalid_or_failed")
        finally:
            if task is not None:
                self._entry_tasks.discard(task)
            self._entry_count -= 1
