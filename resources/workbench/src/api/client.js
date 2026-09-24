import { makeRequest } from "./contract.js";

// AstrBot 4.28.1 mounts plugin extension routes below /api/v1.
export const DEFAULT_WORKBENCH_API_BASE = "/api/v1/plugins/extensions/astrbot_plugin_sylanne/workbench/v1";

export class WorkbenchApiError extends Error {
  constructor(message, { code = "network_unavailable", status = 0, retryable = true, detail } = {}) {
    super(message);
    this.name = "WorkbenchApiError";
    this.code = code;
    this.status = status;
    this.retryable = retryable;
    this.detail = detail;
  }
}

export class WorkbenchApi {
  constructor({ baseUrl = DEFAULT_WORKBENCH_API_BASE, fetchImpl = fetch } = {}) {
    this.baseUrl = baseUrl.replace(/\/$/, "");
    this.csrfToken = null;
    this.sessionRequest = null;
    this.sessionGeneration = 0;
    this.fetchImpl = fetchImpl;
  }

  get hasSession() { return Boolean(this.csrfToken); }

  clearSession() {
    this.csrfToken = null;
    this.sessionRequest = null;
    ++this.sessionGeneration;
  }

  async installationStatus() {
    let response;
    try {
      response = await this.fetchImpl(`${this.baseUrl}/status`, {
        method: "GET", credentials: "same-origin", headers: { accept: "application/json" }
      });
    } catch (error) {
      throw new WorkbenchApiError("无法读取安装状态。请检查连接后重试。", { detail: error });
    }
    const body = await this.#readBody(response);
    if (!response.ok) throw this.#responseError(response, body, "安装状态暂不可用。");
    if (body?.schema_version !== "sylanne.install-status.v1" ||
        !["limited", "blocked", "enrollment_required", "ready", "stopped"].includes(body.runtime_stage) ||
        typeof body.reason_code !== "string") {
      throw new WorkbenchApiError("安装状态响应无效。", { code: "invalid_status", retryable: true });
    }
    return { stage: body.runtime_stage, reason: body.reason_code };
  }

  async sceneCandidates() {
    await this.openSession();
    let response;
    try {
      response = await this.fetchImpl(`${this.baseUrl}/scene-candidates`, {
        method: "GET", credentials: "same-origin", headers: { accept: "application/json" }
      });
    } catch (error) {
      throw new WorkbenchApiError("无法读取当前场景候选。", { detail: error });
    }
    const body = await this.#readBody(response);
    if (!response.ok) {
      if (response.status === 401 || response.status === 403) this.clearSession();
      throw this.#responseError(response, body, "场景候选暂不可用。");
    }
    if (body?.schema_version !== "sylanne.scene-candidates.v1" ||
        !["ready", "empty"].includes(body.status) || !Array.isArray(body.candidates) ||
        body.candidates.some((item) => typeof item.platform_ref !== "string" ||
          typeof item.conversation_ref !== "string" ||
          !["private", "group"].includes(item.visibility) ||
          !/^scene:conversation-v1:[0-9a-f]{64}$/.test(item.scene_ref))) {
      throw new WorkbenchApiError("场景候选响应无效。", { code: "invalid_scene_candidates", retryable: true });
    }
    return body.candidates;
  }

  async openSession() {
    if (this.csrfToken) return;
    if (!this.sessionRequest) {
      const generation = this.sessionGeneration;
      const request = this.#openSession(generation).finally(() => {
        if (this.sessionRequest === request) this.sessionRequest = null;
      });
      this.sessionRequest = request;
    }
    return this.sessionRequest;
  }

  async #openSession(generation) {
    let response;
    try {
      response = await this.fetchImpl(`${this.baseUrl}/session`, {
        method: "GET", credentials: "same-origin", headers: { accept: "application/json" }
      });
    } catch (error) {
      if (generation === this.sessionGeneration) this.clearSession();
      throw new WorkbenchApiError("无法连接工作台会话。请检查连接后重试。", { detail: error });
    }
    const body = await this.#readBody(response);
    if (!response.ok) {
      if (generation === this.sessionGeneration) this.clearSession();
      throw this.#responseError(response, body, "工作台会话尚未建立。请先登录并完成 Owner 配对，然后重试。");
    }
    if (body?.status !== "ready" || body.dashboard_session !== "authenticated" ||
        body.owner_session !== "unlocked" || typeof body.csrf_token !== "string" || !body.csrf_token) {
      if (generation === this.sessionGeneration) this.clearSession();
      throw new WorkbenchApiError("工作台会话响应无效。请重新核验连接。", { code: "invalid_session", retryable: true });
    }
    if (generation !== this.sessionGeneration) {
      throw new WorkbenchApiError("Owner 会话在核验期间已切换。", { code: "session_changed", retryable: true });
    }
    this.csrfToken = body.csrf_token;
  }

  async command(action, options) {
    const payload = makeRequest(action, options);
    return this.#post("/commands", payload);
  }

  async readView({ scope, viewType, cursor, purpose = "workbench_view" }) {
    return this.command("read_character_view", {
      scope,
      purpose,
      input: { view_type: viewType, cursor, page_size: viewType === "d06.memory_sources.v1" ? 100 : 50 }
    });
  }

  async ownerChallenge(request) {
    const body = await this.#ownerPost("/owner/challenge", { request });
    if (body?.schema_version !== "sylanne.owner-login.v1" ||
        body.challenge?.kind !== "owner_session_login_challenge_v1" ||
        body.challenge.request?.kind !== "owner_session_login_request_v1" ||
        typeof body.signing_payload_base64 !== "string" || !body.signing_payload_base64) {
      throw new WorkbenchApiError("Owner 挑战响应无效。", { code: "invalid_owner_challenge", retryable: false });
    }
    return { challenge: body.challenge, signingPayloadBase64: body.signing_payload_base64 };
  }

  async ownerComplete(challenge, signatureBase64) {
    const body = await this.#ownerPost("/owner/complete", {
      challenge, signature_base64: signatureBase64
    });
    if (body?.status !== "authenticated" || body.owner_session !== "unlocked") {
      throw new WorkbenchApiError("Owner 登录结果无效。", { code: "invalid_owner_login", retryable: false });
    }
    this.clearSession();
  }

  async ownerLogout() {
    this.clearSession();
    const body = await this.#ownerPost("/owner/logout", {});
    if (body?.status !== "ok" || body.owner_session !== "locked") {
      throw new WorkbenchApiError("Owner 退出结果无效。", { code: "invalid_owner_logout", retryable: false });
    }
  }

  async #ownerPost(path, payload) {
    let response;
    try {
      response = await this.fetchImpl(`${this.baseUrl}${path}`, {
        method: "POST", credentials: "same-origin",
        headers: { "content-type": "application/json", accept: "application/json" },
        body: JSON.stringify(payload)
      });
    } catch (error) {
      throw new WorkbenchApiError("无法连接 Owner 登录服务。", { detail: error });
    }
    const body = await this.#readBody(response);
    if (!response.ok) throw this.#responseError(response, body, "Owner 登录请求未通过核验。");
    return body;
  }

  async #post(path, payload) {
    await this.openSession();
    let response;
    try {
      response = await this.fetchImpl(`${this.baseUrl}${path}`, {
        method: "POST",
        credentials: "same-origin",
        headers: { "content-type": "application/json", "accept": "application/json", "x-csrf-token": this.csrfToken },
        body: JSON.stringify(payload)
      });
    } catch (error) {
      throw new WorkbenchApiError("无法连接工作台服务。内容没有从本地缓存恢复。", { detail: error });
    }
    const body = await this.#readBody(response);
    if (!response.ok) {
      if (response.status === 401 || response.status === 403) this.clearSession();
      throw this.#responseError(response, body, "服务拒绝了此操作。");
    }
    if (!body || typeof body !== "object") {
      throw new WorkbenchApiError("服务响应格式无效，未显示任何角色内容。", { code: "invalid_response", retryable: false });
    }
    return body;
  }


  async #readBody(response) {
    try { return await response.json(); } catch { return null; }
  }

  #responseError(response, body, fallback) {
    const problem = body?.problem ?? {};
    return new WorkbenchApiError(problem.message ?? fallback, {
      code: problem.code ?? (response.status === 401 || response.status === 403 ? "unauthorized" : "request_rejected"),
      status: response.status, retryable: Boolean(problem.retryable), detail: problem
    });
  }
}
