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
    this.fetchImpl = fetchImpl;
  }

  get hasSession() { return Boolean(this.csrfToken); }

  clearSession() { this.csrfToken = null; }

  async openSession() {
    if (this.csrfToken) return;
    if (!this.sessionRequest) {
      this.sessionRequest = this.#openSession().finally(() => { this.sessionRequest = null; });
    }
    return this.sessionRequest;
  }

  async #openSession() {
    let response;
    try {
      response = await this.fetchImpl(`${this.baseUrl}/session`, {
        method: "GET", credentials: "same-origin", headers: { accept: "application/json" }
      });
    } catch (error) {
      this.clearSession();
      throw new WorkbenchApiError("无法连接工作台会话。请检查连接后重试。", { detail: error });
    }
    const body = await this.#readBody(response);
    if (!response.ok) {
      this.clearSession();
      throw this.#responseError(response, body, "工作台会话尚未建立。请先登录并完成 Owner 配对，然后重试。");
    }
    if (body?.status !== "ready" || typeof body.csrf_token !== "string" || !body.csrf_token) {
      this.clearSession();
      throw new WorkbenchApiError("工作台会话响应无效。请重新核验连接。", { code: "invalid_session", retryable: true });
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
      input: { view_type: viewType, cursor, page_size: 50 }
    });
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
