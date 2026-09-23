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
  constructor({ baseUrl = DEFAULT_WORKBENCH_API_BASE, csrfToken = globalThis.SYLANNE_WORKBENCH_CSRF_TOKEN, fetchImpl = fetch } = {}) {
    this.baseUrl = baseUrl.replace(/\/$/, "");
    this.csrfToken = typeof csrfToken === "string" && csrfToken ? csrfToken : null;
    this.fetchImpl = fetchImpl;
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
    let response;
    try {
      response = await this.fetchImpl(`${this.baseUrl}${path}`, {
        method: "POST",
        credentials: "same-origin",
        headers: { "content-type": "application/json", "accept": "application/json", ...(this.csrfToken ? { "x-csrf-token": this.csrfToken } : {}) },
        body: JSON.stringify(payload)
      });
    } catch (error) {
      throw new WorkbenchApiError("无法连接工作台服务。内容没有从本地缓存恢复。", { detail: error });
    }
    let body = null;
    try { body = await response.json(); } catch { /* protocol error below */ }
    if (!response.ok) {
      const problem = body?.problem ?? {};
      throw new WorkbenchApiError(problem.message ?? "服务拒绝了此操作。", {
        code: problem.code ?? "request_rejected", status: response.status,
        retryable: Boolean(problem.retryable), detail: problem
      });
    }
    if (!body || typeof body !== "object") {
      throw new WorkbenchApiError("服务响应格式无效，未显示任何角色内容。", { code: "invalid_response", retryable: false });
    }
    return body;
  }
}
