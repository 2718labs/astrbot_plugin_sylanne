export const VIEW_STATES = Object.freeze(["loading", "empty", "unauthorized", "stale", "partial", "unavailable", "ready"]);

export function initialState() {
  return { role: null, roleEpoch: 0, view: "overview", projection: null, status: "unavailable", problem: { code: "service_unavailable", message: "工作台服务尚未提供可验证投影。" }, receipt: null };
}

export function switchRole(state, role) {
  return { ...state, role: role || null, roleEpoch: state.roleEpoch + 1, projection: null, receipt: null, status: "loading", problem: null };
}

export function applyResponse(state, response) {
  const status = VIEW_STATES.includes(response?.status) ? response.status : "unavailable";
  const safeProjection = status === "ready" && response?.projection && typeof response.projection === "object" ? response.projection : null;
  const safeReceipt = status === "ready" ? (response?.receipt && typeof response.receipt === "object" ? response.receipt : state.receipt ?? null) : null;
  return { ...state, status, projection: safeProjection, problem: response?.problem ?? null, receipt: safeReceipt };
}

export function applyProblem(state, problem) {
  const status = problem?.code === "unauthorized" ? "unauthorized" : "unavailable";
  return { ...state, status, projection: null, problem, receipt: null };
}
