import { ACTIONS, VIEW_TYPES } from "./api/contract.js";
import { DEFAULT_WORKBENCH_API_BASE, WorkbenchApi, WorkbenchApiError } from "./api/client.js";
import { applyProblem, applyResponse, initialState, switchRole } from "./state.js";
import { needsFreshProjection, workflowForPage } from "./workflows.js";

const pages = [
  ["overview", "总览", "当前角色的权限过滤投影与能力状态", "read"],
  ["creation", "创作", "创建草稿、编译与采用方案", "compile"],
  ["relations", "关系与经历", "关系、情境与纠错投影", "correct"],
  ["memory", "记忆", "来源资格约束的记忆查询与修正", "correct"],
  ["cognition", "感受与认知", "连续感受、关切和解释视图", "read"],
  ["action", "计划与行动", "目标、承诺、活动与控制", "control"],
  ["expression", "表达与投递", "表达合同与投递状态，不直接发送", "control"],
  ["diagnostics", "实验与诊断", "隔离实验、真实费用与结构化诊断", "experiment"],
  ["lifecycle", "数据与生命周期", "导入、迁移、升级、停用与删除", "transfer"]
];

const state = initialState();
const api = new WorkbenchApi({ baseUrl: globalThis.SYLANNE_WORKBENCH_API_BASE ?? DEFAULT_WORKBENCH_API_BASE });
const app = document.querySelector("#app");

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>'"]/g, (character) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;" })[character]);
}

function statusCopy(status, problem) {
  const map = {
    loading: ["正在核验", "正在向服务重新请求权限过滤的投影。"],
    empty: ["暂无内容", "服务已确认这个视图为空；这不表示其他领域也为空。"],
    unauthorized: ["无权查看", "当前会话不能读取此范围。角色切换或重新认证会清除旧内容。"],
    stale: ["投影已过期", "不能据此提交需要共同快照的操作。请重新请求最新投影。"],
    partial: ["投影不完整", "只显示服务已授权且已完成的部分；缺失内容不会被补造。"],
    unavailable: ["功能暂不可用", "提供方未声明可用能力，客户端不会使用替身数据。"],
    ready: ["可用", "投影由服务按当前权限返回。"]
  };
  const [title, detail] = map[status] ?? map.unavailable;
  return [title, problem?.message ?? detail];
}

function formMarkup(page) {
  if (page[0] === "creation") return `<label>新角色或方案草稿（JSON 对象，可编辑）<textarea name="draft_json" placeholder='{"fields":{},"field_sources":{}}'></textarea></label><label>已有方案草稿引用（与 JSON 二选一）<input name="draft_ref" placeholder="由已授权草稿提供" /></label><label>已编译候选引用<input name="compiled_scheme_ref" placeholder="采用前由服务签发" /></label><label>操作<select name="mode"><option value="compile">编译候选</option><option value="activate">采用并绑定</option></select></label>`;
  if (["relations", "memory"].includes(page[0])) return `<label>纠错类型<select name="correction_kind"><option value="source_correction">来源更正</option><option value="interpretation_challenge">解释质疑</option><option value="administrative_edit">创作调整</option></select></label><label>新说明<textarea name="statement" required></textarea></label><label>来源引用（逗号分隔）<input name="source_refs" /></label>`;
  if (["cognition", "action", "expression"].includes(page[0])) return `<label>对象引用<input name="object_ref" required /></label><label>控制请求<input name="control" placeholder="只提交领域可解释的控制请求" /></label>`;
  if (page[0] === "diagnostics") return `<label>操作<select name="mode"><option value="experiment">隔离实验</option><option value="support">生成脱敏支持诊断</option></select></label><label>假设或问题<textarea name="hypothesis"></textarea><input name="question" placeholder="支持问题" /></label>`;
  if (page[0] === "lifecycle") return `<label>操作<select name="mode"><option value="prepare">准备备份或迁移</option><option value="execute">执行已采用计划</option><option value="erase">删除或停用</option><option value="upgrade">校验升级</option></select></label><label>计划/范围引用<input name="plan_ref" /><input name="scope_selection" /><input name="data_choice" placeholder="保留或删除的明确选择" /><input name="release_manifest_ref" placeholder="受信发布清单引用" /></label>`;
  return "";
}

function render() {
  const page = pages.find(([id]) => id === state.view) ?? pages[0];
  const [statusTitle, statusDetail] = statusCopy(state.status, state.problem);
  const body = state.projection
    ? `<pre class="projection" aria-label="服务返回的权限过滤投影">${escapeHtml(JSON.stringify(state.projection, null, 2))}</pre>`
    : `<section class="empty-state" aria-live="polite"><div class="empty-mark" aria-hidden="true">◇</div><h2>${statusTitle}</h2><p>${statusDetail}</p><button class="primary" data-command="refresh" ${state.role ? "" : "disabled"}>重新请求投影</button></section>`;
  app.innerHTML = `
    <div class="shell">
      <header class="topbar">
        <button class="menu-button" data-command="menu" aria-expanded="false" aria-controls="sidebar">菜单</button>
        <label class="role-picker">当前角色 <input id="role-input" value="${escapeHtml(state.role ?? "")}" placeholder="输入角色范围 ID" autocomplete="off" /></label>
        <button class="quiet" data-command="switch-role">切换角色</button>
        <p class="session-status" role="status"><span aria-hidden="true">●</span> 访问由服务端会话逐次核验</p>
      </header>
      <aside id="sidebar" class="sidebar" aria-label="工作台导航">
        <div class="brand">Sylanne <span>角色工作台</span></div>
        <nav>${pages.map(([id, label]) => `<button class="nav-item ${id === state.view ? "selected" : ""}" data-view="${id}" aria-current="${id === state.view ? "page" : "false"}">${label}</button>`).join("")}</nav>
        <p class="sidebar-note">浏览器不保存私密原文。撤权或切换角色时立即清空当前投影。</p>
      </aside>
      <main id="workspace" tabindex="-1">
        <div class="title-row"><div><h1>${page[1]}</h1><p>${page[2]}</p></div><button class="quiet" data-command="open-workspace">刷新能力目录</button></div>
        <div class="state-banner state-${state.status}" role="status"><strong>${statusTitle}</strong><span>${statusDetail}</span></div>
        <div class="workspace-grid"><section class="projection-panel">${body}</section>
          <aside class="inspector" aria-label="操作面板"><h2>操作</h2><p>操作由服务端能力、当前作用域和版本核验。页面不会直接改图或调用平台发送。</p>
          <form id="page-form">${formMarkup(page)}<button type="button" class="primary" data-command="page-action" ${state.role && state.status !== "loading" ? "" : "disabled"}>${page[3] === "read" ? "读取当前视图" : "提交给服务端"}</button></form>
          <dl><dt>操作收据</dt><dd>${escapeHtml(state.receipt?.operation_id ?? "尚无")}</dd><dt>状态</dt><dd>${escapeHtml(state.receipt?.phase ?? statusTitle)}</dd></dl></aside>
        </div>
      </main>
    </div>`;
}

async function loadView() {
  if (!state.role) { Object.assign(state, applyProblem(state, { code: "role_required", message: "请选择角色范围后再请求投影。" })); render(); return; }
  const epoch = state.roleEpoch;
  state.status = "loading"; state.problem = null; render();
  try {
    const result = await api.readView({ scope: state.role, viewType: VIEW_TYPES[state.view] });
    if (epoch !== state.roleEpoch) return;
    Object.assign(state, applyResponse(state, result));
  } catch (error) {
    if (epoch !== state.roleEpoch) return;
    Object.assign(state, applyProblem(state, normalizeError(error)));
  }
  render();
}

function normalizeError(error) {
  if (error instanceof WorkbenchApiError) return { code: error.code, message: error.message, retryable: error.retryable };
  return { code: "client_error", message: "工作台客户端遇到未识别错误；没有显示任何旧内容。", retryable: false };
}

async function command(action) {
  if (action === "menu") {
    const sidebar = document.querySelector("#sidebar");
    const trigger = document.querySelector("[data-command=menu]");
    const open = sidebar?.classList.toggle("open");
    trigger?.setAttribute("aria-expanded", String(Boolean(open)));
    return;
  }
  if (action === "switch-role") {
    const value = document.querySelector("#role-input")?.value.trim();
    Object.assign(state, switchRole(state, value)); render(); await loadView(); return;
  }
  if (action === "refresh") return loadView();
  if (action === "open-workspace") return commandAction(ACTIONS.openWorkspace, { client_protocol: "d12.contract.v1" }, "workbench_view");
  if (action === "page-action") {
    const page = pages.find(([id]) => id === state.view) ?? pages[0];
    if (page[3] === "read") return loadView();
    const form = document.querySelector("#page-form");
    try {
      const [nextAction, input] = workflowForPage(page[0], Object.fromEntries(new FormData(form).entries()));
      return commandAction(nextAction, input);
    } catch (error) {
      Object.assign(state, applyProblem(state, { code: "invalid_input", message: error.message, retryable: false })); render(); return;
    }
  }
}

async function commandAction(action, input, purpose = "workbench_user_action") {
  if (!state.role) return loadView();
  state.status = "loading"; state.problem = null; render();
  try {
    const result = await api.command(action, { scope: state.role, purpose, input });
    Object.assign(state, applyResponse(state, result));
    if (result.status === "ready" && needsFreshProjection(action)) await loadView();
  } catch (error) { Object.assign(state, applyProblem(state, normalizeError(error))); }
  render();
}

app.addEventListener("click", async (event) => {
  const view = event.target.closest("[data-view]")?.dataset.view;
  if (view) { state.view = view; render(); await loadView(); return; }
  const action = event.target.closest("[data-command]")?.dataset.command;
  if (action) await command(action);
});

app.addEventListener("keydown", (event) => {
  if (event.key === "Escape") document.querySelector("#sidebar")?.classList.remove("open");
  if (event.key === "Enter" && event.target.matches("#role-input")) command("switch-role");
});

render();
