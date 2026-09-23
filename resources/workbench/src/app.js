import { ACTIONS, VIEW_TYPES } from "./api/contract.js";
import { DEFAULT_WORKBENCH_API_BASE, WorkbenchApi, WorkbenchApiError } from "./api/client.js";
import { applyProblem, applyResponse, initialState, switchRole } from "./state.js";
import { needsFreshProjection, workflowForPage } from "./workflows.js";

const pages = [
  ["setup", "开始与连接", "核对工作台接通、角色初始化和场景绑定", "read"],
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
let requestEpoch = 0;

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
  if (page[0] === "setup") return `<p class="setup-hint">输入已有且获授权的角色范围 ID 后，可向服务端核验连接。当前版本没有可用的角色创建、场景绑定或会话配对入口。</p>`;
  if (page[0] === "creation") return `<label>方案草稿（JSON 对象，可编辑）<textarea name="draft_json" placeholder='{"fields":{},"field_sources":{}}'></textarea></label><label>已有方案草稿引用（与 JSON 二选一）<input name="draft_ref" placeholder="由已授权草稿提供" /></label><label>已编译候选引用<input name="compiled_scheme_ref" placeholder="采用前由服务签发" /></label><label>操作<select name="mode"><option value="compile">编译候选</option><option value="activate">采用方案</option></select></label>`;
  if (["relations", "memory"].includes(page[0])) return `<label>纠错类型<select name="correction_kind"><option value="source_correction">来源更正</option><option value="interpretation_challenge">解释质疑</option><option value="administrative_edit">创作调整</option></select></label><label>新说明<textarea name="statement" required></textarea></label><label>来源引用（逗号分隔）<input name="source_refs" /></label>`;
  if (["cognition", "action", "expression"].includes(page[0])) return `<label>对象引用<input name="object_ref" required /></label><label>控制请求<input name="control" placeholder="只提交领域可解释的控制请求" /></label>`;
  if (page[0] === "diagnostics") return `<label>操作<select name="mode"><option value="experiment">隔离实验</option><option value="support">生成脱敏支持诊断</option></select></label><label>假设或问题<textarea name="hypothesis"></textarea><input name="question" placeholder="支持问题" /></label>`;
  if (page[0] === "lifecycle") return `<label>操作<select name="mode"><option value="prepare">准备备份或迁移</option><option value="execute">执行已采用计划</option><option value="erase">删除或停用</option><option value="upgrade">校验升级</option></select></label><label>计划/范围引用<input name="plan_ref" /><input name="scope_selection" /><input name="data_choice" placeholder="保留或删除的明确选择" /><input name="release_manifest_ref" placeholder="受信发布清单引用" /></label>`;
  return "";
}

function hasVerifiedCatalogue() {
  return state.status === "ready" && Array.isArray(state.projection?.views);
}

function setupMarkup() {
  const steps = [
    ["宿主与工作台会话", state.sessionReady ? "已核验" : "未核验", state.sessionReady ? "服务端已签发当前会话令牌；角色能力仍以实际目录为准。" : "请登录宿主并完成 Owner 配对，然后重新核验连接。"],
    ["角色初始化", "未核验", "当前能力目录不包含角色初始化回执；填写角色 ID 不会创建角色。"],
    ["场景绑定", "未核验", "当前没有绑定成功回执；私聊或群聊不可据此视为已接通。"],
    ["验证对话", "未核验", "尚无真实对话和投递收据；不会自动向聊天场景发消息。"]
  ];
  return `<div class="setup-guide"><h2>首次使用进度</h2><p>每一步都以服务端实际状态或回执为准。</p><ol class="setup-steps">${steps.map(([label, status, detail]) => `<li><strong>${label}</strong><span>${status}</span><p>${detail}</p></li>`).join("")}</ol><p class="setup-next">${state.role ? "可刷新能力目录；创建与绑定入口需服务端完成后才会开放。" : "先从宿主取得已授权的角色范围；当前浏览器不能自行签发角色。"}</p><button class="quiet" data-command="retry-session">重新核验工作台会话</button></div>`;
}

function render() {
  const page = pages.find(([id]) => id === state.view) ?? pages[0];
  const [statusTitle, statusDetail] = state.view === "setup" && hasVerifiedCatalogue()
    ? ["工作台会话已核验", "角色初始化、场景绑定与验证对话仍需各自的真实回执。"]
    : statusCopy(state.status, state.problem);
  const sessionVerified = state.sessionReady;
  const body = state.view === "setup" ? setupMarkup() : state.projection
    ? `<pre class="projection" aria-label="服务返回的权限过滤投影">${escapeHtml(JSON.stringify(state.projection, null, 2))}</pre>`
    : `<section class="empty-state" aria-live="polite"><div class="empty-mark" aria-hidden="true">◇</div><h2>${statusTitle}</h2><p>${statusDetail}</p><button class="primary" data-command="refresh" ${state.role ? "" : "disabled"}>重新请求投影</button></section>`;
  app.innerHTML = `
    <div class="shell">
      <header class="topbar">
        <button class="menu-button" data-command="menu" aria-expanded="false" aria-controls="sidebar">菜单</button>
        <label class="role-picker">当前角色 <input id="role-input" value="${escapeHtml(state.role ?? "")}" placeholder="输入角色范围 ID" autocomplete="off" /></label>
        <button class="quiet" data-command="switch-role">切换角色</button>
        <p class="session-status ${sessionVerified ? "verified" : ""}" role="status"><span aria-hidden="true">●</span> ${sessionVerified ? "当前请求已通过服务端核验" : "工作台会话尚未核验"}</p>
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
          <form id="page-form">${formMarkup(page)}<button type="button" class="primary" data-command="page-action" ${state.role && state.status !== "loading" ? "" : "disabled"}>${page[0] === "setup" ? "核验当前连接" : page[3] === "read" ? "读取当前视图" : "提交给服务端"}</button></form>
          <dl><dt>操作收据</dt><dd>${escapeHtml(state.receipt?.operation_id ?? "尚无")}</dd><dt>状态</dt><dd>${escapeHtml(state.receipt?.phase ?? statusTitle)}</dd></dl></aside>
        </div>
      </main>
    </div>`;
}

async function loadView() {
  const epoch = ++requestEpoch;
  if (!state.role) { Object.assign(state, applyProblem(state, { code: "role_required", message: "请填写已由服务端授权的角色范围；浏览器输入不会创建角色。" })); render(); return; }
  state.status = "loading"; state.problem = null; render();
  try {
    const result = state.view === "setup"
      ? await api.command(ACTIONS.openWorkspace, { scope: state.role, purpose: "workbench_view", input: { client_protocol: "d12.contract.v1" } })
      : await api.readView({ scope: state.role, viewType: VIEW_TYPES[state.view] });
    if (epoch !== requestEpoch) return;
    state.sessionReady = api.hasSession;
    Object.assign(state, applyResponse(state, result));
  } catch (error) {
    if (epoch !== requestEpoch) return;
    state.sessionReady = api.hasSession;
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
  if (action === "retry-session") return verifySession(true);
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
  const epoch = ++requestEpoch;
  state.status = "loading"; state.problem = null; render();
  try {
    const result = await api.command(action, { scope: state.role, purpose, input });
    if (epoch !== requestEpoch) return;
    state.sessionReady = api.hasSession;
    Object.assign(state, applyResponse(state, result));
    if (result.status === "ready" && needsFreshProjection(action)) return loadView();
  } catch (error) {
    if (epoch !== requestEpoch) return;
    state.sessionReady = api.hasSession;
    Object.assign(state, applyProblem(state, normalizeError(error)));
  }
  render();
}

async function verifySession(refreshRole = false) {
  if (refreshRole) {
    ++requestEpoch;
    api.clearSession();
    state.sessionReady = false;
    state.projection = null;
    state.receipt = null;
    state.status = "loading";
    state.problem = null;
    render();
  }
  try {
    await api.openSession();
    state.sessionReady = true;
    if (refreshRole && state.role) return loadView();
    if (!state.role) {
      state.status = "unavailable";
      state.problem = { code: "role_required", message: "会话已核验。填写已授权的角色范围后可读取能力目录。" };
    }
  } catch (error) {
    state.sessionReady = false;
    Object.assign(state, applyProblem(state, normalizeError(error)));
  }
  render();
}

app.addEventListener("click", async (event) => {
  const view = event.target.closest("[data-view]")?.dataset.view;
  if (view) {
    if (view !== state.view) { state.view = view; state.projection = null; }
    await loadView(); return;
  }
  const action = event.target.closest("[data-command]")?.dataset.command;
  if (action) await command(action);
});

app.addEventListener("keydown", (event) => {
  if (event.key === "Escape") document.querySelector("#sidebar")?.classList.remove("open");
  if (event.key === "Enter" && event.target.matches("#role-input")) command("switch-role");
});

render();
void verifySession();
