import { ACTIONS, VIEW_TYPES, makeOwnerLoginRequest } from "./api/contract.js";
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
let sessionCheckEpoch = 0;
let ownerFlowEpoch = 0;
let installation = null;
let installationProblem = null;
let ownerBusy = false;
let ownerChallenge = null;
let ownerSigningPayload = "";
let ownerSignature = "";
let ownerProblem = null;
const ownerDraft = {};

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>'"]/g, (character) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;" })[character]);
}

function statusCopy(status, problem) {
  if (problem?.code === "owner_session_locked") return ["Owner 尚未解锁", "AstrBot 控制台已登录。Sylanne Owner 会话尚未建立或已失效；角色内容和操作保持锁定。"];
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
  if (page[0] === "setup") return `<p class="setup-hint">请仅填写管理员可信渠道提供的当前会话场景引用。聊天消息不会授权或自动绑定场景；服务端仍会核验角色、场景和权限，可能暂缓绑定。</p><label>场景引用<input name="scene_ref" required autocomplete="off" placeholder="scene:conversation-v1:（64 位小写十六进制值）" /></label><label>可见范围<select name="visibility" required><option value="">请选择</option><option value="private">私聊</option><option value="group">群聊</option></select></label><label class="acknowledgement"><input type="checkbox" name="acknowledgement" required /><span>我确认此引用及可见范围由管理员可信渠道提供，且适用于当前角色。</span></label>`;
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

function ownerLoginMarkup() {
  const problem = ownerProblem ? `<p class="owner-problem" role="alert">${escapeHtml(ownerProblem.message)}</p>` : "";
  if (state.sessionReady) {
    return `<section class="owner-login"><h3>Owner 已解锁</h3><p>工作台会话已由服务端核验。退出会立即清除当前页面中的角色投影。</p>${problem}<button type="button" class="quiet" data-command="owner-logout" ${ownerBusy ? "disabled" : ""}>退出 Owner</button></section>`;
  }
  if (!globalThis.location?.origin?.startsWith("https://")) {
    return `<section class="owner-login"><h3>Owner 待配对</h3><p>Owner 签名登录需要受信 HTTPS 工作台地址。当前地址不能建立安全 Owner 会话；请从已配置的 HTTPS 入口打开工作台。</p>${problem}</section>`;
  }
  if (ownerChallenge) {
    return `<section class="owner-login"><h3>离线签名</h3><p>将下面的 Base64 解码为原始字节，用已登记的 Owner Ed25519 私钥在本机签名。只把 64 字节签名的标准 Base64 填回这里。私钥不要输入工作台或发送给服务端。</p>
      ${problem}<label>待签名原文（Base64）<textarea id="owner-signing-payload" readonly spellcheck="false">${escapeHtml(ownerSigningPayload)}</textarea></label>
      <p>挑战有效期至 ${escapeHtml(ownerChallenge.expires_at_utc)}。刷新页面后需重新获取挑战。</p>
      <button type="button" class="quiet" data-command="copy-owner-payload">复制待签名原文</button>
      <label>签名（标准 Base64）<textarea id="owner-signature" autocomplete="off" spellcheck="false" placeholder="仅粘贴签名，不要粘贴私钥">${escapeHtml(ownerSignature)}</textarea></label>
      <div class="owner-actions"><button type="button" class="primary" data-command="owner-complete" ${ownerBusy ? "disabled" : ""}>验证签名并解锁</button><button type="button" class="quiet" data-command="owner-restart" ${ownerBusy ? "disabled" : ""}>重新开始</button></div></section>`;
  }
  const fields = [
    ["authority_id", "Authority ID"], ["authority_namespace", "Authority 命名空间"],
    ["installation_id", "安装 ID"], ["identity_provider", "身份提供方"],
    ["account_ref", "Owner 账号引用"], ["account_incarnation", "账号实例"],
    ["credential_id", "已登记凭据 ID"], ["credential_epoch", "凭据版本"]
  ];
  return `<section class="owner-login"><h3>解锁 Owner</h3><p>从本机已配对的安装记录逐项填写身份与凭据引用。当前接口尚不能读取这些字段；没有真实记录时保持锁定。这里不需要私钥。</p>${problem}
    <form id="owner-login-form" autocomplete="off"><div class="owner-fields">${fields.map(([name, label]) => `<label>${label}<input name="${name}" value="${escapeHtml(ownerDraft[name] ?? "")}" ${name === "credential_epoch" ? 'type="number" min="1" step="1"' : 'type="text"'} required /></label>`).join("")}</div>
    <p>当前工作台 Origin：<code>${escapeHtml(globalThis.location?.origin ?? "待核验")}</code>。服务端会按当前安装、配对和 Origin 复核。</p>
    <button type="button" class="primary" data-command="owner-challenge" ${ownerBusy || !state.dashboardAuthenticated ? "disabled" : ""}>获取签名挑战</button></form></section>`;
}

function setupMarkup() {
  const stageNames = { limited: "能力受限", blocked: "启动受阻", enrollment_required: "需要登记", ready: "运行就绪", stopped: "已停止" };
  const reasonNames = {
    none: "无", not_started: "尚未启动", disabled: "插件未启用", configuration: "配置无效",
    data_dir: "数据目录不可用", authority_profile: "需要管理员登记 Authority",
    authority_profile_verification: "Authority 核验不可用",
    authority_profile_integrity: "Authority 资料无效",
    installation_verification: "安装核验失败",
    affect_scheme_verification: "感受方案核验失败",
    runtime_bootstrap: "运行时启动失败", namespace_activation: "命名空间启用失败",
    installed_package: "安装包未通过正式版本核验，请使用完整的正式安装包。",
    graph_worker: "图工作进程未能启动，请检查宿主诊断。",
    domain_registry: "领域模块未齐备，请检查安装包。",
    v2_fence_recovery: "Authority 操作结果待恢复，请检查宿主诊断后再继续。",
    product_ingress: "对话入口尚未接通，当前不能验证真实对话。",
    owner_guard: "Owner 授权尚未核验，需先完成 Owner 配对与授权。",
    active_role: "当前活跃角色尚未确认，需完成角色初始化并取得服务端确认。",
    scene_binding: "场景尚未绑定，需在宿主侧完成绑定并取得回执。",
    dispatch: "行动与投递出口尚未接通，当前不能发送消息。",
    runtime_unavailable: "运行状态暂不可用"
  };
  const stage = installation ? stageNames[installation.stage] : "未取得";
  const reason = installation ? (reasonNames[installation.reason] ?? "运行能力尚未齐备")
    : (installationProblem?.message ?? "正在读取宿主安装状态");
  const creationReceipt = state.receipt?.phase === "role_initialized" ? state.receipt : null;
  const sceneReceipt = state.receipt?.phase === "scene_bound" ? state.receipt : null;
  const creationHold = ["role_initialization_unavailable", "role_initialization_policy_unavailable", "role_initialization_receipt_invalid", "authority_unavailable", "invalid_provider_response"].includes(state.problem?.code);
  const steps = [
    ["插件安装与运行", stage, reason],
    ["AstrBot 控制台", state.dashboardAuthenticated ? "已登录" : "登录失效", state.dashboardAuthenticated ? "已认证，可打开工作台和查看安装状态。" : "请重新登录 AstrBot 控制台。"],
    ["Sylanne Owner", state.sessionReady ? "已解锁" : "锁定", state.sessionReady ? "服务端已复核当前可撤销 Owner 会话；每次命令还会重新复核。" : "需使用已配对的安装身份和 Owner 签名完成登录。"],
    ["角色初始化", creationReceipt ? "已初始化" : creationHold ? "HOLD" : "未核验", creationReceipt ? `服务端已确认 ${creationReceipt.role_ref}。` : creationHold ? "服务端未确认初始化；请检查安装配置和可信资源目录。" : "尚无初始化收据；模型能力和预算引用需来自可信安装资料。"],
    ["场景绑定", sceneReceipt ? "已绑定" : "未核验", sceneReceipt ? `服务端已确认 ${sceneReceipt.scene_ref}。` : "当前没有绑定成功回执；私聊或群聊不可据此视为已接通。"],
    ["验证对话", "未核验", "尚无真实对话和投递收据；不会自动向聊天场景发消息。"]
  ];
  return `<div class="setup-guide"><h2>首次使用进度</h2><p>每一步都以服务端实际状态或回执为准。</p><ol class="setup-steps">${steps.map(([label, status, detail]) => `<li><strong>${label}</strong><span>${status}</span><p>${escapeHtml(detail)}</p></li>`).join("")}</ol>${ownerLoginMarkup()}<p class="setup-next">${state.sessionReady ? (state.role ? "可提交角色初始化或场景绑定申请；只有服务端回执代表完成。" : "填写已授权的角色范围后，可读取能力目录。") : "完成 Owner 签名登录后，工作台会重新核验会话；在此之前角色内容和操作保持锁定。"}</p><button class="quiet" data-command="retry-status">刷新安装状态</button><button class="quiet" data-command="retry-session">重新核验 Owner 会话</button></div>`;
}

function render() {
  const page = pages.find(([id]) => id === state.view) ?? pages[0];
  const [statusTitle, statusDetail] = state.view === "setup" && hasVerifiedCatalogue()
    ? ["工作台会话已核验", "角色初始化、场景绑定与验证对话仍需各自的真实回执。"]
    : statusCopy(state.status, state.problem);
  const sessionVerified = state.sessionReady;
  const body = state.view === "setup" ? setupMarkup() : sessionVerified && state.projection
    ? `<pre class="projection" aria-label="服务返回的权限过滤投影">${escapeHtml(JSON.stringify(state.projection, null, 2))}</pre>`
    : `<section class="empty-state" aria-live="polite"><div class="empty-mark" aria-hidden="true">◇</div><h2>${sessionVerified ? statusTitle : "Owner 尚未解锁"}</h2><p>${sessionVerified ? statusDetail : "Sylanne Owner 会话尚未核验。请先完成服务端登录，再刷新解锁状态。"}</p><button class="primary" data-command="refresh" ${state.role && sessionVerified ? "" : "disabled"}>重新请求投影</button></section>`;
  app.innerHTML = `
    <div class="shell">
      <header class="topbar">
        <button class="menu-button" data-command="menu" aria-expanded="false" aria-controls="sidebar">菜单</button>
        <label class="role-picker">当前角色 <input id="role-input" value="${escapeHtml(state.role ?? "")}" placeholder="输入角色范围 ID" autocomplete="off" /></label>
        <button class="quiet" data-command="switch-role">切换角色</button>
        <p class="session-status ${sessionVerified ? "verified" : ""}" role="status"><span aria-hidden="true">●</span> AstrBot ${state.dashboardAuthenticated ? "已登录" : "登录失效"} · Sylanne Owner ${sessionVerified ? "已解锁" : "锁定"}</p>
      </header>
      <aside id="sidebar" class="sidebar" aria-label="工作台导航">
        <div class="brand">Sylanne <span>角色工作台</span></div>
        <nav>${pages.map(([id, label]) => `<button class="nav-item ${id === state.view ? "selected" : ""}" data-view="${id}" aria-current="${id === state.view ? "page" : "false"}">${label}</button>`).join("")}</nav>
        <p class="sidebar-note">浏览器不保存私密原文。会话复核失败或切换角色时清空当前投影。</p>
      </aside>
      <main id="workspace" tabindex="-1">
        <div class="title-row"><div><h1>${page[1]}</h1><p>${page[2]}</p></div><button class="quiet" data-command="open-workspace" ${sessionVerified ? "" : "disabled"}>刷新能力目录</button></div>
        <div class="state-banner state-${state.status}" role="status"><strong>${statusTitle}</strong><span>${statusDetail}</span></div>
        <div class="workspace-grid"><section class="projection-panel">${body}</section>
          <aside class="inspector" aria-label="操作面板"><h2>操作</h2><p>操作由服务端能力、当前作用域和版本核验。页面不会直接改图或调用平台发送。</p>
          <form id="page-form">${formMarkup(page)}<button type="button" class="primary" data-command="page-action" ${state.role && sessionVerified && state.status !== "loading" ? "" : "disabled"}>${page[0] === "setup" ? "提交场景绑定" : page[3] === "read" ? "读取当前视图" : "提交给服务端"}</button></form>
          ${page[0] === "setup" ? `<section class="owner-operation"><h3>角色初始化</h3><p>模型能力和预算目录不会由工作台推测。请从可信安装资料填写引用；服务端未配置或无法核验时会保持 HOLD。</p><form id="create-character-form"><label>角色名称<input name="display_name" required maxlength="80" /></label><label>角色预设<select name="blueprint" required><option value="">请选择</option><option value="d01.persona.warm-listener.v1">温和倾听者</option><option value="d01.persona.curious-maker.v1">好奇探索者</option></select></label><label>模型能力引用<input name="model_capability_ref" required autocomplete="off" placeholder="来自可信安装资料" /></label><label>预算引用<input name="budget_ref" required autocomplete="off" placeholder="来自可信安装资料" /></label><button type="button" class="primary" data-command="create-character" ${state.role && sessionVerified && state.status !== "loading" ? "" : "disabled"}>提交角色初始化</button></form></section>` : ""}
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
    if (error?.code === "host_session_missing") state.dashboardAuthenticated = false;
    Object.assign(state, applyProblem(state, normalizeError(error)));
  }
  render();
}

function normalizeError(error) {
  if (error instanceof WorkbenchApiError) return { code: error.code, message: error.message, retryable: error.retryable };
  return { code: "client_error", message: "工作台客户端遇到未识别错误；没有显示任何旧内容。", retryable: false };
}

function clearOwnerChallenge() {
  ownerChallenge = null;
  ownerSigningPayload = "";
  ownerSignature = "";
}

async function ownerAction(action) {
  if (action === "owner-restart") {
    ++ownerFlowEpoch;
    clearOwnerChallenge(); ownerProblem = null; render();
    return;
  }
  if (action === "copy-owner-payload") {
    try {
      await navigator.clipboard.writeText(ownerSigningPayload);
      ownerProblem = null;
    } catch {
      ownerProblem = { message: "无法自动复制；可手动复制上方待签名原文。" };
    }
    render();
    return;
  }
  if (ownerBusy) return;
  if (action === "owner-logout") {
    ++ownerFlowEpoch;
    ++sessionCheckEpoch;
    ++requestEpoch;
    ownerBusy = true;
    clearOwnerChallenge();
    ownerProblem = null;
    api.clearSession();
    state.sessionReady = false;
    Object.assign(state, applyProblem(state, { code: "owner_session_locked", message: "页面已锁定，正在等待服务端确认 Owner 退出。" }));
    render();
    try {
      await api.ownerLogout();
      state.problem = { code: "owner_session_locked", message: "Owner 已退出；角色内容已清除。" };
    } catch (error) {
      ownerProblem = normalizeError(error);
      state.problem = { code: "owner_session_locked", message: "页面已锁定；服务端退出未确认，请检查连接。" };
    } finally {
      ownerBusy = false;
      render();
    }
    return;
  }
  if (action === "owner-challenge") {
    let request;
    try {
      const form = document.querySelector("#owner-login-form");
      const values = Object.fromEntries(new FormData(form).entries());
      Object.assign(ownerDraft, values);
      request = makeOwnerLoginRequest(values, globalThis.location?.origin);
    } catch (error) {
      ownerProblem = { message: error.message };
      render();
      return;
    }
    const epoch = ++ownerFlowEpoch;
    ownerBusy = true; ownerProblem = null; render();
    try {
      const result = await api.ownerChallenge(request);
      if (epoch !== ownerFlowEpoch) return;
      ownerChallenge = result.challenge;
      ownerSigningPayload = result.signingPayloadBase64;
    } catch (error) {
      if (epoch !== ownerFlowEpoch) return;
      ownerProblem = normalizeError(error);
      if (error?.code === "host_session_missing") state.dashboardAuthenticated = false;
    } finally {
      if (epoch === ownerFlowEpoch) { ownerBusy = false; render(); }
    }
    return;
  }
  if (action === "owner-complete" && ownerChallenge) {
    ownerSignature = (document.querySelector("#owner-signature")?.value ?? ownerSignature).trim();
    if (!ownerSignature) {
      ownerProblem = { message: "请填入本机生成的 Ed25519 签名 Base64。" };
      render(); return;
    }
    const epoch = ++ownerFlowEpoch;
    const challenge = ownerChallenge;
    ownerBusy = true; ownerProblem = null; render();
    try {
      await api.ownerComplete(challenge, ownerSignature);
      if (epoch !== ownerFlowEpoch) return;
      clearOwnerChallenge();
      await verifySession(true);
    } catch (error) {
      if (epoch !== ownerFlowEpoch) return;
      clearOwnerChallenge();
      ownerProblem = normalizeError(error);
      if (error?.code === "host_session_missing") state.dashboardAuthenticated = false;
    } finally {
      if (epoch === ownerFlowEpoch) { ownerBusy = false; render(); }
    }
  }
}

async function command(action) {
  if (action === "menu") {
    const sidebar = document.querySelector("#sidebar");
    const trigger = document.querySelector("[data-command=menu]");
    const open = sidebar?.classList.toggle("open");
    trigger?.setAttribute("aria-expanded", String(Boolean(open)));
    return;
  }
  if (action?.startsWith("owner-") || action === "copy-owner-payload") return ownerAction(action);
  if (action === "switch-role") {
    const value = document.querySelector("#role-input")?.value.trim();
    Object.assign(state, switchRole(state, value)); render(); await loadView(); return;
  }
  if (action === "retry-session") return verifySession(true);
  if (action === "retry-status") return verifyInstallationStatus();
  if (action === "refresh") return loadView();
  if (action === "open-workspace") return commandAction(ACTIONS.openWorkspace, { client_protocol: "d12.contract.v1" }, "workbench_view");
  if (action === "page-action") {
    const page = pages.find(([id]) => id === state.view) ?? pages[0];
    if (page[0] === "setup") {
      try {
        const [nextAction, input] = workflowForPage("setup", Object.fromEntries(new FormData(document.querySelector("#page-form")).entries()));
        return commandAction(nextAction, input);
      } catch (error) {
        Object.assign(state, applyProblem(state, { code: "invalid_input", message: error.message, retryable: false })); render(); return;
      }
    }
    if (page[3] === "read") return loadView();
    const form = document.querySelector("#page-form");
    try {
      const [nextAction, input] = workflowForPage(page[0], Object.fromEntries(new FormData(form).entries()));
      return commandAction(nextAction, input);
    } catch (error) {
      Object.assign(state, applyProblem(state, { code: "invalid_input", message: error.message, retryable: false })); render(); return;
    }
  }
  if (action === "create-character") {
    try {
      const [nextAction, input] = workflowForPage("role-init", Object.fromEntries(new FormData(document.querySelector("#create-character-form")).entries()));
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
    if (error?.code === "host_session_missing") state.dashboardAuthenticated = false;
    Object.assign(state, applyProblem(state, normalizeError(error)));
  }
  render();
}

async function verifySession(refreshRole = false) {
  const checkEpoch = ++sessionCheckEpoch;
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
    if (checkEpoch !== sessionCheckEpoch) return;
    state.sessionReady = true;
    state.dashboardAuthenticated = true;
    if (refreshRole && state.role) return loadView();
    if (!state.role) {
      state.status = "unavailable";
      state.problem = { code: "role_required", message: "会话已核验。填写已授权的角色范围后可读取能力目录。" };
    }
  } catch (error) {
    if (checkEpoch !== sessionCheckEpoch) return;
    state.sessionReady = false;
    if (error?.code === "host_session_missing") state.dashboardAuthenticated = false;
    Object.assign(state, applyProblem(state, normalizeError(error)));
  }
  render();
}

async function verifyInstallationStatus() {
  try {
    installation = await api.installationStatus();
    installationProblem = null;
  } catch (error) {
    installation = null;
    installationProblem = normalizeError(error);
    if (error?.code === "host_session_missing") state.dashboardAuthenticated = false;
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

app.addEventListener("input", (event) => {
  if (event.target?.form?.id === "owner-login-form" && event.target.name) {
    ownerDraft[event.target.name] = event.target.value;
  }
  if (event.target?.id === "owner-signature") ownerSignature = event.target.value;
});

app.addEventListener("keydown", (event) => {
  if (event.key === "Escape") document.querySelector("#sidebar")?.classList.remove("open");
  if (event.key === "Enter" && event.target.matches("#role-input")) command("switch-role");
});

render();
void verifyInstallationStatus();
void verifySession();
