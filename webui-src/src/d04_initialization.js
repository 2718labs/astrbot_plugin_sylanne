// Explicit Owner choices only. No default clock, root state, budget or adoption.
export const INITIALIZATION_MODES = Object.freeze([
  ["d04_root_draft", "1 · 保存创作根草稿"],
  ["d04_root_budget", "2 · 分配专用计算预算"],
  ["compile_scheme", "3 · 编译根方案候选"],
  ["activate_scheme", "4 · 采用已编译创作根"],
  ["d04_root_coupling", "5 · 采用已提交根的拓扑"],
  ["d04_semantic_mapping", "6 · 审阅并采用语义映射"],
  ["d11_role_clock", "7 · 显式注册角色时钟"]
]);
const esc = (v) => String(v ?? "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const text = (v) => String(v ?? "").trim();
function integer(value, name, min = 0) {
  const raw = text(value), n = Number(raw);
  if (!/^(0|[1-9]\d*)$/.test(raw) || !Number.isSafeInteger(n) || n < min) throw new Error(`${name}必须明确填写为${min ? "正" : "非负"}整数。`);
  return n;
}
function required(value, name) {
  const v = text(value);
  if (!v || v.length > 4096) throw new Error(`请填写${name}。`);
  return v;
}
export function validInitializationProfile(p) {
  return p?.schema === "d12.d04_initialization_profile.v3"
    && /^[a-f0-9]{64}$/.test(p.profile_digest)
    && p.profile && typeof p.profile === "object" && !Array.isArray(p.profile)
    && p.profile.content_digest === p.profile_digest
    && p.clock_requires_explicit_rate_and_interval === true
    && p.root_budget_dimension === "thread_cpu_ms";
}
export function initializationInput(mode, values, profile) {
  if (values.confirm !== "on" && values.confirm !== true) throw new Error("请核对本次输入并明确确认提交。");
  switch (mode) {
    case "d04_root_draft": {
      let root;
      try { root = JSON.parse(values.root_json); } catch { throw new Error("创作根需为合法 JSON 对象。"); }
      if (!root || typeof root !== "object" || Array.isArray(root) || !Object.keys(root).length) throw new Error("创作根不能为空或为数组。");
      return { root_field: root };
    }
    case "d04_root_budget": return {parent_budget_lease_ref: required(values.parent_budget_lease_ref, "父预算引用"), ceiling: {thread_cpu_ms: integer(values.thread_cpu_ms, "CPU 毫秒上限", 1)}};
    case "compile_scheme": return {draft_ref: required(values.draft_ref, "实际草稿引用"), budget_ref: required(values.compile_budget_ref, "编译预算引用")};
    case "activate_scheme": {
      const digest = text(values.compiled_digest);
      if (!/^[a-f0-9]{64}$/.test(digest)) throw new Error("请填写编译回执中的完整摘要。");
      return {compiled_digest: digest};
    }
    case "d04_root_coupling": {
      const end = required(values.effective_until, "角色时间有效终点");
      if (!Number.isFinite(Number(end))) throw new Error("角色时间有效终点必须为有限数值。");
      return {root_operation_id: required(values.root_operation_id, "已提交根操作 ID"), effective_until: Number(end)};
    }
    case "d04_semantic_mapping":
      if (!validInitializationProfile(profile)) throw new Error("请先读取并审阅服务端当前安装的完整映射资料。");
      if (values.profile_reviewed !== "on" && values.profile_reviewed !== true) throw new Error("需明确确认已审阅完整映射与成员份额。");
      return {profile_digest: profile.profile_digest, expected_revision: integer(values.expected_revision, "当前映射版本")};
    case "d11_role_clock": {
      const out = {expected_version: integer(values.expected_version, "当前时钟版本")};
      for (const name of ["character_origin", "rate", "wall_origin_utc", "valid_from_utc", "valid_until_utc"]) {
        out[name] = required(values[name], name);
        if (out[name].length > 128) throw new Error(`${name}过长。`);
      }
      if (!/^[+-]?(?:\d+(?:\.\d*)?|\.\d+)$/.test(out.character_origin) || !/^(?:\d+(?:\.\d*)?|\.\d+)$/.test(out.rate) || !Number.isFinite(Number(out.rate)) || Number(out.rate) <= 0) throw new Error("角色起点和正速率需填写精确十进制字符串。");
      for (const name of ["wall_origin_utc", "valid_from_utc", "valid_until_utc"]) {
        if (!/Z$/.test(out[name]) || !Number.isFinite(Date.parse(out[name]))) throw new Error(`${name}需为以 Z 结尾的 UTC 时间。`);
      }
      if (Date.parse(out.valid_until_utc) <= Date.parse(out.valid_from_utc)) throw new Error("有效终点必须晚于起点。");
      return out;
    }
    default: throw new Error("请选择初始化步骤。");
  }
}
export function initializationForm(values, profile) {
  const mode = values.mode ?? "d04_root_draft";
  const input = (name, label, type = "text") => `<label>${label}<input name="${name}" type="${type}" value="${esc(values[name])}" autocomplete="off" ${["expected_revision", "expected_version"].includes(name) ? "readonly" : ""} required /></label>`;
  const fields = {
    d04_root_draft: `<p>填入明确选择的 root_field：候选 ID、时间游标、安装预设/资产摘要及各成员的轴、初始值和区间。保存草稿不会采用方案，也不会覆盖其他领域字段。</p><label>创作根 JSON<textarea name="root_json" rows="12" spellcheck="false" required>${esc(values.root_json)}</textarea></label>`,
    d04_root_budget: `<p>从实际父预算保留专用 CPU 额度；不会凭空新增预算。</p>${input("parent_budget_lease_ref", "父预算租约引用")}${input("thread_cpu_ms", "专用 CPU 上限（毫秒）")}`,
    compile_scheme: `<p>从已保存草稿编译真实候选；按实际预算计费，编译不等于采用。</p>${input("draft_ref", "实际草稿引用")}${input("compile_budget_ref", "编译预算引用")}`,
    activate_scheme: `<p>明确采用编译回执中的创作根。服务端会核对专用预算、当前预设、草稿版本和 Owner 授权。</p>${input("compiled_digest", "编译候选摘要")}`,
    d04_root_coupling: `<p>需先完成根方案的编译与真实采用。此操作只为该根采用安装包中的明确 48 条耦合，不代表观测经历。</p>${input("root_operation_id", "已提交根操作 ID")}${input("effective_until", "角色时间有效终点")}`,
    d04_semantic_mapping: `<p>先审阅左侧服务端返回的完整映射规则、样例、校准状态与份额。版本填当前权威记录；不能猜测为 0。</p>${input("expected_revision", "当前映射版本（CAS）")}<label class="acknowledgement"><input name="profile_reviewed" type="checkbox" required /><span>我已审阅完整映射，接受其工程未校准性质及明确成员份额</span></label>`,
    d11_role_clock: `<p>没有默认速率或默认有效期。十进制值保持字符串精度；所有墙钟时间用 UTC（末尾 Z）。版本冲突需重新核对，不自动覆盖。</p>${input("expected_version", "当前时钟版本（CAS）")}${input("character_origin", "角色时间起点")}${input("rate", "角色时间 / 墙钟秒速率")}${input("wall_origin_utc", "墙钟起点 UTC")}${input("valid_from_utc", "有效开始 UTC")}${input("valid_until_utc", "有效结束 UTC")}`
  };
  return `<label>初始化步骤<select name="mode" id="initialization-mode">${INITIALIZATION_MODES.map(([id,label]) => `<option value="${id}" ${id === mode ? "selected" : ""}>${label}</option>`).join("")}</select></label>${fields[mode] ?? ""}<label class="acknowledgement"><input name="confirm" type="checkbox" required /><span>我已核对当前角色、输入和影响，明确申请本步骤操作</span></label><p>超时不代表未提交。相同输入重试沿用同一操作 ID；刷新页面会丢失本地草稿，请先保存回执。</p>`;
}
export function initializationProjection(profile, receipt) {
  const receiptHtml = receipt?.operation_id && receipt?.phase ? `<h3>本次权威回执</h3><pre class="projection">${esc(JSON.stringify(receipt, null, 2))}</pre>` : "";
  if (!validInitializationProfile(profile)) return `<section class="empty-state"><h2>初始化资料待核验</h2><p>读取当前安装资料后再作明确选择。不会自动采用任何设置。</p>${receiptHtml}</section>`;
  return `<section class="initialization-profile"><h2>当前安装资料与完整语义映射</h2><p>资料摘要：<code>${esc(profile.profile_digest)}</code></p><details><summary>当前权威版本、已登记时钟与完整根预设</summary><pre class="projection">${esc(JSON.stringify(profile.current ?? null, null, 2))}</pre></details><p>完整资料包含工程样例；它们不是角色已经发生的经历。</p><pre class="projection">${esc(JSON.stringify(profile.profile, null, 2))}</pre>${receipt?.operation_id && receipt?.phase ? `<h3>本次权威回执</h3><pre class="projection">${esc(JSON.stringify(receipt, null, 2))}</pre>` : ""}</section>`;
}
