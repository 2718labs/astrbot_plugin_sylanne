// DEV-ONLY mock. Gated by `import.meta.env.DEV`, so Vite dead-code-eliminates
// this whole path from the production singlefile build (import.meta.env.DEV
// === false at build time). It exists purely so `pnpm dev` can show the full
// dashboard with plausible data when no real backend is running — and it only
// kicks in as a FALLBACK after a real fetch fails, so a live backend (via the
// dev proxy) always wins. This is NOT the old shipped mock-fallback anti-pattern.

function jitter(base: number, amp = 0.04): number {
  return Math.max(0, Math.min(1, base + (Math.random() - 0.5) * amp))
}

function mockState(): Record<string, unknown> {
  const layers: Record<string, unknown> = {}
  for (let i = 1; i <= 7; i++) {
    layers['L' + i] = {
      avg: 1.5 + Math.random() * 5,
      p95: 4 + Math.random() * 8,
      count: 40 + Math.floor(Math.random() * 200),
    }
  }
  return {
    schema_version: 3,
    runtime: 'dev-mock',
    current_session: 'qq:private:2300184498',
    session_id: 'qq:private:2300184498',
    emotion: {
      warmth: jitter(0.62),
      arousal: jitter(0.41),
      valence: jitter(0.35),
      tension: jitter(0.28),
      curiosity: jitter(0.55),
      repair_pressure: jitter(0.18),
      expression_drive: jitter(0.71),
      boundary_firmness: jitter(0.66),
    },
    boundary: {
      integrity: jitter(0.9, 0.02),
      entropy: jitter(0.12),
      rotation: jitter(0.34),
      repair_rate: jitter(0.8, 0.02),
    },
    route_distribution: {
      FAST: 120 + Math.floor(Math.random() * 10),
      NORMAL: 44 + Math.floor(Math.random() * 8),
      FULL: 190 + Math.floor(Math.random() * 12),
      SKIP: 22 + Math.floor(Math.random() * 5),
    },
    gate: {
      surprise: jitter(0.33),
      threshold: 0.4,
      route: ['FAST', 'NORMAL', 'FULL'][Math.floor(Math.random() * 3)],
    },
    expression: {
      mode: ['speak', 'hold', 'reach'][Math.floor(Math.random() * 3)],
      pressure: jitter(0.71),
      threshold: 0.4,
    },
    feedback: { positive: 14, negative: 2, neutral: 5 },
    layers,
    sessions: [
      { id: 'qq:private:2300184498', name: 'qq:private:2300184498', ticks: 412 },
      { id: 'qq:group:10086', name: 'qq:group:10086', ticks: 88 },
    ],
    csrf_token: 'dev-mock-csrf',
    personality: {
      five: {
        openness: jitter(0.68),
        warmth: jitter(0.62),
        intensity: jitter(0.74),
        autonomy: jitter(0.58),
        resilience: jitter(0.7),
      },
      six: [
        { name: '傲娇', value: jitter(0.81), color: '#ff6b9d' },
        { name: '嘴硬', value: jitter(0.66), color: '#ffa94d' },
        { name: '专业', value: jitter(0.88), color: '#4dabf7' },
        { name: '粘人', value: jitter(0.44), color: '#c084fc' },
        { name: '克制', value: jitter(0.57), color: '#63e6be' },
        { name: '警觉', value: jitter(0.39), color: '#ff8787' },
      ],
      drift: [
        { time: '2026-07-04 23:12', text: '边界完整度短暂下探后自愈，未触发熔断' },
        { time: '2026-07-04 18:40', text: '连续正反馈后表达驱动小幅上扬' },
        { time: '2026-07-03 09:05', text: '夜间低唤醒区间，温度维持基线' },
      ],
    },
  }
}

function mockV2CoreState(): Record<string, unknown> {
  return {
    enabled: true,
    session: 'qq:private:2300184498',
    sessions: [
      { id: 'qq:private:2300184498', name: 'qq:private:2300184498', ticks: 412 },
      { id: 'qq:group:10086', name: 'qq:group:10086', ticks: 88 },
    ],
    fragment: '窗外雨声很轻，手边的咖啡凉了一半，还在想刚才那句话该怎么接。',
    decision: {
      action: ['speak', 'hold', 'reach'][Math.floor(Math.random() * 3)],
      g_speak: jitter(0.62),
      g_hold: jitter(0.24),
      g_reach: jitter(0.14),
      eff_drive: jitter(0.71),
      express_at: 0.4,
      outcome: 'expressed',
      silent_reason: '',
      quality: jitter(0.77),
    },
    body: {
      warmth: jitter(0.62),
      arousal: jitter(0.41),
    },
    domains: {
      emotion: {
        warmth: jitter(0.62),
        valence: jitter(0.35),
        arousal: jitter(0.41),
        tension: jitter(0.28),
        volatility: jitter(0.22),
        trend: jitter(0.5, 0.2) - 0.5,
        unexpressed: jitter(0.18),
        line: '温度平稳偏暖，张力可控',
      },
      usermodel: {
        synchrony: jitter(0.7),
        grip: jitter(0.55),
        rhythm_ema: jitter(0.63),
        disposition: {
          warmth: jitter(0.6),
          engagement: jitter(0.72),
          defensiveness: jitter(0.2),
          distress: jitter(0.12),
        },
        line: '对话节奏同步度良好',
      },
      narrative: {
        epoch: 12,
        rigidity: jitter(0.31),
        ossification: jitter(0.15),
        anchor_count: 7,
        anchor_total: 20,
        line: '叙事自我锚点稳定增长中',
      },
      distill: {
        fidelity: jitter(0.84),
        samples: 156,
        mean_error: jitter(0.06, 0.02),
      },
    },
  }
}

function mockSettings(): Record<string, unknown> {
  return {
    schema: {
      llm_temperature: { description: 'LLM 采样温度', type: 'float', default: 0.8 },
      llm_max_tokens: { description: '单次回复最大 token 数', type: 'int', default: 800 },
      persona_name: { description: '人格显示名', type: 'string', default: 'Sylanne' },
      enable_proactive_chat: { description: '启用主动对话', type: 'bool', default: true },
      enable_memory_consolidation: { description: '启用记忆整理', type: 'bool', default: true },
      gate_surprise_threshold: { description: '门控惊异阈值', type: 'float', default: 0.4 },
      log_level: {
        description: '日志级别',
        type: 'options',
        default: 'info',
        options: ['debug', 'info', 'warn', 'error'],
      },
      sylanne_alpha_life_simulation_enabled: {
        description: '启用生活模拟（alpha）',
        type: 'bool',
        default: false,
      },
      sylanne_alpha_life_simulation_share_intensity: {
        description: '主动分享强度（alpha）',
        type: 'options',
        default: 'standard',
        options: ['off', 'low', 'standard', 'high'],
      },
      internal_debug_seed: {
        description: '内部调试种子（不可见）',
        type: 'int',
        default: 0,
        invisible: true,
      },
    },
    values: {
      llm_temperature: 0.8,
      llm_max_tokens: 800,
      persona_name: 'Sylanne',
      enable_proactive_chat: true,
      enable_memory_consolidation: true,
      gate_surprise_threshold: 0.4,
      log_level: 'info',
      sylanne_alpha_life_simulation_enabled: false,
      sylanne_alpha_life_simulation_share_intensity: 'standard',
      internal_debug_seed: 0,
    },
    providers: [
      { id: 'openai-gpt', name: 'OpenAI GPT-4o', type: 'chat_completion' },
      { id: 'anthropic-claude', name: 'Claude 3.5', type: 'chat_completion' },
    ],
  }
}

function mockConfigPresets(): unknown {
  return {
    presets: [
      { id: 'balanced', name: '均衡模式' },
      { id: 'intense', name: '高强度模式' },
      { id: 'quiet', name: '静默模式' },
    ],
  }
}

function mockComputationLogs(): Record<string, unknown> {
  const routes = ['FAST', 'NORMAL', 'FULL', 'SKIP']
  const msgs = [
    '门控通过，进入表达裁决',
    '惊异值低于阈值，跳过全量计算',
    '记忆检索命中 L2 温存储',
    '边界完整度校验通过',
    '叙事锚点更新',
    '情绪账本写入',
  ]
  const logs = []
  const now = Date.now()
  for (let i = 0; i < 30; i++) {
    const route = routes[Math.floor(Math.random() * routes.length)]
    logs.push({
      route,
      ts: (now - i * 60_000) / 1000,
      msg: msgs[Math.floor(Math.random() * msgs.length)],
      layers: { L1: jitter(0.5) * 5, L4: jitter(0.5) * 8 },
    })
  }
  return {
    logs,
    total: 3402,
    total_for_session: 412,
    session: 'qq:private:2300184498',
  }
}

function mockErrorStats(): unknown {
  return {
    total: 3,
    recent: [
      { time: new Date(Date.now() - 3_600_000).toISOString(), route: 'FULL', msg: 'LLM timeout, retried' },
      { time: new Date(Date.now() - 7_200_000).toISOString(), route: 'NORMAL', msg: 'embedding backend 503' },
    ],
  }
}

function mockMemoryPools(): Record<string, unknown> {
  const hot = [
    { content: '刚才聊到周末去看展的事', weight: jitter(0.8), age: 2, created_at: new Date().toISOString() },
    { content: '他说加班到很晚，有点心疼', weight: jitter(0.75), age: 5, created_at: new Date().toISOString() },
  ]
  const warm = [
    { summary: '上周讨论过毕业设计的选题方向', weight: jitter(0.5), age: 40 },
    { summary: '提到过喜欢下雨天', weight: jitter(0.45), age: 55 },
  ]
  const nodes = [
    { content: '身份锚点：MIT EECS 在读', weight: jitter(0.9) },
    { content: '关系锚点：异地恋，QQ 主要联络', weight: jitter(0.85) },
  ]
  const edges = [
    { content: '身份锚点 -> 关系锚点', weight: jitter(0.6) },
  ]
  return {
    layers: {
      l1_hot: { label: 'L1 热池', count: hot.length, items: hot },
      l2_warm: { label: 'L2 温池', count: warm.length, items: warm },
      l3_cold: { nodes, edges },
    },
    hot,
    warm,
    cold: nodes,
    summary: {
      total: 212,
      l1_count: hot.length,
      l2_count: warm.length,
      l3_node_count: nodes.length,
      l3_edge_count: edges.length,
      embedded: 198,
      avg_weight: jitter(0.6),
      avg_temperature: jitter(0.5),
    },
    sessions: [{ id: 'qq:private:2300184498', name: 'qq:private:2300184498' }],
    session: 'qq:private:2300184498',
    mode: 'hot',
  }
}

function mockLifeStatus(): Record<string, unknown> {
  return {
    available: true,
    enabled: true,
    world: {
      phase: 'evening',
      local_date: '2026-07-05',
      energy: jitter(0.66),
      focus: jitter(0.58),
      current_activity_id: 'act-reading',
      last_tick_at: new Date().toISOString(),
      seconds_since_tick: 42,
    },
    current_activity: { id: 'act-reading', title: '在看一本关于分布式系统的书' },
    counts: { simulation_count: 812, outreach_count: 26, events_total: 340 },
    timing: { avg_tick_ms: 120 },
    recent_events: [],
    distribution: { work: 0.4, rest: 0.3, social: 0.2, idle: 0.1 },
    prompt_fragment_preview: '刚泡了杯茶，在等一个编译跑完。',
  }
}

function mockLifeEvents(): Record<string, unknown> {
  const types = ['simulation', 'outreach', 'milestone']
  const events = []
  const now = Date.now()
  for (let i = 0; i < 8; i++) {
    events.push({
      event_id: 'evt-' + i,
      text: [
        '写了一段调参脚本，跑了三次才收敛',
        '想起来还没回复一条消息，有点不好意思',
        '看到一篇有意思的论文，标记了待读',
        '和朋友吐槽了一下今天的会议',
        '试着煮了个新菜谱，火候差点意思',
        '深夜emo了一下，翻了翻旧聊天记录',
        '完成了一个小项目的里程碑',
        '窗外下雨，心情跟着静了下来',
      ][i],
      event_type: types[i % types.length],
      timestamp: (now - i * 3_600_000) / 1000,
      source: 'life_sim',
      importance: jitter(0.5),
      wants_to_share: i % 3 === 0,
      shared: i % 3 === 0 && i !== 0,
      project_id: i % 2 === 0 ? 'proj-thesis' : undefined,
      origin_session: 'qq:private:2300184498',
      privacy_level: 'normal',
    })
  }
  return { events, available: true }
}

function mockLifeProjects(): Record<string, unknown> {
  return {
    projects: [
      { title: '毕业设计：分布式调度器', kind: 'work', state: 'active', progress: jitter(0.62), share_policy: 'auto', effectiveness: jitter(0.7) },
      { title: '学一点新的绘画技巧', kind: 'hobby', state: 'active', progress: jitter(0.3), share_policy: 'manual', effectiveness: jitter(0.55) },
    ],
    skills: [
      { name: '时间管理', effectiveness: jitter(0.68), success_count: 40, failure_count: 6 },
      { name: '情绪复盘', effectiveness: jitter(0.72), success_count: 55, failure_count: 9 },
      { name: '主动求助', effectiveness: jitter(0.5), success_count: 20, failure_count: 14 },
    ],
    available: true,
  }
}

function mockLifeAudit(): Record<string, unknown> {
  return {
    audit: {
      'qq:private:2300184498': [
        {
          kind: 'share',
          intent_id: 'intent-1',
          ts: (Date.now() - 1_800_000) / 1000,
          feedback_status: 'allowed',
        },
        {
          kind: 'share',
          intent_id: 'intent-2',
          ts: (Date.now() - 5_400_000) / 1000,
          feedback_status: 'blocked',
        },
      ],
    },
    available: true,
  }
}

function mockAdminInspect(): Record<string, unknown> {
  return {
    session: 'qq:private:2300184498',
    kv_keys: {
      primary: { exists: true, bytes: 48213, version: 'v3' },
      v2_backup: { exists: true, bytes: 47990, version: 'v3', crc_valid: true },
      quarantine: { exists: false, bytes: null, version: null },
    },
    hydrated: true,
    incarnation_epoch: 7,
    current_epoch: 7,
    epoch_matches: true,
    queue_depth: 0,
    throat_stats: {
      reject_count: 2,
      rebuild_count: 1,
      dropped_no_loop_count: 0,
      active_sessions: 3,
      tracked_epochs: 7,
    },
    has_pending_delete: false,
  }
}

function mockAdminQuarantineView(): Record<string, unknown> {
  return {
    session: 'qq:private:2300184498',
    sessions: {
      'qq:private:2300184498': { count: 0, items: [] },
      'qq:group:10086': {
        count: 2,
        items: [
          { reason: 'crc_mismatch', epoch: 5, ts: (Date.now() - 3_600_000) / 1000 },
          { reason: 'epoch_stale', epoch: 4, ts: (Date.now() - 9_000_000) / 1000 },
        ],
      },
    },
    total_entries: 2,
    note: 'quarantine entries are retained for manual inspection only; nothing is auto-deleted',
  }
}

function mockAdminPendingDeletes(): Record<string, unknown> {
  return {
    scan_done: true,
    entries: {
      'qq:group:99999': { epoch: 3, ts: (Date.now() - 1_800_000) / 1000 },
    },
    count: 1,
  }
}

// Return a mock payload for a known GET path, or undefined to signal "no mock".
export function devMock(path: string, method: string): unknown {
  const clean = path.split('?')[0]
  if (method === 'GET') {
    if (clean.endsWith('/api/state')) return mockState()
    if (clean.endsWith('/api/v2core_state')) return mockV2CoreState()
    if (clean.endsWith('/api/settings')) return mockSettings()
    if (clean.endsWith('/api/config_presets')) return mockConfigPresets()
    if (clean.endsWith('/api/computation_logs')) return mockComputationLogs()
    if (clean.endsWith('/api/error_stats')) return mockErrorStats()
    if (clean.endsWith('/api/memory_pools')) return mockMemoryPools()
    if (clean.endsWith('/api/meltdown_nonce')) return { nonce: 'DV42' }
    if (clean.endsWith('/api/memory_sink')) return { ok: true, sunk: 4 }
    if (clean.endsWith('/api/life/status')) return mockLifeStatus()
    if (clean.endsWith('/api/life/events')) return mockLifeEvents()
    if (clean.endsWith('/api/life/projects')) return mockLifeProjects()
    if (clean.endsWith('/api/life/audit')) return mockLifeAudit()
    if (clean.endsWith('/api/admin/inspect')) return mockAdminInspect()
    if (clean.endsWith('/api/admin/quarantine_view')) return mockAdminQuarantineView()
    if (clean.endsWith('/api/admin/pending_deletes')) return mockAdminPendingDeletes()
    return undefined
  }
  if (method === 'POST') {
    if (clean.endsWith('/api/settings')) return { ok: true, updated: [] }
    if (clean.endsWith('/api/life/controls')) return { ok: true }
    if (clean.endsWith('/api/memory_consolidate')) return { ok: true, estimated_seconds: 3 }
    if (clean.endsWith('/api/memory_meltdown')) return { ok: true, cleared: true }
    return undefined
  }
  return undefined
}
