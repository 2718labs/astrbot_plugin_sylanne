<script setup lang="ts">
import { computed } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useI18n } from '../../composables/useI18n'
import { useInteractionFeedback } from '../../composables/useInteractionFeedback'
import { useTheme, useLang } from '../../composables/useTheme'
import { useAuthStore } from '../../stores/auth'
import { useScopeStore } from '../../stores/scope'
import { useLiveStore } from '../../stores/live'
import { usesHostAuthentication } from '../../api/client'

const router = useRouter()
const route = useRoute()
const { t } = useI18n()

const pageName = computed(() => {
  const n = route.name
  return typeof n === 'string' ? t('nav.' + n) : ''
})
const { theme, toggleTheme } = useTheme()
const { lang, toggleLang } = useLang()
const auth = useAuthStore()
const scope = useScopeStore()
const live = useLiveStore()
const feedback = useInteractionFeedback()

const online = computed(() => !!live.state && !live.error)
const canLogout = !usesHostAuthentication()

type ScopeTier = 'bot' | 'persona' | 'session'

async function onScopeChange(tier: ScopeTier, e: Event): Promise<void> {
  const ref = (e.target as HTMLSelectElement).value
  if (tier === 'bot') scope.selectBot(ref)
  if (tier === 'persona') scope.selectPersona(ref)
  if (tier === 'session') scope.selectSession(ref)
  const selected = scope.selection.sessionRef || scope.selection.personaRef || scope.selection.botRef
  feedback.show(
    `${t('feedback.session_switching')} · ${selected}`,
    'neutral',
    { sticky: true },
  )
  const applied = await live.fetchOnce()
  if (applied) {
    feedback.show(`${t('feedback.session_switched')} · ${scope.selection.sessionRef}`, 'success')
  } else {
    feedback.clear()
  }
}
function onThemeToggle(): void {
  toggleTheme()
  feedback.show(t('feedback.theme_switched'))
}
function onLanguageToggle(): void {
  toggleLang()
  feedback.show(t('feedback.language_switched'))
}
function logout(): void {
  auth.logout()
  void router.replace({ name: 'login' })
}
</script>

<template>
  <header class="top">
    <div class="left">
      <div class="brand">
        <span class="brand-name">SYLANNE</span>
        <span class="brand-sub">{{ t('app.title') }}</span>
      </div>
      <span v-if="pageName" class="page-sep" aria-hidden="true" />
      <span v-if="pageName" class="page-name">{{ pageName }}</span>
    </div>

    <div class="controls">
      <span class="status" :class="{ on: online }">
        <i class="status-dot" />
        {{ online ? t('chrome.online') : t('chrome.offline') }}
      </span>

      <select
        v-if="scope.bots.length"
        class="scope-pill mono"
        :value="scope.selection.botRef"
        title="Bot"
        @change="onScopeChange('bot', $event)"
      >
        <option value="" disabled>Bot</option>
        <option v-for="bot in scope.bots" :key="bot" :value="bot">{{ bot }}</option>
      </select>

      <select
        v-if="scope.selection.botRef"
        class="scope-pill mono"
        :value="scope.selection.personaRef"
        title="Persona"
        @change="onScopeChange('persona', $event)"
      >
        <option value="" disabled>Persona</option>
        <option v-for="persona in scope.personas" :key="persona" :value="persona">{{ persona }}</option>
      </select>

      <select
        v-if="scope.selection.personaRef"
        class="scope-pill mono"
        :value="scope.selection.sessionRef"
        :title="t('chrome.session')"
        @change="onScopeChange('session', $event)"
      >
        <option value="" disabled>{{ t('chrome.session') }}</option>
        <option v-for="session in scope.sessions" :key="session" :value="session">{{ session }}</option>
      </select>

      <button class="chip" :title="t('chrome.theme')" @click="onThemeToggle">
        {{ theme === 'dark' ? '☾' : '☀' }}
      </button>
      <button class="chip mono" :title="t('chrome.lang')" @click="onLanguageToggle">
        {{ lang === 'zh' ? '中' : 'EN' }}
      </button>
      <button
        v-if="canLogout"
        class="chip logout-chip"
        :title="t('chrome.logout')"
        @click="logout"
      >
        {{ t('chrome.logout') }}
      </button>
    </div>
  </header>
</template>

<style scoped>
.top {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0 var(--space-8);
  border-bottom: 1px solid var(--card-border);
}
.left {
  display: flex;
  align-items: center;
  gap: var(--space-6);
}
.brand {
  display: flex;
  align-items: baseline;
  gap: var(--space-4);
}
.page-sep {
  width: 1px;
  height: 18px;
  background: var(--card-border);
}
.page-name {
  font-size: var(--font-sm);
  letter-spacing: 2px;
  text-transform: uppercase;
  color: var(--accent);
  text-shadow: var(--glow-text);
}
.brand-name {
  font-size: var(--font-md);
  font-weight: 700;
  letter-spacing: 3px;
  color: var(--accent);
}
.brand-sub {
  font-size: var(--font-xs);
  letter-spacing: 2px;
  color: var(--text-muted);
}
.controls {
  display: flex;
  align-items: center;
  gap: var(--space-4);
}
.status {
  display: inline-flex;
  align-items: center;
  gap: var(--space-2);
  font-size: var(--font-xs);
  letter-spacing: 1px;
  color: var(--text-muted);
}
.status-dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  background: var(--text-muted);
}
.status.on .status-dot {
  background: var(--green);
  animation: dotBreath 3.2s ease-in-out infinite;
}
.scope-pill {
  background: var(--card);
  border: 1px solid var(--card-border);
  border-radius: var(--r-pill);
  color: var(--text);
  font-size: var(--font-xs);
  padding: var(--space-2) var(--space-5);
  max-width: 200px;
  cursor: pointer;
}
.chip {
  background: var(--card);
  border: 1px solid var(--card-border);
  border-radius: var(--r-pill);
  color: var(--text);
  width: 30px;
  height: 26px;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  font-size: var(--font-sm);
  transition: border-color var(--dur-fast) ease;
}
.logout-chip {
  width: auto;
  min-width: fit-content;
  padding: 0 var(--space-3);
  font-size: var(--font-xs);
  white-space: nowrap;
}
.chip:hover {
  border-color: var(--accent);
}

@media (max-width: 620px) {
  .top {
    gap: var(--space-2);
    padding: 0 var(--space-3);
  }
  .left,
  .controls {
    min-width: 0;
  }
  .brand-sub,
  .page-sep,
  .page-name,
  .status {
    display: none;
  }
  .brand-name {
    font-size: var(--font-sm);
    letter-spacing: 2px;
  }
  .controls {
    flex: 1;
    justify-content: flex-end;
    gap: var(--space-2);
  }
  .scope-pill {
    width: clamp(72px, 24vw, 100px);
    min-width: 0;
    padding: var(--space-2) var(--space-3);
  }
  .chip {
    width: 26px;
    flex: none;
  }
  .logout-chip {
    width: auto;
    padding: 0 var(--space-2);
  }
}

@media (max-width: 420px) {
  .top {
    align-items: center;
    flex-wrap: nowrap;
    min-width: 0;
    overflow: hidden;
  }
  .left {
    flex: 0 0 auto;
  }
  .controls {
    width: auto;
    min-width: 0;
    flex: 1 1 0;
    flex-wrap: nowrap;
    justify-content: flex-start;
    overflow-x: auto;
    overflow-y: hidden;
    scrollbar-width: none;
  }
  .controls::-webkit-scrollbar {
    display: none;
  }
  .scope-pill {
    flex: 0 0 72px;
    width: 72px;
    max-width: 72px;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .logout-chip {
    flex: none;
  }
}
</style>
