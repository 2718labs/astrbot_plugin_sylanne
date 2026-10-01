import { createRouter, createWebHashHistory } from 'vue-router'
import { getToken, usesHostAuthentication } from '../api/client'
import DashboardLayout from '../components/shell/DashboardLayout.vue'
import LoginView from '../views/LoginView.vue'
import MonitorView from '../views/MonitorView.vue'
import CognitionView from '../views/CognitionView.vue'
import ConfigView from '../views/ConfigView.vue'
import LogsView from '../views/LogsView.vue'
import MemoryView from '../views/MemoryView.vue'
import PersonalityView from '../views/PersonalityView.vue'
import LifeView from '../views/LifeView.vue'
import AdminView from '../views/AdminView.vue'

// Hash history: the SPA ships as a single file served from arbitrary paths
// (standalone '/' or AstrBot-native '/astrbot_plugin_sylanne/dashboard') with
// no server-side route config — hash routing is the safe choice.
const router = createRouter({
  history: createWebHashHistory(),
  routes: [
    { path: '/login', name: 'login', component: LoginView, meta: { public: true } },
    {
      path: '/',
      component: DashboardLayout,
      children: [
        { path: '', redirect: '/monitor' },
        { path: 'monitor', name: 'monitor', component: MonitorView },
        { path: 'cognition', name: 'cognition', component: CognitionView },
        { path: 'config', name: 'config', component: ConfigView },
        { path: 'logs', name: 'logs', component: LogsView },
        { path: 'memory', name: 'memory', component: MemoryView },
        { path: 'personality', name: 'personality', component: PersonalityView },
        { path: 'life', name: 'life', component: LifeView },
        { path: 'admin', name: 'admin', component: AdminView },
      ],
    },
    { path: '/:pathMatch(.*)*', redirect: '/monitor' },
  ],
})

router.beforeEach((to) => {
  if (usesHostAuthentication()) {
    if (to.name === 'login') return { name: 'monitor' }
    return true
  }
  if (to.meta.public) return true
  if (!getToken()) return { name: 'login', query: { redirect: to.fullPath } }
  return true
})

export default router
