import { createApp } from 'vue'
import App from './App.vue'
import './style.css'
import { initializeTheme } from './theme'

initializeTheme()

createApp(App).mount('#app')
