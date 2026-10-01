import { ref } from 'vue'

// Theme + language are set pre-paint by the inline <head> script (FOUC guard);
// these composables just read/toggle the same <html> attributes + localStorage.

export type Theme = 'dark' | 'light'
export type Lang = 'zh' | 'en'

const theme = ref<Theme>(
  (document.documentElement.getAttribute('data-theme') as Theme) || 'dark',
)
const lang = ref<Lang>(
  (document.documentElement.getAttribute('data-lang') as Lang) || 'zh',
)

export function useTheme() {
  function setTheme(t: Theme) {
    theme.value = t
    document.documentElement.setAttribute('data-theme', t)
    try {
      localStorage.setItem('sylanne_theme', t)
    } catch {
      /* ignore */
    }
  }
  function toggleTheme() {
    setTheme(theme.value === 'dark' ? 'light' : 'dark')
  }
  return { theme, setTheme, toggleTheme }
}

export function useLang() {
  function setLang(l: Lang) {
    lang.value = l
    document.documentElement.setAttribute('data-lang', l)
    try {
      localStorage.setItem('sylanne_lang', l)
    } catch {
      /* ignore */
    }
  }
  function toggleLang() {
    setLang(lang.value === 'zh' ? 'en' : 'zh')
  }
  return { lang, setLang, toggleLang }
}
