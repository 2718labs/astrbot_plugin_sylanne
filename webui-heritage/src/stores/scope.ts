import { computed, ref } from 'vue'
import { defineStore } from 'pinia'
import { fetchScopeCatalog } from '../api/client'
import type {
  PersonaDossierResponse,
  PersonaRequestSnapshot,
  ScopeCatalogEntry,
  ScopeCatalogResponse,
  ScopeRequestSnapshot,
  ScopedApiResponse,
  ScopeSelection,
} from '../api/types'

const STORAGE_KEY = 'sylanne_scope_selection_v1'

const EMPTY_SELECTION: ScopeSelection = {
  botRef: '',
  personaRef: '',
  sessionRef: '',
}

interface PersonaSelection {
  botRef: string
  personaRef: string
}

interface PersonaGenerations {
  botGeneration: number
  personaLifecycleGeneration: number
}

function sameSelection(left: ScopeSelection, right: ScopeSelection): boolean {
  return (
    left.botRef === right.botRef &&
    left.personaRef === right.personaRef &&
    left.sessionRef === right.sessionRef
  )
}

function samePersonaSelection(left: PersonaSelection, right: PersonaSelection): boolean {
  return left.botRef === right.botRef && left.personaRef === right.personaRef
}

function samePersonaGenerations(
  left: PersonaGenerations | null,
  right: PersonaGenerations | null,
): boolean {
  return (
    left === right ||
    (left !== null &&
      right !== null &&
      left.botGeneration === right.botGeneration &&
      left.personaLifecycleGeneration === right.personaLifecycleGeneration)
  )
}

function unique(values: string[]): string[] {
  return [...new Set(values)]
}

function readStoredSelection(): ScopeSelection {
  try {
    const parsed = JSON.parse(localStorage.getItem(STORAGE_KEY) || '') as {
      schema?: unknown
      selection?: Partial<ScopeSelection>
    }
    const selection = parsed.schema === 1 ? parsed.selection : undefined
    if (
      typeof selection?.botRef === 'string' &&
      typeof selection.personaRef === 'string' &&
      typeof selection.sessionRef === 'string'
    ) {
      return {
        botRef: selection.botRef,
        personaRef: selection.personaRef,
        sessionRef: selection.sessionRef,
      }
    }
  } catch {
    // A malformed persisted choice must never select an arbitrary scope.
  }
  return { ...EMPTY_SELECTION }
}

function persistSelection(selection: ScopeSelection): void {
  try {
    if (selection.botRef && selection.personaRef && selection.sessionRef) {
      localStorage.setItem(STORAGE_KEY, JSON.stringify({ schema: 1, selection }))
    } else {
      localStorage.removeItem(STORAGE_KEY)
    }
  } catch {
    // Storage is only a convenience; the authoritative scope is the catalog.
  }
}

function matchingEntry(
  entries: ScopeCatalogEntry[],
  selection: ScopeSelection,
): ScopeCatalogEntry | undefined {
  if (!selection.botRef || !selection.personaRef || !selection.sessionRef) return undefined
  return entries.find(
    (entry) =>
      entry.scope.bot_ref === selection.botRef &&
      entry.scope.persona_ref === selection.personaRef &&
      entry.scope.session_ref === selection.sessionRef,
  )
}

function personaGenerations(
  entries: ScopeCatalogEntry[],
  selection: PersonaSelection,
): PersonaGenerations | null {
  if (!selection.botRef || !selection.personaRef) return null
  const matching = entries.filter(
    (entry) =>
      entry.scope.bot_ref === selection.botRef &&
      entry.scope.persona_ref === selection.personaRef,
  )
  if (!matching.length) return null
  const first = matching[0].generations
  if (
    matching.some(
      (entry) =>
        entry.generations.bot !== first.bot ||
        entry.generations.persona_lifecycle !== first.persona_lifecycle,
    )
  ) {
    return null
  }
  return {
    botGeneration: first.bot,
    personaLifecycleGeneration: first.persona_lifecycle,
  }
}

function reconciledSelection(
  entries: ScopeCatalogEntry[],
  previous: ScopeSelection,
): ScopeSelection {
  const bots = unique(entries.map((entry) => entry.scope.bot_ref))
  const botRef = bots.includes(previous.botRef)
    ? previous.botRef
    : bots.length === 1
      ? bots[0]
      : ''
  if (!botRef) return { ...EMPTY_SELECTION }

  const personas = unique(
    entries
      .filter((entry) => entry.scope.bot_ref === botRef)
      .map((entry) => entry.scope.persona_ref),
  )
  const personaRef = personas.includes(previous.personaRef)
    ? previous.personaRef
    : personas.length === 1
      ? personas[0]
      : ''
  if (!personaRef) return { botRef, personaRef: '', sessionRef: '' }

  const sessions = unique(
    entries
      .filter(
        (entry) =>
          entry.scope.bot_ref === botRef && entry.scope.persona_ref === personaRef,
      )
      .map((entry) => entry.scope.session_ref),
  )
  const sessionRef = sessions.includes(previous.sessionRef)
    ? previous.sessionRef
    : sessions.length === 1
      ? sessions[0]
      : ''
  return { botRef, personaRef, sessionRef }
}

export const useScopeStore = defineStore('scope', () => {
  const catalog = ref<ScopeCatalogEntry[]>([])
  const selection = ref<ScopeSelection>(readStoredSelection())
  const selectionEpoch = ref(0)
  const personaEpoch = ref(0)

  const selectedEntry = computed(() => matchingEntry(catalog.value, selection.value))
  const selectedScopeGeneration = computed<number | null>(
    () => selectedEntry.value?.generations.scope ?? null,
  )
  const selectedPersonaGenerations = computed<PersonaGenerations | null>(() =>
    personaGenerations(catalog.value, selection.value),
  )
  const selectedPersonaGeneration = computed<number | null>(
    () => selectedPersonaGenerations.value?.personaLifecycleGeneration ?? null,
  )
  const bots = computed(() => unique(catalog.value.map((entry) => entry.scope.bot_ref)))
  const personas = computed(() =>
    selection.value.botRef
      ? unique(
          catalog.value
            .filter((entry) => entry.scope.bot_ref === selection.value.botRef)
            .map((entry) => entry.scope.persona_ref),
        )
      : [],
  )
  const sessions = computed(() =>
    selection.value.botRef && selection.value.personaRef
      ? unique(
          catalog.value
            .filter(
              (entry) =>
                entry.scope.bot_ref === selection.value.botRef &&
                entry.scope.persona_ref === selection.value.personaRef,
            )
            .map((entry) => entry.scope.session_ref),
        )
      : [],
  )

  function setSelection(next: ScopeSelection): void {
    if (sameSelection(selection.value, next)) return
    const previousPersona: PersonaSelection = {
      botRef: selection.value.botRef,
      personaRef: selection.value.personaRef,
    }
    selection.value = next
    selectionEpoch.value += 1
    if (!samePersonaSelection(previousPersona, next)) {
      personaEpoch.value += 1
    }
    persistSelection(next)
  }

  function setCatalog(response: ScopeCatalogResponse): void {
    const previousSelection = { ...selection.value }
    const previousGeneration = selectedScopeGeneration.value
    const previousPersonaGenerations = selectedPersonaGenerations.value
    catalog.value = Array.isArray(response.scopes) ? response.scopes : []
    const next = reconciledSelection(catalog.value, selection.value)
    const changedSelection = !sameSelection(selection.value, next)
    const nextGeneration = matchingEntry(catalog.value, next)?.generations.scope ?? null
    if (changedSelection) {
      selection.value = next
      persistSelection(next)
    }
    const nextPersonaGenerations = selectedPersonaGenerations.value
    const personaChanged = !samePersonaSelection(previousSelection, next)
    const personaGenerationsChanged = !samePersonaGenerations(
      previousPersonaGenerations,
      nextPersonaGenerations,
    )
    if (
      changedSelection ||
      previousGeneration !== nextGeneration ||
      personaGenerationsChanged
    ) {
      selectionEpoch.value += 1
    }
    if (personaChanged || personaGenerationsChanged) personaEpoch.value += 1
  }

  async function refreshCatalog(): Promise<void> {
    setCatalog(await fetchScopeCatalog())
  }

  function selectBot(botRef: string): void {
    if (!bots.value.includes(botRef)) return
    if (selection.value.botRef === botRef) return
    setSelection({ botRef, personaRef: '', sessionRef: '' })
  }

  function selectPersona(personaRef: string): void {
    if (!selection.value.botRef || !personas.value.includes(personaRef)) return
    if (selection.value.personaRef === personaRef) return
    setSelection({
      botRef: selection.value.botRef,
      personaRef,
      sessionRef: '',
    })
  }

  function selectSession(sessionRef: string): void {
    if (
      !selection.value.botRef ||
      !selection.value.personaRef ||
      !sessions.value.includes(sessionRef)
    ) {
      return
    }
    setSelection({
      botRef: selection.value.botRef,
      personaRef: selection.value.personaRef,
      sessionRef,
    })
  }

  function snapshot(): ScopeRequestSnapshot | null {
    const generation = selectedScopeGeneration.value
    if (!selectedEntry.value || generation === null) return null
    return {
      selection: {
        botRef: selection.value.botRef,
        personaRef: selection.value.personaRef,
        sessionRef: selection.value.sessionRef,
      },
      selectionEpoch: selectionEpoch.value,
      scopeGeneration: generation,
    }
  }

  function isCurrent(snapshotValue: ScopeRequestSnapshot, response?: ScopedApiResponse): boolean {
    const current = snapshot()
    if (
      !current ||
      current.selectionEpoch !== snapshotValue.selectionEpoch ||
      current.scopeGeneration !== snapshotValue.scopeGeneration ||
      !sameSelection(current.selection, snapshotValue.selection)
    ) {
      return false
    }
    if (!response) return true
    const scope = response.scope
    const generation = response.scope_generation ?? response.generations?.scope
    return (
      scope?.bot_ref === snapshotValue.selection.botRef &&
      scope.persona_ref === snapshotValue.selection.personaRef &&
      scope.session_ref === snapshotValue.selection.sessionRef &&
      generation === snapshotValue.scopeGeneration
    )
  }

  function personaSnapshot(): PersonaRequestSnapshot | null {
    const generations = selectedPersonaGenerations.value
    if (!generations || !selection.value.botRef || !selection.value.personaRef) return null
    return {
      selection: {
        botRef: selection.value.botRef,
        personaRef: selection.value.personaRef,
      },
      personaEpoch: personaEpoch.value,
      botGeneration: generations.botGeneration,
      personaLifecycleGeneration: generations.personaLifecycleGeneration,
    }
  }

  function isPersonaCurrent(
    snapshotValue: PersonaRequestSnapshot,
    response?: PersonaDossierResponse,
  ): boolean {
    const current = personaSnapshot()
    if (
      !current ||
      current.personaEpoch !== snapshotValue.personaEpoch ||
      current.botGeneration !== snapshotValue.botGeneration ||
      current.personaLifecycleGeneration !== snapshotValue.personaLifecycleGeneration ||
      !samePersonaSelection(current.selection, snapshotValue.selection)
    ) {
      return false
    }
    if (!response) return true
    return (
      response.persona_scope.bot_ref === snapshotValue.selection.botRef &&
      response.persona_scope.persona_ref === snapshotValue.selection.personaRef &&
      response.generations.bot === snapshotValue.botGeneration &&
      response.generations.persona_lifecycle === snapshotValue.personaLifecycleGeneration
    )
  }

  return {
    catalog,
    selection,
    selectionEpoch,
    personaEpoch,
    selectedScopeGeneration,
    selectedPersonaGeneration,
    bots,
    personas,
    sessions,
    setCatalog,
    refreshCatalog,
    selectBot,
    selectPersona,
    selectSession,
    snapshot,
    isCurrent,
    personaSnapshot,
    isPersonaCurrent,
  }
})
