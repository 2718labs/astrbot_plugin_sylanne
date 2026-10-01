export const INITIALIZATION_MODES: ReadonlyArray<readonly [string, string]>;
export function validInitializationProfile(value: unknown): boolean;
export function initializationInput(mode: string, values: Record<string, unknown>, profile?: unknown): Record<string, unknown>;
export function initializationForm(values: Record<string, unknown>, profile?: unknown): string;
export function initializationProjection(profile: unknown, receipt?: unknown): string;
