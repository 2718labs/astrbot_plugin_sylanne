export const ACTIONS: Readonly<Record<string,string>>;
export const VIEW_TYPES: Readonly<Record<string,string>>;
export function makeOwnerLoginRequest(values: Record<string, unknown>, dashboardOrigin: string): Record<string, unknown>;
export function makeRequest(action: string, options?: Record<string, unknown>): Record<string, unknown>;
