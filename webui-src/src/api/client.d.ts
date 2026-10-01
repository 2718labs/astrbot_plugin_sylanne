export const DEFAULT_WORKBENCH_API_BASE: string;
export class WorkbenchApiError extends Error {code: string; status: number; retryable: boolean; detail?: unknown;}
export class WorkbenchApi {
 constructor(options?: {baseUrl?: string; fetchImpl?: typeof fetch}); csrfToken: string | null; readonly hasSession: boolean;
 clearSession(): void; openSession(): Promise<void>;
 ownerChallenge(request: unknown): Promise<{challenge: Record<string, unknown>; signingPayloadBase64: string}>;
 ownerComplete(challenge: unknown, signatureBase64: string): Promise<void>; ownerLogout(): Promise<void>;
 command(action: string, options: Record<string, unknown>): Promise<Record<string, any>>;
 sceneCandidates(): Promise<Array<{platform_ref: string; conversation_ref: string; visibility: string; scene_ref: string}>>;
}
