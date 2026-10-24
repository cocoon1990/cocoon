/* tslint:disable */
/* eslint-disable */

export class PhantomSession {
    free(): void;
    [Symbol.dispose](): void;
    /**
     * ساخت HMAC-signed URL برای Streaming Worker
     * این URL به Worker ثابت می‌کند که درخواست از client معتبر می‌آید
     */
    build_stream_url(target_url: string): string;
    /**
     * از بین بردن صریح session — فراخوانی در 'beforeunload' event
     * ZeroizeOnDrop هم به صورت خودکار در drop() اجرا می‌شود
     */
    destroy(): void;
    /**
     * رمزنگاری payload برای Apps Script با AES-256-GCM
     */
    encrypt_payload(plaintext: string): string;
    /**
     * ساخت Session جدید
     * hmac_key_hex: کلید HMAC به صورت hex string (از Signaling Worker دریافت می‌شود)
     * aes_key_hex: کلید AES-256-GCM به صورت hex string
     */
    constructor(hmac_key_hex: string, aes_key_hex: string, streaming_endpoint: string, signaling_endpoint: string, gas_endpoints_json: string);
    /**
     * آمارگیری session — برای debugging در browser console
     */
    stats(): string;
}

export class SessionHandshake {
    free(): void;
    [Symbol.dispose](): void;
    /**
     * باز کردن پاسخ سرور.
     * خروجی: JSON به شکل `{"hmac_key_hex":"...","aes_key_hex":"..."}`
     */
    complete(server_pubkey_b64: string, salt_b64: string, wrapped_b64: string): string;
    /**
     * ساخت keypair موقت X25519
     */
    constructor();
    /**
     * کلید عمومی به base64 — همین رشته به `/session-init` می‌رود
     */
    public_key_b64(): string;
}

/**
 * Constant-time string comparison — جلوگیری از timing attack
 */
export function constant_time_eq(a: string, b: string): boolean;

/**
 * مقداردهی اولیه Router از JSON Config
 * باید یک بار در ابتدای Service Worker فراخوانی شود.
 * config_json: محتوای ghost-routing-config.json که از KV خوانده شده
 */
export function init_router(config_json: string): void;

/**
 * بررسی اینکه Router مقداردهی اولیه شده است یا نه
 */
export function is_router_initialized(): boolean;

/**
 * تصمیم‌گیری routing — فراخوانی از Service Worker fetch handler
 * بازگشت: JSON string حاوی RouteDecision
 * مثال فراخوانی در JS:
 *   const decision = JSON.parse(route_request(url, contentType, sizeHint));
 */
export function route_request(url: string, content_type: string, size_hint: number): string;

export function start(): void;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly __wbg_phantomsession_free: (a: number, b: number) => void;
    readonly __wbg_sessionhandshake_free: (a: number, b: number) => void;
    readonly constant_time_eq: (a: number, b: number, c: number, d: number) => number;
    readonly init_router: (a: number, b: number, c: number) => void;
    readonly is_router_initialized: () => number;
    readonly phantomsession_build_stream_url: (a: number, b: number, c: number, d: number) => void;
    readonly phantomsession_destroy: (a: number) => void;
    readonly phantomsession_encrypt_payload: (a: number, b: number, c: number, d: number) => void;
    readonly phantomsession_new: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number) => void;
    readonly phantomsession_stats: (a: number, b: number) => void;
    readonly route_request: (a: number, b: number, c: number, d: number, e: number, f: number) => void;
    readonly sessionhandshake_complete: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number) => void;
    readonly sessionhandshake_new: (a: number) => void;
    readonly sessionhandshake_public_key_b64: (a: number, b: number) => void;
    readonly start: () => void;
    readonly __wbindgen_export: (a: number, b: number) => number;
    readonly __wbindgen_export2: (a: number, b: number, c: number, d: number) => number;
    readonly __wbindgen_export3: (a: number) => void;
    readonly __wbindgen_export4: (a: number, b: number, c: number) => void;
    readonly __wbindgen_add_to_stack_pointer: (a: number) => number;
    readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
 * Instantiates the given `module`, which can either be bytes or
 * a precompiled `WebAssembly.Module`.
 *
 * @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
 *
 * @returns {InitOutput}
 */
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
 *
 * @returns {Promise<InitOutput>}
 */
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
