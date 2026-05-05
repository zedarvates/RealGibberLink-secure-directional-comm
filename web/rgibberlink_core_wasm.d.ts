/* tslint:disable */
/* eslint-disable */
/**
 * Initialize WebAssembly module
 */
export function main(): void;
export function greet(name: string): string;
export function get_version(): string;
export function get_build_info(): string;
/**
 * WebAssembly-compatible cryptographic utilities
 */
export class WasmCryptoEngine {
  free(): void;
  [Symbol.dispose](): void;
  /**
   * Create a new WebAssembly crypto engine
   */
  constructor();
  /**
   * Generate a random nonce
   */
  generate_nonce(): string;
  /**
   * Generate secure random bytes
   */
  generate_random_bytes(length: number): string;
  /**
   * Compute HMAC
   */
  compute_hmac(key_hex: string, data_hex: string): string;
  /**
   * Verify HMAC
   */
  verify_hmac(key_hex: string, data_hex: string, hmac_hex: string): boolean;
  /**
   * Encrypt data with AES-GCM
   */
  encrypt_data(key_hex: string, data: string): string;
  /**
   * Decrypt data with AES-GCM
   */
  decrypt_data(key_hex: string, encrypted_hex: string): string;
}
/**
 * Simplified WebAssembly-compatible protocol engine for browser demo
 * This is a synchronous version that simulates protocol operations for demonstration
 */
export class WasmProtocolEngine {
  free(): void;
  [Symbol.dispose](): void;
  /**
   * Create a new WebAssembly protocol engine
   */
  constructor();
  /**
   * Get current protocol state
   */
  get_state(): string;
  /**
   * Get communication mode
   */
  get_mode(): string;
  /**
   * Set communication mode
   */
  set_mode(mode: string): void;
  /**
   * Initiate handshake (short-range)
   */
  initiate_handshake(): void;
  /**
   * Receive nonce and generate QR code
   */
  receive_nonce(nonce_hex: string): string;
  /**
   * Process QR code payload
   */
  process_qr_payload(qr_data: string): void;
  /**
   * Receive ACK
   */
  receive_ack(): void;
  /**
   * Send text message (encrypt and return hex)
   */
  send_text_message(message: string): string;
  /**
   * Receive and decrypt message
   */
  receive_message(encrypted_hex: string): string;
  /**
   * Get pending messages (for demo purposes)
   */
  get_pending_messages(): string;
  /**
   * Get session ID
   */
  get_session_id(): string;
  /**
   * Get public key
   */
  get_public_key(): string;
  /**
   * Generate nonce
   */
  generate_nonce(): string;
  /**
   * Generate random bytes
   */
  generate_random_bytes(length: number): string;
}
/**
 * WebAssembly-compatible visual engine for QR codes
 */
export class WasmVisualEngine {
  free(): void;
  [Symbol.dispose](): void;
  /**
   * Create a new WebAssembly visual engine
   */
  constructor();
  /**
   * Generate QR code from payload
   */
  encode_payload(session_id_hex: string, public_key_hex: string, nonce_hex: string): string;
  /**
   * Decode QR code payload
   */
  decode_payload(qr_data: string): string;
}

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
  readonly memory: WebAssembly.Memory;
  readonly __wbg_wasmcryptoengine_free: (a: number, b: number) => void;
  readonly wasmcryptoengine_new: () => number;
  readonly wasmcryptoengine_generate_nonce: (a: number) => [number, number, number, number];
  readonly wasmcryptoengine_generate_random_bytes: (a: number, b: number) => [number, number, number, number];
  readonly wasmcryptoengine_compute_hmac: (a: number, b: number, c: number, d: number, e: number) => [number, number, number, number];
  readonly wasmcryptoengine_verify_hmac: (a: number, b: number, c: number, d: number, e: number, f: number, g: number) => [number, number, number];
  readonly wasmcryptoengine_encrypt_data: (a: number, b: number, c: number, d: number, e: number) => [number, number, number, number];
  readonly wasmcryptoengine_decrypt_data: (a: number, b: number, c: number, d: number, e: number) => [number, number, number, number];
  readonly __wbg_wasmvisualengine_free: (a: number, b: number) => void;
  readonly wasmvisualengine_new: () => number;
  readonly wasmvisualengine_encode_payload: (a: number, b: number, c: number, d: number, e: number, f: number, g: number) => [number, number, number, number];
  readonly wasmvisualengine_decode_payload: (a: number, b: number, c: number) => [number, number, number, number];
  readonly __wbg_wasmprotocolengine_free: (a: number, b: number) => void;
  readonly wasmprotocolengine_new: () => number;
  readonly wasmprotocolengine_get_state: (a: number) => [number, number];
  readonly wasmprotocolengine_get_mode: (a: number) => [number, number];
  readonly wasmprotocolengine_set_mode: (a: number, b: number, c: number) => [number, number];
  readonly wasmprotocolengine_initiate_handshake: (a: number) => [number, number];
  readonly wasmprotocolengine_receive_nonce: (a: number, b: number, c: number) => [number, number, number, number];
  readonly wasmprotocolengine_process_qr_payload: (a: number, b: number, c: number) => [number, number];
  readonly wasmprotocolengine_receive_ack: (a: number) => [number, number];
  readonly wasmprotocolengine_send_text_message: (a: number, b: number, c: number) => [number, number, number, number];
  readonly wasmprotocolengine_receive_message: (a: number, b: number, c: number) => [number, number, number, number];
  readonly wasmprotocolengine_get_pending_messages: (a: number) => [number, number];
  readonly wasmprotocolengine_get_session_id: (a: number) => [number, number];
  readonly wasmprotocolengine_get_public_key: (a: number) => [number, number];
  readonly wasmprotocolengine_generate_nonce: (a: number) => [number, number];
  readonly wasmprotocolengine_generate_random_bytes: (a: number, b: number) => [number, number];
  readonly main: () => void;
  readonly greet: (a: number, b: number) => [number, number];
  readonly get_version: () => [number, number];
  readonly get_build_info: () => [number, number];
  readonly __wbindgen_exn_store: (a: number) => void;
  readonly __externref_table_alloc: () => number;
  readonly __wbindgen_externrefs: WebAssembly.Table;
  readonly __externref_table_dealloc: (a: number) => void;
  readonly __wbindgen_free: (a: number, b: number, c: number) => void;
  readonly __wbindgen_malloc: (a: number, b: number) => number;
  readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
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
