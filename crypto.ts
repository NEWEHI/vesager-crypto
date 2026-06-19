/**
 * Vesager — Client-side encryption core (PVN1)
 *
 * Design constraints (per project spec):
 *  - Server NEVER sees plaintext, the fragment key, or any value that alone could
 *    reconstruct the AES encryption key.
 *  - Primary key ("fragment key") lives only in the URL fragment (#...), never sent over the wire.
 *  - Optional password adds a second factor. The password is run through PBKDF2 once, then
 *    HKDF-expanded into TWO domain-separated, cryptographically independent sub-keys:
 *      - `encryptionContribution` — stays in the browser, feeds into the final AES key.
 *      - `serverVerifier`        — sent to the server's open_note RPC so it can gate access
 *                                  and enforce the 5-failed-attempt wipe rule.
 *    Because the two sub-keys are HKDF outputs with different `info` labels, knowing one does
 *    not reveal the other. The server therefore never receives anything usable to derive the
 *    actual encryption key — even a full database breach does not yield plaintext, since the
 *    fragment key was never transmitted to or stored on the server in the first place.
 *  - AES-256-GCM for authenticated encryption (confidentiality + integrity in one step).
 *  - This file is the part intended for open-source release; it stays self-contained and free
 *    of any server/business logic.
 */

const AES_KEY_LENGTH_BITS = 256;
const GCM_IV_LENGTH_BYTES = 12; // 96-bit IV, recommended size for AES-GCM
const FRAGMENT_KEY_LENGTH_BYTES = 32; // 256-bit random fragment key
const PBKDF2_SALT_LENGTH_BYTES = 16;
const PBKDF2_ITERATIONS = 600_000; // OWASP 2023+ guidance for PBKDF2-SHA256

const HKDF_INFO_FINAL_NO_PASSWORD = utf8("vesager-v1:final-key:no-password");
const HKDF_INFO_FINAL_WITH_PASSWORD = utf8("vesager-v1:final-key:with-password");
const HKDF_INFO_PASSWORD_ENC_CONTRIBUTION = utf8("vesager-v1:password-subkey:encryption");
const HKDF_INFO_PASSWORD_SERVER_VERIFIER = utf8("vesager-v1:password-subkey:server-verifier");

function utf8(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

/**
 * TypeScript's DOM lib types Uint8Array generically over ArrayBufferLike (which includes
 * SharedArrayBuffer), while the WebCrypto BufferSource type expects a plain ArrayBuffer-backed
 * view. At runtime every Uint8Array we construct here is always ArrayBuffer-backed (we never
 * use SharedArrayBuffer), so this cast is purely satisfying the type checker, not changing
 * behavior.
 */
function bs(bytes: Uint8Array): BufferSource {
  return bytes as unknown as BufferSource;
}

// ---------- Encoding helpers (base64url, no padding — safe for URLs and RPC params) ----------

export function bytesToBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  const base64 = btoa(binary);
  return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function base64UrlToBytes(b64url: string): Uint8Array {
  const base64 = b64url.replace(/-/g, "+").replace(/_/g, "/");
  const padded = base64 + "===".slice((base64.length + 3) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

// ---------- Fragment key (the part that lives after # in the URL) ----------

/** Generates a fresh random 256-bit key. This becomes the URL fragment. */
export function generateFragmentKey(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(FRAGMENT_KEY_LENGTH_BYTES));
}

export const fragmentKeyToString = bytesToBase64Url;
export const fragmentKeyFromString = base64UrlToBytes;

// ---------- Password → two independent sub-keys (enc contribution + server verifier) ----------

export function generatePasswordSalt(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(PBKDF2_SALT_LENGTH_BYTES));
}

export interface PasswordKeyMaterial {
  /** Stays in the browser. Feeds into the final AES key. Never sent to the server. */
  encryptionContribution: Uint8Array;
  /** Sent to the server's open_note RPC for password gating / attempt counting only. */
  serverVerifier: Uint8Array;
}

/**
 * Runs PBKDF2 once (the expensive, ~hundreds-of-ms step) and HKDF-expands the result into
 * two cryptographically independent 256-bit sub-keys. Call this once per password entry —
 * do not call it twice (once "for encryption" and once "for verification") as that would
 * needlessly double the PBKDF2 cost felt by the user.
 */
export async function derivePasswordKeyMaterial(
  password: string,
  salt: Uint8Array
): Promise<PasswordKeyMaterial> {
  const pbkdf2KeyMaterial = await crypto.subtle.importKey(
    "raw",
    bs(utf8(password)),
    "PBKDF2",
    false,
    ["deriveBits"]
  );
  const masterBits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt: bs(salt), iterations: PBKDF2_ITERATIONS, hash: "SHA-256" },
    pbkdf2KeyMaterial,
    AES_KEY_LENGTH_BITS
  );
  const master = new Uint8Array(masterBits);

  const hkdfMaster = await crypto.subtle.importKey("raw", bs(master), "HKDF", false, ["deriveBits"]);

  const [encryptionContribution, serverVerifier] = await Promise.all([
    hkdfExpand(hkdfMaster, HKDF_INFO_PASSWORD_ENC_CONTRIBUTION),
    hkdfExpand(hkdfMaster, HKDF_INFO_PASSWORD_SERVER_VERIFIER),
  ]);

  return { encryptionContribution, serverVerifier };
}

async function hkdfExpand(hkdfKeyMaterial: CryptoKey, info: Uint8Array): Promise<Uint8Array> {
  const bits = await crypto.subtle.deriveBits(
    { name: "HKDF", hash: "SHA-256", salt: bs(new Uint8Array(0)), info: bs(info) },
    hkdfKeyMaterial,
    AES_KEY_LENGTH_BITS
  );
  return new Uint8Array(bits);
}

// ---------- Final AES key derivation (combines fragment key + optional password contribution) ----------

async function deriveAesKey(
  fragmentKeyBytes: Uint8Array,
  encryptionContribution: Uint8Array | null
): Promise<CryptoKey> {
  const ikm = encryptionContribution
    ? concatBytes(fragmentKeyBytes, encryptionContribution)
    : fragmentKeyBytes;
  const info = encryptionContribution ? HKDF_INFO_FINAL_WITH_PASSWORD : HKDF_INFO_FINAL_NO_PASSWORD;

  const hkdfKeyMaterial = await crypto.subtle.importKey("raw", bs(ikm), "HKDF", false, ["deriveKey"]);

  return crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: bs(new Uint8Array(0)), info: bs(info) },
    hkdfKeyMaterial,
    { name: "AES-GCM", length: AES_KEY_LENGTH_BITS },
    false,
    ["encrypt", "decrypt"]
  );
}

function concatBytes(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

// ---------- Public encrypt / decrypt API ----------

export interface EncryptedPayload {
  ciphertext: string; // base64url, includes GCM auth tag
  iv: string; // base64url
}

/**
 * Encrypts plaintext. `encryptionContribution` should come from derivePasswordKeyMaterial()
 * when the note is password-protected, or be omitted/null otherwise.
 */
export async function sealNote(
  plaintext: string,
  encryptionContribution: Uint8Array | null = null
): Promise<{ payload: EncryptedPayload; fragmentKey: Uint8Array }> {
  const fragmentKeyBytes = generateFragmentKey();
  const aesKey = await deriveAesKey(fragmentKeyBytes, encryptionContribution);

  const iv = crypto.getRandomValues(new Uint8Array(GCM_IV_LENGTH_BYTES));
  const ciphertextBuffer = await crypto.subtle.encrypt({ name: "AES-GCM", iv: bs(iv) }, aesKey, bs(utf8(plaintext)));

  return {
    payload: {
      ciphertext: bytesToBase64Url(new Uint8Array(ciphertextBuffer)),
      iv: bytesToBase64Url(iv),
    },
    fragmentKey: fragmentKeyBytes,
  };
}

/**
 * Decrypts a note. Throws if the key combination is wrong (GCM auth tag check fails).
 * The server-side `serverVerifier` check should already have gated access before this is
 * ever called; this function is purely the local decryption step.
 */
export async function openNote(
  payload: EncryptedPayload,
  fragmentKeyBytes: Uint8Array,
  encryptionContribution: Uint8Array | null = null
): Promise<string> {
  const aesKey = await deriveAesKey(fragmentKeyBytes, encryptionContribution);
  const plaintextBuffer = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: bs(base64UrlToBytes(payload.iv)) },
    aesKey,
    bs(base64UrlToBytes(payload.ciphertext))
  );
  return new TextDecoder().decode(plaintextBuffer);
}
