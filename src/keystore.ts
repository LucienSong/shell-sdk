import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { argon2id } from "hash-wasm";

import { derivePqAddressFromPublicKey, normalizeHexAddress, normalizePqAddress } from "./address.js";
import { adapterFromKeyPair } from "./adapters.js";
import { ShellSigner, publicKeyFromHex, signatureTypeFromKeyType } from "./signer.js";
import type { ShellEncryptedKey, SignatureTypeName } from "./types.js";

export interface ParsedShellKeystore {
  raw: ShellEncryptedKey;
  signatureType: SignatureTypeName;
  algorithmId: number;
  publicKey: Uint8Array;
  canonicalAddress: string;
  hexAddress: string; // 0x-prefixed
}

const SIG_IDS: Record<SignatureTypeName, number> = { Dilithium3: 0, MlDsa65: 1, SphincsSha2256f: 2 };

export function parseEncryptedKey(input: string | ShellEncryptedKey): ParsedShellKeystore {
  const raw = typeof input === "string" ? (JSON.parse(input) as ShellEncryptedKey) : input;
  const signatureType = signatureTypeFromKeyType(raw.key_type);
  const algorithmId = SIG_IDS[signatureType];
  const publicKey = publicKeyFromHex(raw.public_key);
  const canonicalAddress = derivePqAddressFromPublicKey(publicKey, algorithmId);
  const hexAddress = normalizeHexAddress(canonicalAddress) as string;
  return { raw, signatureType, algorithmId, publicKey, canonicalAddress, hexAddress };
}

export function validateEncryptedKeyAddress(input: string | ShellEncryptedKey): ParsedShellKeystore {
  const parsed = parseEncryptedKey(input);
  const declared = normalizePqAddress(parsed.raw.address);
  if (declared !== parsed.canonicalAddress) {
    throw new Error("keystore address mismatch: declared=" + declared + " derived=" + parsed.canonicalAddress);
  }
  return parsed;
}

export function exportEncryptedKeyJson(input: string | ShellEncryptedKey): string {
  return JSON.stringify(typeof input === "string" ? JSON.parse(input) : input, null, 2);
}

export function assertSignerMatchesKeystore(signer: ShellSigner, keystore: ParsedShellKeystore): void {
  if (signer.signatureType !== keystore.signatureType) {
    throw new Error("algorithm mismatch: signer=" + signer.signatureType + " keystore=" + keystore.signatureType);
  }
  const addr = signer.getAddress();
  if (addr !== keystore.canonicalAddress) {
    throw new Error("address mismatch: signer=" + addr + " keystore=" + keystore.canonicalAddress);
  }
}

function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) throw new Error("invalid hex");
  const buf = new Uint8Array(hex.length / 2);
  for (let i = 0; i < buf.length; i++) buf[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return buf;
}

/**
 * Decrypt a Shell keystore file and return a ready-to-use ShellSigner.
 * KDF: argon2id | Cipher: xchacha20-poly1305 (24-byte nonce)
 * Plaintext layout: [secret_key_bytes][public_key_bytes]
 */
export async function decryptKeystore(
  input: string | ShellEncryptedKey,
  password: string,
): Promise<ShellSigner> {
  const parsed = validateEncryptedKeyAddress(input);
  const ek = parsed.raw;
  if (ek.kdf !== "argon2id") throw new Error("unsupported kdf: " + ek.kdf);
  if (ek.cipher !== "xchacha20-poly1305") throw new Error("unsupported cipher: " + ek.cipher);

  const salt = hexToBytes(ek.kdf_params.salt);
  const nonce = hexToBytes(ek.cipher_params.nonce);
  const ciphertext = hexToBytes(ek.ciphertext);

  const derivedKeyHex = await argon2id({
    password,
    salt,
    iterations: ek.kdf_params.t_cost,
    memorySize: ek.kdf_params.m_cost,
    parallelism: ek.kdf_params.p_cost,
    hashLength: 32,
    outputType: "hex",
  });
  const derivedKey = hexToBytes(derivedKeyHex);

  const chacha = xchacha20poly1305(derivedKey, nonce);
  const plaintext = chacha.decrypt(ciphertext);

  const pubkeyLen = parsed.publicKey.length;
  const skLen = plaintext.length - pubkeyLen;
  if (skLen <= 0) {
    throw new Error("payload too short: " + plaintext.length + " bytes");
  }
  const secretKey = plaintext.slice(0, skLen);
  const derivedPubkey = plaintext.slice(skLen);
  if (!derivedPubkey.every((b: number, i: number) => b === parsed.publicKey[i])) {
    throw new Error("decrypted public key mismatch");
  }

  const adapter = adapterFromKeyPair(parsed.signatureType, parsed.publicKey, secretKey);
  return new ShellSigner(parsed.signatureType, adapter);
}
