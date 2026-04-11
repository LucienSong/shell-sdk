/**
 * Concrete SignerAdapter implementations for each PQ algorithm.
 *
 * @noble/post-quantum provides ML-DSA-65 and SLH-DSA-SHA2-256f.
 * Dilithium3 (pre-FIPS Round-3) uses MlDsa65Adapter as a stand-in.
 */

import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";
import { slh_dsa_sha2_256f } from "@noble/post-quantum/slh-dsa.js";

import type { SignerAdapter } from "./signer.js";
import type { SignatureTypeName } from "./types.js";

export interface MlDsa65KeyPair { publicKey: Uint8Array; secretKey: Uint8Array; }
export interface SlhDsaKeyPair { publicKey: Uint8Array; secretKey: Uint8Array; }

export function generateMlDsa65KeyPair(seed?: Uint8Array): MlDsa65KeyPair {
  const s = seed ?? crypto.getRandomValues(new Uint8Array(32));
  return ml_dsa65.keygen(s);
}

export function generateSlhDsaKeyPair(seed?: Uint8Array): SlhDsaKeyPair {
  const s = seed ?? crypto.getRandomValues(new Uint8Array(96));
  return slh_dsa_sha2_256f.keygen(s);
}

export class MlDsa65Adapter implements SignerAdapter {
  constructor(
    private readonly _publicKey: Uint8Array,
    private readonly _secretKey: Uint8Array,
  ) {}

  static generate(seed?: Uint8Array): MlDsa65Adapter {
    const kp = generateMlDsa65KeyPair(seed);
    return new MlDsa65Adapter(kp.publicKey, kp.secretKey);
  }

  static fromKeyPair(pk: Uint8Array, sk: Uint8Array): MlDsa65Adapter {
    return new MlDsa65Adapter(pk, sk);
  }

  getPublicKey(): Uint8Array { return this._publicKey; }

  async sign(message: Uint8Array): Promise<Uint8Array> {
    return ml_dsa65.sign(this._secretKey, message);
  }
}

export class SlhDsaAdapter implements SignerAdapter {
  constructor(
    private readonly _publicKey: Uint8Array,
    private readonly _secretKey: Uint8Array,
  ) {}

  static generate(seed?: Uint8Array): SlhDsaAdapter {
    const kp = generateSlhDsaKeyPair(seed);
    return new SlhDsaAdapter(kp.publicKey, kp.secretKey);
  }

  static fromKeyPair(pk: Uint8Array, sk: Uint8Array): SlhDsaAdapter {
    return new SlhDsaAdapter(pk, sk);
  }

  getPublicKey(): Uint8Array { return this._publicKey; }

  async sign(message: Uint8Array): Promise<Uint8Array> {
    return slh_dsa_sha2_256f.sign(this._secretKey, message);
  }
}

/** Generate a fresh adapter for the given algorithm. */
export function generateAdapter(algorithm: SignatureTypeName, seed?: Uint8Array): SignerAdapter {
  switch (algorithm) {
    case "Dilithium3":
    case "MlDsa65":
      return MlDsa65Adapter.generate(seed);
    case "SphincsSha2256f":
      return SlhDsaAdapter.generate(seed ? seed.slice(0, 96) : undefined);
    default:
      throw new Error("unsupported algorithm: " + algorithm);
  }
}

/** Build adapter from an existing key pair (e.g. from keystore). */
export function adapterFromKeyPair(
  algorithm: SignatureTypeName,
  publicKey: Uint8Array,
  secretKey: Uint8Array,
): SignerAdapter {
  switch (algorithm) {
    case "Dilithium3":
    case "MlDsa65":
      return MlDsa65Adapter.fromKeyPair(publicKey, secretKey);
    case "SphincsSha2256f":
      return SlhDsaAdapter.fromKeyPair(publicKey, secretKey);
    default:
      throw new Error("unsupported algorithm: " + algorithm);
  }
}
