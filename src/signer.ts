import { hexToBytes } from "viem";

import { derivePqAddressFromPublicKey, normalizeHexAddress, normalizePqAddress } from "./address.js";
import {
  buildSignature,
  buildSignedTransaction,
  type BuildSignedTransactionOptions,
} from "./transactions.js";
import type { SignedShellTransaction, SignatureTypeName } from "./types.js";

export const SIGNATURE_TYPE_IDS: Record<SignatureTypeName, number> = {
  Dilithium3: 0,
  MlDsa65: 1,
  SphincsSha2256f: 2,
};

export const KEY_TYPE_TO_SIGNATURE_TYPE: Record<string, SignatureTypeName> = {
  dilithium3: "Dilithium3",
  "sphincs-sha2-256f": "SphincsSha2256f",
  mldsa65: "MlDsa65",
};

export interface SignerAdapter {
  sign(message: Uint8Array): Promise<Uint8Array>;
  getPublicKey(): Uint8Array;
}

export class ShellSigner {
  readonly signatureType: SignatureTypeName;
  readonly adapter: SignerAdapter;

  constructor(signatureType: SignatureTypeName, adapter: SignerAdapter) {
    this.signatureType = signatureType;
    this.adapter = adapter;
  }

  get algorithmId(): number {
    return SIGNATURE_TYPE_IDS[this.signatureType];
  }

  getPublicKey(): Uint8Array {
    return this.adapter.getPublicKey();
  }

  getAddress(): string {
    return derivePqAddressFromPublicKey(this.getPublicKey(), this.algorithmId);
  }

  getHexAddress(): `0x${string}` {
    return normalizeHexAddress(this.getAddress());
  }

  async sign(message: Uint8Array): Promise<Uint8Array> {
    return this.adapter.sign(message);
  }

  async buildSignedTransaction(
    options: Omit<BuildSignedTransactionOptions, "from" | "signature" | "signatureType"> & {
      txHash: Uint8Array;
      includePublicKey?: boolean;
    },
  ): Promise<SignedShellTransaction> {
    const signature = await this.sign(options.txHash);

    return buildSignedTransaction({
      from: normalizePqAddress(this.getAddress()),
      tx: options.tx,
      signature,
      signatureType: this.signatureType,
      senderPubkey: options.includePublicKey ? this.getPublicKey() : undefined,
    });
  }
}

export function signatureTypeFromKeyType(keyType: string): SignatureTypeName {
  const normalized = keyType.trim().toLowerCase();
  const value = KEY_TYPE_TO_SIGNATURE_TYPE[normalized];
  if (!value) {
    throw new Error(`unsupported key type: ${keyType}`);
  }
  return value;
}

export function publicKeyFromHex(publicKeyHex: string): Uint8Array {
  return hexToBytes(`0x${publicKeyHex.replace(/^0x/i, "")}`);
}

export function buildShellSignature(signatureType: SignatureTypeName, signature: Uint8Array) {
  return buildSignature(signatureType, signature);
}
