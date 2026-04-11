import { derivePqAddressFromPublicKey, normalizeHexAddress, normalizePqAddress } from "./address.js";
import { publicKeyFromHex, signatureTypeFromKeyType, type ShellSigner } from "./signer.js";
import type { ShellEncryptedKey, SignatureTypeName } from "./types.js";

export interface ParsedShellKeystore {
  raw: ShellEncryptedKey;
  signatureType: SignatureTypeName;
  algorithmId: number;
  publicKey: Uint8Array;
  canonicalAddress: string;
  hexAddress: `0x${string}`;
}

const SIGNATURE_TYPE_ALGORITHM_IDS: Record<SignatureTypeName, number> = {
  Dilithium3: 0,
  MlDsa65: 1,
  SphincsSha2256f: 2,
};

export function parseEncryptedKey(input: string | ShellEncryptedKey): ParsedShellKeystore {
  const raw = typeof input === "string" ? (JSON.parse(input) as ShellEncryptedKey) : input;
  const signatureType = signatureTypeFromKeyType(raw.key_type);
  const algorithmId = SIGNATURE_TYPE_ALGORITHM_IDS[signatureType];
  const publicKey = publicKeyFromHex(raw.public_key);
  const canonicalAddress = derivePqAddressFromPublicKey(publicKey, algorithmId);
  const hexAddress = normalizeHexAddress(canonicalAddress);

  return {
    raw,
    signatureType,
    algorithmId,
    publicKey,
    canonicalAddress,
    hexAddress,
  };
}

export function validateEncryptedKeyAddress(input: string | ShellEncryptedKey): ParsedShellKeystore {
  const parsed = parseEncryptedKey(input);
  const declaredCanonical = normalizePqAddress(parsed.raw.address);

  if (declaredCanonical !== parsed.canonicalAddress) {
    throw new Error(
      `keystore address mismatch: declared=${declaredCanonical} derived=${parsed.canonicalAddress}`,
    );
  }

  return parsed;
}

export function exportEncryptedKeyJson(input: string | ShellEncryptedKey): string {
  const parsed = typeof input === "string" ? JSON.parse(input) : input;
  return JSON.stringify(parsed, null, 2);
}

export function assertSignerMatchesKeystore(
  signer: ShellSigner,
  keystore: ParsedShellKeystore,
): void {
  if (signer.signatureType !== keystore.signatureType) {
    throw new Error(
      `signer algorithm mismatch: signer=${signer.signatureType} keystore=${keystore.signatureType}`,
    );
  }

  const signerAddress = signer.getAddress();
  if (signerAddress !== keystore.canonicalAddress) {
    throw new Error(
      `signer address mismatch: signer=${signerAddress} keystore=${keystore.canonicalAddress}`,
    );
  }
}
