import { bech32m } from "@scure/base";

export const PQ_ADDRESS_HRP = "pq";
export const PQ_ADDRESS_LENGTH = 20;

type Bech32Address = `${string}1${string}`;

function assertBech32Address(value: string): asserts value is Bech32Address {
  if (!value.includes("1")) {
    throw new Error("invalid bech32m address");
  }
}

export function bytesToPqAddress(bytes: Uint8Array): string {
  if (bytes.length !== PQ_ADDRESS_LENGTH) {
    throw new Error(`expected ${PQ_ADDRESS_LENGTH} address bytes, got ${bytes.length}`);
  }

  return bech32m.encode(PQ_ADDRESS_HRP, bech32m.toWords(bytes));
}

export function pqAddressToBytes(address: string): Uint8Array {
  assertBech32Address(address);
  const { prefix, words } = bech32m.decode(address);

  if (prefix !== PQ_ADDRESS_HRP) {
    throw new Error(`expected ${PQ_ADDRESS_HRP} address prefix, got ${prefix}`);
  }

  const bytes = Uint8Array.from(bech32m.fromWords(words));
  if (bytes.length !== PQ_ADDRESS_LENGTH) {
    throw new Error(`expected ${PQ_ADDRESS_LENGTH} address bytes, got ${bytes.length}`);
  }

  return bytes;
}

export function isPqAddress(address: string): boolean {
  try {
    pqAddressToBytes(address);
    return true;
  } catch {
    return false;
  }
}
