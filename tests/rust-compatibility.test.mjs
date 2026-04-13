import assert from 'node:assert/strict';
import test from 'node:test';

import { derivePqAddressFromPublicKey, normalizeHexAddress } from '../dist/address.js';
import { hashTransaction, hexBytes } from '../dist/transactions.js';

import fixture from './fixtures/rust-compatibility.json' with { type: 'json' };

test('rust compatibility: address derivation vectors match shell-chain', () => {
  for (const vector of fixture.addresses) {
    const publicKey = hexToBytes(vector.public_key_hex);
    const derived = derivePqAddressFromPublicKey(publicKey, vector.algo_id);

    assert.equal(derived, vector.pq_address, `pq address mismatch for ${vector.name}`);
    assert.equal(normalizeHexAddress(derived), vector.hex_address, `hex address mismatch for ${vector.name}`);
  }
});

test('rust compatibility: transaction hash vectors match shell-chain', () => {
  for (const vector of fixture.transactions) {
    const hash = hashTransaction(vector.tx);
    assert.equal(hexBytes(hash), vector.hash_hex, `tx hash mismatch for ${vector.name}`);
  }
});

function hexToBytes(hex) {
  const clean = hex.replace(/^0x/, '');
  const bytes = new Uint8Array(clean.length / 2);
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = parseInt(clean.slice(index * 2, index * 2 + 2), 16);
  }
  return bytes;
}
