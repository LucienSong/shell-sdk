export type HexString = `0x${string}`;
export type AddressLike = string;

export interface ShellAccessListItem {
  address: AddressLike;
  storage_keys: HexString[];
}

export interface ShellTransactionRequest {
  chain_id: number;
  nonce: number;
  to: AddressLike | null;
  value: string;
  data: HexString;
  gas_limit: number;
  max_fee_per_gas: number;
  max_priority_fee_per_gas: number;
  access_list?: ShellAccessListItem[] | null;
  tx_type?: number;
  max_fee_per_blob_gas?: number | null;
  blob_versioned_hashes?: HexString[] | null;
}

export type SignatureTypeName = "Dilithium3" | "MlDsa65" | "SphincsSha2256f";

export interface ShellSignature {
  sig_type: SignatureTypeName;
  data: number[];
}

export interface SignedShellTransaction {
  from: AddressLike;
  tx: ShellTransactionRequest;
  signature: ShellSignature;
  sender_pubkey?: number[] | null;
}

export interface ShellTxByAddressPage {
  address: AddressLike;
  page: number;
  limit: number;
  total: number;
  transactions: unknown[];
}

export interface ShellSendTransactionParams {
  signedTransaction: SignedShellTransaction;
}

export interface ShellKdfParams {
  m_cost: number;
  t_cost: number;
  p_cost: number;
  salt: string;
}

export interface ShellCipherParams {
  nonce: string;
}

export interface ShellEncryptedKey {
  version: number;
  address: string;
  key_type: string;
  kdf: string;
  kdf_params: ShellKdfParams;
  cipher: string;
  cipher_params: ShellCipherParams;
  ciphertext: string;
  public_key: string;
}
