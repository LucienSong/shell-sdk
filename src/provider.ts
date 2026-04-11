import { createPublicClient, defineChain, http, type Chain, type PublicClient } from "viem";

export const shellDevnet = defineChain({
  id: 424242,
  name: "Shell Devnet",
  nativeCurrency: {
    decimals: 18,
    name: "SHELL",
    symbol: "SHELL",
  },
  rpcUrls: {
    default: {
      http: ["http://127.0.0.1:8545"],
      webSocket: ["ws://127.0.0.1:8546"],
    },
  },
});

export interface CreateShellPublicClientOptions {
  chain?: Chain;
  rpcHttpUrl?: string;
}

export function createShellPublicClient(
  options: CreateShellPublicClientOptions = {},
): PublicClient {
  const chain = options.chain ?? shellDevnet;
  const rpcHttpUrl = options.rpcHttpUrl ?? chain.rpcUrls.default.http[0];

  return createPublicClient({
    chain,
    transport: http(rpcHttpUrl),
  });
}
