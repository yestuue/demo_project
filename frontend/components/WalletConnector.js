"use client";

import { useState } from "react";
import { BrowserProvider } from "ethers";
import { SiweMessage } from "siwe";
import { api } from "@/lib/api";

export function WalletConnector() {
  const [wallet, setWallet] = useState(null);
  const [loading, setLoading] = useState(false);
  const [session, setSession] = useState(null);

  const handleSignIn = async () => {
    if (!window.ethereum) {
      alert("Ethereum wallet extension not detected! Please install MetaMask.");
      return;
    }

    setLoading(true);
    try {
      // 1. Connect wallet and get the address
      const provider = new BrowserProvider(window.ethereum);
      const accounts = await provider.send("eth_requestAccounts", []);
      const address = accounts[0];
      const signer = await provider.getSigner();
      
      setWallet(address);

      // 2. Fetch the challenge nonce from your backend endpoint
      const nonceResponse = await api("/auth/nonce", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ walletAddress: address }),
      });

      const { nonce } = nonceResponse;

      // 3. Prepare the standard SIWE message
      const siweMessage = new SiweMessage({
        domain: window.location.host,
        address: address,
        statement: "Sign in with Ethereum to the NFT Airdrop Platform.",
        uri: window.location.origin,
        version: "1",
        chainId: 1, 
        nonce: nonce,
      });

      const preparedMessage = siweMessage.prepareMessage();

      // 4. Request signature from the wallet
      const signature = await signer.signMessage(preparedMessage);

      // 5. Verify signature on the backend
      const verifyResponse = await api("/auth/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ message: preparedMessage, signature }),
      });

      if (verifyResponse.success) {
        setSession(verifyResponse.user);
        alert("Authentication successful!");
      }
    } catch (error) {
      console.error("Authentication error:", error);
      alert("Web3 authentication failed.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="flex items-center gap-3">
      {session ? (
        <div className="rounded-2xl border border-emerald-500/30 bg-emerald-500/10 px-4 py-2 text-xs font-mono text-emerald-400">
          Connected: {wallet.substring(0, 6)}...{wallet.substring(wallet.length - 4)}
        </div>
      ) : (
        <button
          onClick={handleSignIn}
          disabled={loading}
          className="rounded-2xl border border-brand-500 bg-brand-500/20 px-5 py-2 text-sm font-semibold text-white transition hover:bg-brand-500/40 disabled:opacity-50"
        >
          {loading ? "Authenticating..." : "Connect Wallet"}
        </button>
      )}
    </div>
  );
}