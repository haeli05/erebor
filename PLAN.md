# Erebor — Road to Privy Parity

## Critical Path (Phases 4–7)

These four phases turn Erebor from "solid Rust crates" into "something a developer would use instead of Privy."

---

### Phase 4: Gateway API Routes
**Goal:** Full REST API surface — a developer can curl every auth/wallet/tx endpoint.

**Files:** `crates/erebor-gateway/src/`

- `routes/auth.rs` — POST `/auth/google`, `/auth/email/send-otp`, `/auth/email/verify`, `/auth/siwe/nonce`, `/auth/siwe/verify`, `/auth/refresh`, `/auth/logout`
- `routes/users.rs` — GET `/users/me`, PATCH `/users/me`, GET `/users/:id` (admin), DELETE `/users/:id`
- `routes/wallets.rs` — POST `/wallets/create`, GET `/wallets`, GET `/wallets/:id`, POST `/wallets/:id/sign-message`, POST `/wallets/:id/sign-transaction`, POST `/wallets/:id/send-transaction`
- `routes/linking.rs` — POST `/auth/link`, DELETE `/auth/link/:provider`, GET `/auth/linked-accounts`
- `state.rs` — Shared app state wiring (auth service, vault service, chain service)
- `error.rs` — Unified API error responses with proper HTTP status codes

**Dependencies:** All four existing crates, PostgreSQL (sqlx), Redis.

---

### Phase 5: Transaction Signing + Broadcast
**Goal:** Sign and submit transactions to real chains. Nonce management, gas bumping, confirmations.

**Files:** `crates/erebor-chain/src/`

- `tx.rs` — `TransactionBuilder` (EIP-1559 + legacy), nonce manager (per-address atomic counter with Redis), `SignedTransaction` type
- `broadcast.rs` — `Broadcaster` trait, `EvmBroadcaster` (eth_sendRawTransaction, pending tx tracking, gas bump on stale, confirmation polling), `SolanaBroadcaster` stub
- `signer.rs` — Bridge between vault (key derivation) and chain (signing). Reconstruct key → sign → zeroize. Never holds key material longer than one function scope.
- Update `lib.rs` — `ChainService` gains `sign_and_send()`, `get_transaction()`, `estimate_gas()`

**Key design:**
- Nonce manager: Redis INCR per (chain_id, address). Handles gaps via periodic sync with on-chain nonce.
- Gas bumping: If tx pending > 30s, resubmit with 10% higher gas. Max 3 bumps.
- Confirmation: Poll receipt with exponential backoff. Return tx hash immediately, confirmation via webhook/polling.

---

### Phase 6: React SDK (`@erebor/react`)
**Goal:** `npm install @erebor/react` gives you `useErebor()`, login modal, wallet hooks — drop-in Privy replacement.

**Directory:** `sdks/react/`

**Package structure:**
```
sdks/react/
├── package.json          (@erebor/react)
├── tsconfig.json
├── src/
│   ├── index.ts          (public API exports)
│   ├── EreborProvider.tsx (context provider — wraps app, holds config + state)
│   ├── hooks/
│   │   ├── useErebor.ts      (login/logout/user/ready state)
│   │   ├── useWallets.ts     (list wallets, active wallet, create wallet)
│   │   ├── useSignMessage.ts (sign arbitrary messages)
│   │   ├── useSendTransaction.ts (build + sign + broadcast)
│   │   └── useAuth.ts        (lower-level: linkAccount, unlinkAccount)
│   ├── components/
│   │   ├── LoginModal.tsx     (pre-built modal: email, google, wallet buttons)
│   │   ├── WalletButton.tsx   (connect/disconnect button)
│   │   └── TransactionStatus.tsx
│   ├── api/
│   │   └── client.ts         (typed fetch wrapper for all gateway endpoints)
│   ├── iframe/
│   │   ├── IframeController.ts  (postMessage bridge to embedded wallet iframe)
│   │   └── iframe.html          (minimal HTML served from gateway — runs key ops)
│   └── types.ts
└── README.md
```

**Key hooks API:**
```tsx
const { login, logout, user, ready, authenticated } = useErebor();
const { wallets, createWallet, activeWallet } = useWallets();
const { signMessage } = useSignMessage();
const { sendTransaction } = useSendTransaction();
```

**LoginModal supports:** Email OTP, Google OAuth, SIWE (injected wallet), more providers as added.

---

### Phase 7: Embedded Wallet Iframe
**Goal:** Key operations (sign, derive) run in a cross-origin iframe. App never touches private keys.

**How it works:**
1. Gateway serves `/_erebor/iframe.html` on a separate origin (e.g., `vault.erebor.localhost`)
2. React SDK spawns invisible iframe pointing to this origin
3. All sign/derive operations go through `postMessage` to iframe
4. Iframe holds decrypted device share in memory (never exposed to parent)
5. Server share + device share = 2-of-3 threshold met → sign in iframe → return signature

**Files:**
- `crates/erebor-gateway/src/iframe.rs` — Serve iframe HTML with strict CSP headers
- `sdks/react/src/iframe/IframeController.ts` — postMessage protocol (request/response with nonces)
- `sdks/react/src/iframe/iframe.html` — Minimal page: receives share, derives key, signs, returns signature, zeroizes
- `sdks/react/src/iframe/worker.ts` — Web Worker for CPU-heavy crypto (optional, keeps UI responsive)

**Security model:**
- Iframe origin ≠ app origin → app JS cannot read iframe memory
- CSP: `frame-ancestors` restricted to registered app domains
- Device share encrypted at rest in iframe origin's localStorage (encrypted with user password / biometric)
- Server compromise alone = useless (only has server share)
- App compromise alone = useless (can't read iframe memory)
- Both compromised = still need user's device share password

---

## Implementation Order

Each phase builds on the last. No phase is useful without the ones before it.

```
Phase 4 (Gateway routes)     ← makes the backend usable via HTTP
    ↓
Phase 5 (Tx signing)         ← makes wallets actually do something
    ↓
Phase 6 (React SDK)          ← makes it usable by developers
    ↓
Phase 7 (Iframe isolation)   ← makes it production-secure
```

## After Parity (Phases 8–12)

- **Phase 8:** OAuth providers — Apple (ASAuthorizationAppleIDProvider), Twitter (OAuth 2.0 PKCE), Discord, GitHub, Farcaster (SIWF)
- **Phase 9:** Policy engine — DSL for rules (spending limits, geo, time windows), condition sets, aggregation queries
- **Phase 10:** Mobile SDKs — React Native (Expo), Swift (SPM), Kotlin (Maven)
- **Phase 11:** MPC-TSS — CGGMP21 protocol replaces Shamir for threshold signing without reconstruction
- **Phase 12:** TEE/HSM — Intel SGX/AWS Nitro enclaves for key operations, Helm charts for k8s deployment
