# SN118 service treasury v2: three separately held wallets

Status: **design for review; no production allocation, wallet, or payment is authorized**.
The existing v1 policy is shadow only, has two fixed fields and a 500 bps cap.
This proposal supersedes its 25 bps GM / 25 bps maintenance example. It does
not reinterpret any stored v1 revision or turn the current signer prototype on.

## Economic contract

Use basis points of the **released miner vector**, after the separately governed
burn decision. For a released fraction `R = 1 - burn_share`, service bucket
`i` receives `R * bucket_bps[i] / 10_000` of the miner vector. The remainder
of `R` goes to eligible miners. An empty eligible vector still follows the
existing burn fallback; it is never swept into a service wallet. At today's
`burn_share=1`, every service bucket receives zero, regardless of its shadow
target. Scoring recovery, screening admission, treasury allocation and burn
changes are independent decisions.

The requested initial target is **1,000 bps for GM credits**. Bitsec audit and
Bitcast advertising buckets start at zero until their shares, budgets and
owners are explicitly reviewed. The open economic decision is whether 1,000
bps caps all service buckets together or applies to GM alone. The active
validator path must not be implemented or enabled until this is settled in a
revisioned policy. No service bucket may borrow another bucket's allocation.

## Wallet identity and custody

**Recommend one collector hotkey with three holding coldkeys, subject to custody
review before the active weight path is built.** The current shadow schema
instead models one registered hotkey per service wallet. The collector design
uses one registered hotkey and three separately controlled
holding coldkeys. Validators would route only the reviewed aggregate service
share to the collector. After finality, a guarded, reconciled
[`transfer_stake`](https://github.com/latent-to/developer-docs/blob/main/docs/navigating-subtensor/subtensor-extrinsics.md)
could move each bucket's SN118 stake from the collector coldkey to its holding
coldkey while retaining the same hotkey. This would give each service a distinct
on-chain balance without adding three emission recipients or occupying three
registration slots. It introduces a collector custody window and requires
exactly-once sweep accounting, independent signer review, and a tested rollback.
Holding SN118 stake is not the same as a spendable TAO balance; a provider
payment would need a separate reviewed conversion and transfer.
It is preferable because the validator has one bounded treasury recipient and
service wallets do not occupy separate miner registration slots. The current
shadow schema describes the direct-recipient option only; it must be revised
for the recommended custody model or explicitly approved before any validator
implementation.

Under the recommended design, each purpose gets a dedicated, publicly
identified holding coldkey:

| Bucket | Purpose | Initial bps | Holding wallet | Spend destination |
| --- | --- | ---: | --- | --- |
| `gm_credits` | GM inference credit | 1,000 proposed | dedicated coldkey holding swept SN118 stake | current GM Billing instructions |
| `bitsec_audits` | independent security audits | 0 | separate coldkey holding swept SN118 stake | approved Bitsec invoice |
| `bitcast_ads` | advertising campaigns | 0 | separate coldkey holding swept SN118 stake | approved Bitcast campaign invoice |

The collector hotkey must be registered on SN118 and independently verified
as owned by the collector coldkey, distinct from the subnet owner's burn
hotkey. Each holding coldkey must be independently controlled and distinct
from the collector and the other holders. A wallet label or SS58 address alone
does not prove custody. Signing keys need separate access scopes; Platform and
Backroom retain no signing authority. The current single-key signer cannot
manage all bucket wallets without a custody and recovery review. Draft
host-activation PR #2327 stays dormant.

The existing personal wallet
`5Ecr5EGwvg2Xue2MdeJeCVSMLYWYuGcFb7y41eo7rQy3mGDN` is historical
payment evidence, **not** the proposed treasury custody wallet. Four outgoing
TAO transfers went to the same
`5FqbWhtCvoSD3X3iNxyWXogrKGmeVLnjZXoNWPx16yErYQd9` address:

| User's GM top-up row | Candidate chain transfer |
| --- | --- |
| September 13, $200 | [0.852283908 TAO](https://taostats.io/extrinsic/9062791-0015), September 14 02:11 UTC / September 13 22:11 Toronto |
| September 18, $250 | [1.002844206 TAO](https://taostats.io/extrinsic/9095188-0019), September 18 14:39 UTC |
| September 27, $1,000 | [3.073733948 TAO](https://taostats.io/extrinsic/9161565-0011), September 27 20:35 UTC |
| September 28, $1,000 | [3.270986440 TAO](https://taostats.io/extrinsic/9167610-0004), September 28 16:44 UTC |

[GM's own buybacks page](https://saygm.com/buybacks) identifies that address
as its treasury. The dates, destination, and approximate values strongly link
these transfers to the user's four `X402-Relayed` top-ups. The chain receipts
still do not identify the GM account credited or prove each exact billing-row
match. Correlate GM deposit references and conversion times before using them
as an automated payment template. The public treasury address is not
necessarily the currently instructed direct-deposit address for a new payment.

## Allocation, settlement and publication

1. A versioned policy lists stable bucket IDs, bps, registered receiving
   hotkeys, coldkeys, purpose, spending cap, and an independently approved
   revision. Unknown bucket IDs or missing wallet identity make a nonzero
   proposal invalid. A v1 revision remains subject to its original 500 bps
   cap; it is never upgraded by interpretation.
2. Validators must pin the exact policy revision and independently verify each
   recipient's registration and ownership before constructing weights. All
   serving validators must agree on recipients, rounding and the burn fallback.
   Any missing/stale recipient or policy discrepancy fails closed to the
   already reviewed miner/burn path, never to an arbitrary wallet.
3. Finalized chain receipts, validator weight telemetry, actual stake ownership
   and per-bucket balance form the source of spendable funds. A shadow quote or
   expected emissions cannot authorize spending. Every conversion, transfer,
   invoice and provider credit belongs to exactly one bucket and one immutable
   policy revision in a public receipt feed without leaking secrets.
4. GM's documented Billing flow currently requires the account owner to link
   the exact sender wallet and obtain **current** payment instructions. Its
   documented API exposes credit-balance reads, not a purchase endpoint. The
   existing daily timer may request a top-up, but unattended signing remains
   disabled until a documented, authenticated payment contract and reliable
   account-level reconciliation are demonstrated. An `X402-Relayed` row by
   itself does not establish that contract. Bitsec and Bitcast require their
   own reviewed invoices, payees, spending approvals and reconciliation rules.

The existing `ditto/treasury/store.py` journal is GM-specific (`gm_alpha_rao`,
`maintenance_alpha_rao`, and one top-up plan). Its `execute_one_leg` entry point
is deliberately blocked before signing. It must not be treated as a generic
three-service payment engine. Add a bucket-scoped, finalized-receipt sweep
journal first; keep each provider's payment adapter separate and blocked until
its own authenticated instructions and reconciliation proof exist.

## Activation sequence

1. Settle the total-cap and denominator decisions publicly; review miner
   economics, custody, recipient identity and wallet recovery. Keep the
   policy shadow-only and all three bps zero in production while doing so.
2. Land backwards-compatible shadow-policy and read-only chain/receipt code.
   Prove the old 500 bps revisions retain their meaning and the new policy
   rejects duplicate buckets, repeated wallets and overflow. A shadow wallet
   string is a proposal, never proof of custody; the active weight path must
   reject every nonzero recipient until registration and ownership are verified
   on a finalized block. Hosted CI and an independent exact-head review are
   required before merge.
3. Choose direct recipients or one collector plus holding coldkeys. Review and
   register only the chosen keys through a protected ceremony, after an exact
   infrastructure plan and explicit action-time approval. Verify finalized
   ownership, signer isolation, recovery and public read-only visibility. Do
   not activate #2327 merely because its Terraform is valid.
4. Ship a validator implementation behind a default-off flag. Rehearse zero
   allocation, small shadow forecasts, rounding and every chosen recipient
   failure path across every serving validator version. If using a collector,
   rehearse the separate finalized-stake sweep and per-bucket reconciliation.
   Publish expected versus actual finalized receipts before positive routing.
5. Coordinate a separate burn/release decision with screening and scoring
   recovery. Activate one small, time-bounded allocation with an immediate
   zero rollback, audit finalized funds and public receipts, then increase only
   through a new reviewed revision. No automatic service payment is implied by
   receipt of emissions.

No part of this design opens screening admission, changes GCE capacity,
adjusts live weights/burn, provisions a secret, registers a wallet, or pays a
provider.
