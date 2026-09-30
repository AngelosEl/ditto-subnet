import { describe, expect, it } from 'vitest'
import { treasuryQuoteSchema, treasuryRouteImpactBps, treasurySettingsSchema } from './treasury.schemas'

const quote = treasuryQuoteSchema.parse({
  block: 7,
  block_hash: `0x${'b'.repeat(64)}`,
  source_alpha_rao: 10_000,
  tao_path: { deposit_asset: 'TAO', amount_rao: 9_900, price_impact_bps: 100 },
  // Platform reports the GM route's compounded two-hop impact.
  gm_alpha_path: { deposit_asset: 'SN28_ALPHA', amount_rao: 19_800, price_impact_bps: 199 },
  gm_credit_usd: null,
  execution_enabled: false,
  settlement: 'confirmed deposit rate',
})

const gm = {
  bucket_id: 'gm_credits',
  purpose: 'GM inference credit',
  allocation_bps: 1000,
  holding_coldkey: 'gm-holding-coldkey',
  service_account_ref: 'reviewed-gm-account',
}

const v2 = {
  mode: 'shadow',
  allocation_version: 2,
  maintenance_bps: 0,
  gm_bps: 0,
  service_buckets: [gm, {
    bucket_id: 'bitsec_audits',
    purpose: 'independent security audits',
    allocation_bps: 0,
    holding_coldkey: null,
    service_account_ref: null,
  }],
  treasury_hotkey: 'collector-hotkey',
  treasury_coldkey: 'collector-coldkey',
  gm_account_ref: null,
  max_daily_outflow_rao: 0,
  max_single_topup_rao: 0,
  max_slippage_bps: 0,
}

describe('shadow treasury policy versions', () => {
  it('keeps a legacy revision at its original 500 bps cap', () => {
    const old = { ...v2, allocation_version: undefined, service_buckets: [],
      maintenance_bps: 250, gm_bps: 250,
      treasury_hotkey: 'legacy-hotkey', treasury_coldkey: 'legacy-coldkey',
      gm_account_ref: 'legacy-gm-account' }
    expect(treasurySettingsSchema.parse(old).allocation_version).toBe(1)
    expect(treasurySettingsSchema.safeParse({ ...old, gm_bps: 251 }).success).toBe(false)
  })

  it('accepts isolated v2 service wallets only in shadow mode', () => {
    expect(treasurySettingsSchema.parse(v2).service_buckets).toHaveLength(2)
    expect(treasurySettingsSchema.safeParse({ ...v2, mode: 'active' }).success).toBe(false)
    expect(treasurySettingsSchema.safeParse({ ...v2, gm_bps: 1 }).success).toBe(false)
    expect(treasurySettingsSchema.safeParse({ ...v2, service_buckets: [gm, gm] }).success).toBe(false)
    expect(treasurySettingsSchema.safeParse({ ...v2, service_buckets: [{ ...gm, service_account_ref: null }] }).success).toBe(false)
    expect(treasurySettingsSchema.safeParse({ ...v2, service_buckets: [gm, {
      ...v2.service_buckets[1], allocation_bps: 1,
      holding_coldkey: 'bitsec-holding-coldkey',
    }] }).success).toBe(false)
    expect(treasurySettingsSchema.safeParse({ ...v2, service_buckets: [gm, {
      ...v2.service_buckets[1], allocation_bps: 1,
    }] }).success).toBe(false)
    expect(treasurySettingsSchema.safeParse({ ...v2, service_buckets: [gm, {
      ...v2.service_buckets[1], holding_coldkey: gm.holding_coldkey,
    }] }).success).toBe(false)
    expect(treasurySettingsSchema.safeParse({ ...v2, treasury_coldkey: gm.holding_coldkey }).success).toBe(false)
    expect(treasurySettingsSchema.safeParse({ ...v2, treasury_hotkey: null }).success).toBe(false)
  })
})

describe('treasuryRouteImpactBps', () => {
  it('uses the TAO path impact for the TAO route', () => {
    expect(treasuryRouteImpactBps('tao', quote)).toBe(100)
  })

  it('uses the cumulative GM path impact without re-adding the first hop', () => {
    expect(treasuryRouteImpactBps('gm_alpha', quote)).toBe(199)
  })
})
