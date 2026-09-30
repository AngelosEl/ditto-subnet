import { describe, expect, it } from 'vitest'
import { treasurySettingsSchema } from './treasury.schemas'

const gm = {
  bucket_id: 'gm_credits',
  purpose: 'GM inference credit',
  allocation_bps: 1000,
  receiving_hotkey: 'gm-hotkey',
  receiving_coldkey: 'gm-coldkey',
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
    receiving_hotkey: null,
    receiving_coldkey: null,
    service_account_ref: null,
  }],
  treasury_hotkey: null,
  treasury_coldkey: null,
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
    expect(treasurySettingsSchema.safeParse({ ...v2, service_buckets: [gm, {
      ...v2.service_buckets[1], allocation_bps: 1,
    }] }).success).toBe(false)
  })
})
