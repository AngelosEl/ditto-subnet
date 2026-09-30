import { z } from 'zod'

export const treasurySettingsSchema = z.object({
  mode: z.literal('shadow'),
  allocation_version: z.union([z.literal(1), z.literal(2)]).default(1),
  maintenance_bps: z.number().int().min(0).max(500),
  gm_bps: z.number().int().min(0).max(500),
  service_buckets: z.array(z.object({
    bucket_id: z.string().regex(/^[a-z][a-z0-9_]{1,47}$/),
    purpose: z.string().min(8).max(160),
    allocation_bps: z.number().int().min(0).max(1000),
    receiving_hotkey: z.string().nullable(),
    receiving_coldkey: z.string().nullable(),
    service_account_ref: z.string().nullable(),
  })).max(20).default([]),
  treasury_hotkey: z.string().nullable(),
  treasury_coldkey: z.string().nullable(),
  gm_account_ref: z.string().nullable(),
  max_daily_outflow_rao: z.number().int().nonnegative(),
  max_single_topup_rao: z.number().int().nonnegative(),
  max_slippage_bps: z.number().int().min(0).max(500),
}).superRefine((value, context) => {
  if (value.allocation_version === 2) {
    if (value.maintenance_bps || value.gm_bps || value.treasury_hotkey ||
        value.treasury_coldkey || value.gm_account_ref) {
      context.addIssue({ code: 'custom', message: 'v2 cannot mix with v1 allocation or wallet' })
    }
    if (value.service_buckets.length === 0) {
      context.addIssue({ code: 'custom', message: 'v2 requires service buckets' })
    }
    const ids = value.service_buckets.map(bucket => bucket.bucket_id)
    if (new Set(ids).size !== ids.length) {
      context.addIssue({ code: 'custom', message: 'duplicate service bucket ID' })
    }
    const wallets = value.service_buckets.flatMap(bucket =>
      [bucket.receiving_hotkey, bucket.receiving_coldkey].filter((key): key is string => !!key))
    if (new Set(wallets).size !== wallets.length) {
      context.addIssue({ code: 'custom', message: 'service wallets must be distinct' })
    }
    if (value.service_buckets.reduce((total, bucket) => total + bucket.allocation_bps, 0) > 1000) {
      context.addIssue({ code: 'custom', message: 'combined service allocation exceeds 1000 bps' })
    }
    for (const bucket of value.service_buckets) {
      if (bucket.allocation_bps && (!bucket.receiving_hotkey || !bucket.receiving_coldkey)) {
        context.addIssue({ code: 'custom', message: 'nonzero service allocation requires wallet identity' })
      }
      if (bucket.bucket_id === 'gm_credits' && bucket.allocation_bps && !bucket.service_account_ref) {
        context.addIssue({ code: 'custom', message: 'GM allocation requires account reference' })
      }
    }
    if (value.max_daily_outflow_rao || value.max_single_topup_rao || value.max_slippage_bps) {
      context.addIssue({ code: 'custom', message: 'v1 payment bounds cannot authorize v2 spending' })
    }
    return
  }
  if (value.service_buckets.length) {
    context.addIssue({ code: 'custom', message: 'v1 cannot contain service buckets' })
  }
  if (value.maintenance_bps + value.gm_bps > 500) {
    context.addIssue({ code: 'custom', message: 'combined allocation exceeds 500 bps' })
  }
  if ((value.maintenance_bps || value.gm_bps) &&
      (!value.treasury_hotkey || !value.treasury_coldkey)) {
    context.addIssue({ code: 'custom', message: 'treasury keys are required' })
  }
  if (value.gm_bps && !value.gm_account_ref) {
    context.addIssue({ code: 'custom', message: 'GM account reference is required' })
  }
  if (value.max_single_topup_rao > value.max_daily_outflow_rao) {
    context.addIssue({ code: 'custom', message: 'single top-up exceeds daily limit' })
  }
})

export const treasuryRevisionSchema = z.object({
  revision: z.number().int().nonnegative(),
  parent_revision: z.number().int().nonnegative(),
  settings: treasurySettingsSchema,
  checksum: z.string().regex(/^[0-9a-f]{64}$/),
  reason: z.string(),
  actor: z.string(),
  created_at: z.string(),
})

export const treasuryControlSchema = z.object({
  effective: treasurySettingsSchema,
  revision: z.number().int().nonnegative(),
  miner_bps: z.number().int().min(9000).max(10000),
  history: z.array(treasuryRevisionSchema),
  weight_effect: z.literal('none'),
})

export const recordTreasurySettingsInputSchema = z.object({
  expectedRevision: z.number().int().nonnegative(),
  settings: treasurySettingsSchema,
  reason: z.string().trim().min(8),
  confirmation: z.literal('RECORD TREASURY SHADOW POLICY'),
})

export const treasuryQuoteInputSchema = z.object({
  sourceAlphaRao: z.number().int().positive().max(10_000_000_000),
})

export const treasuryPreviewInputSchema = treasuryQuoteInputSchema.extend({
  route: z.enum(['tao', 'gm_alpha']),
})

export const treasuryQuoteSchema = z.object({
  block: z.number().int().nonnegative(),
  block_hash: z.string().regex(/^0x[0-9a-f]{64}$/),
  source_alpha_rao: z.number().int().positive(),
  tao_path: z.object({
    deposit_asset: z.literal('TAO'),
    amount_rao: z.number().int().nonnegative(),
    price_impact_bps: z.number().int().nonnegative(),
  }),
  gm_alpha_path: z.object({
    deposit_asset: z.literal('SN28_ALPHA'),
    amount_rao: z.number().int().nonnegative(),
    price_impact_bps: z.number().int().nonnegative(),
  }),
  gm_credit_usd: z.null(),
  execution_enabled: z.literal(false),
  settlement: z.string(),
})

// Each path's price_impact_bps is already cumulative for that route: Platform
// compounds both swaps into gm_alpha_path, so adding tao_path would count the
// DITTO-to-TAO hop twice.
export function treasuryRouteImpactBps(
  route: z.infer<typeof treasuryPreviewInputSchema>['route'],
  quote: z.infer<typeof treasuryQuoteSchema>,
): number {
  return route === 'tao'
    ? quote.tao_path.price_impact_bps
    : quote.gm_alpha_path.price_impact_bps
}
