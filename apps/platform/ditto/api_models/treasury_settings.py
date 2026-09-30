"""Versioned, shadow-only SN118 treasury allocation proposal.

Neither policy version changes validator weights or authorizes a transfer.
Version 1 keeps its original 500 bps ceiling; version 2 describes isolated
service wallets under a separately reviewed 1,000 bps aggregate ceiling.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

MAX_TREASURY_BPS = 500
MAX_SERVICE_BPS = 1_000


class TreasuryServiceBucket(BaseModel):
    model_config = ConfigDict(extra="ignore", frozen=True, strict=True)

    bucket_id: Annotated[str, Field(pattern=r"^[a-z][a-z0-9_]{1,47}$")]
    purpose: Annotated[str, Field(min_length=8, max_length=160)]
    allocation_bps: Annotated[int, Field(ge=0, le=MAX_SERVICE_BPS)] = 0
    receiving_hotkey: str | None = None
    receiving_coldkey: str | None = None
    service_account_ref: str | None = None

    @model_validator(mode="after")
    def validate_recipient(self) -> TreasuryServiceBucket:
        if self.allocation_bps and (
            not self.receiving_hotkey or not self.receiving_coldkey
        ):
            raise ValueError(
                "nonzero service allocation requires receiving wallet identity"
            )
        if (
            self.bucket_id == "gm_credits"
            and self.allocation_bps
            and not self.service_account_ref
        ):
            raise ValueError("GM allocation requires an account reference")
        return self


class TreasurySettings(BaseModel):
    model_config = ConfigDict(extra="ignore", frozen=True, strict=True)

    mode: Literal["shadow"] = "shadow"
    allocation_version: Literal[1, 2] = 1
    maintenance_bps: Annotated[int, Field(ge=0, le=MAX_TREASURY_BPS)] = 0
    gm_bps: Annotated[int, Field(ge=0, le=MAX_TREASURY_BPS)] = 0
    service_buckets: Annotated[
        list[TreasuryServiceBucket], Field(default_factory=list, max_length=20)
    ]
    treasury_hotkey: str | None = None
    treasury_coldkey: str | None = None
    gm_account_ref: str | None = None
    max_daily_outflow_rao: Annotated[int, Field(ge=0)] = 0
    max_single_topup_rao: Annotated[int, Field(ge=0)] = 0
    max_slippage_bps: Annotated[int, Field(ge=0, le=500)] = 0

    @model_validator(mode="after")
    def validate_allocation(self) -> TreasurySettings:
        if self.allocation_version == 2:
            if self.maintenance_bps or self.gm_bps:
                raise ValueError("v2 service buckets cannot mix with v1 allocations")
            if self.treasury_hotkey or self.treasury_coldkey or self.gm_account_ref:
                raise ValueError("v2 service buckets cannot reuse the v1 wallet")
            if not self.service_buckets:
                raise ValueError("v2 requires at least one service bucket")
            ids = [bucket.bucket_id for bucket in self.service_buckets]
            if len(ids) != len(set(ids)):
                raise ValueError("duplicate service bucket ID")
            wallets = [
                key
                for bucket in self.service_buckets
                for key in (bucket.receiving_hotkey, bucket.receiving_coldkey)
                if key
            ]
            if len(wallets) != len(set(wallets)):
                raise ValueError("service buckets must have distinct wallet identities")
            if (
                sum(bucket.allocation_bps for bucket in self.service_buckets)
                > MAX_SERVICE_BPS
            ):
                raise ValueError("combined service allocation exceeds 1000 bps")
            if (
                self.max_daily_outflow_rao
                or self.max_single_topup_rao
                or self.max_slippage_bps
            ):
                raise ValueError(
                    "v1 GM payment bounds cannot authorize v2 service spending"
                )
            return self
        if self.service_buckets:
            raise ValueError("v1 allocation cannot contain service buckets")
        if self.maintenance_bps + self.gm_bps > MAX_TREASURY_BPS:
            raise ValueError("combined treasury allocation exceeds 500 bps")
        if (self.maintenance_bps or self.gm_bps) and (
            not self.treasury_hotkey or not self.treasury_coldkey
        ):
            raise ValueError("nonzero allocation requires both treasury keys")
        if self.gm_bps and not self.gm_account_ref:
            raise ValueError("GM allocation requires an account reference")
        if self.max_single_topup_rao > self.max_daily_outflow_rao:
            raise ValueError("single top-up cannot exceed daily outflow limit")
        return self

    @property
    def miner_bps(self) -> int:
        if self.allocation_version == 2:
            return 10_000 - sum(
                bucket.allocation_bps for bucket in self.service_buckets
            )
        return 10_000 - self.maintenance_bps - self.gm_bps


class TreasurySettingsRevision(BaseModel):
    model_config = ConfigDict(extra="ignore", frozen=True)

    revision: int
    parent_revision: int
    settings: TreasurySettings
    checksum: str
    reason: str
    actor: str
    created_at: datetime


class TreasurySettingsControl(BaseModel):
    model_config = ConfigDict(extra="ignore", frozen=True)

    effective: TreasurySettings
    revision: int
    miner_bps: int
    history: list[TreasurySettingsRevision]
    weight_effect: Literal["none"] = "none"


class AdminTreasurySettingsRequest(BaseModel):
    model_config = ConfigDict(extra="ignore", strict=True)

    expected_revision: Annotated[int, Field(ge=0)]
    settings: TreasurySettings
    reason: Annotated[str, Field(min_length=8)]
    confirmation: Literal["RECORD TREASURY SHADOW POLICY"]
