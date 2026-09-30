import pytest

from ditto.treasury.service_allocation import (
    ServiceDestination,
    plan_service_distribution,
    service_first_weights,
)


@pytest.mark.parametrize(
    "burn, expected",
    [
        (1, {"collector": 0.1, "burn": 0.9}),
        (0.5, {"miner": 0.45, "collector": 0.1, "burn": 0.45}),
    ],
)
def test_service_pool_survives_full_burn(burn, expected):
    vector = service_first_weights(
        {"miner": 1},
        service_bps=1000,
        burn_share=burn,
        collector_hotkey="collector",
        collector_verified=True,
        burn_hotkey="burn",
    )
    assert vector == pytest.approx(expected)


def test_empty_and_unpaid_miner_share_does_not_enlarge_collector():
    common = {
        "service_bps": 1000,
        "burn_share": 0,
        "collector_hotkey": "collector",
        "collector_verified": True,
        "burn_hotkey": "burn",
    }
    assert service_first_weights({}, **common) == pytest.approx(
        {"collector": 0.1, "burn": 0.9}
    )
    assert service_first_weights(
        {"miner": 1}, paid_miner_fraction=0.5, **common
    ) == pytest.approx({"miner": 0.45, "collector": 0.1, "burn": 0.45})
    assert service_first_weights({"collector": 1}, **common) == pytest.approx(
        {"collector": 0.1, "burn": 0.9}
    )


def test_unverified_or_burn_collector_cannot_receive_funds():
    with pytest.raises(ValueError, match="independently verified"):
        service_first_weights(
            {},
            service_bps=1000,
            burn_share=1,
            collector_hotkey="collector",
            collector_verified=False,
            burn_hotkey="burn",
        )
    with pytest.raises(ValueError, match="independently verified"):
        service_first_weights(
            {},
            service_bps=1000,
            burn_share=1,
            collector_hotkey="burn",
            collector_verified=True,
            burn_hotkey="burn",
        )


def test_distribution_conserves_atomic_earnings_and_does_not_spend_principal():
    destinations = (
        ServiceDestination("gm", 600, "gm-holder"),
        ServiceDestination("bitsec", 200, "audit-holder"),
        ServiceDestination("bitcast", 200, "ads-holder"),
    )
    result = plan_service_distribution(
        attributed_alpha_rao=11,
        available_alpha_rao=100,
        collector_coldkey="collector",
        destinations=destinations,
    )
    assert sum(d.alpha_rao for d in result) == 11
    assert {d.bucket_id: d.alpha_rao for d in result} == {
        "gm": 7,
        "bitsec": 2,
        "bitcast": 2,
    }
    assert result == plan_service_distribution(
        attributed_alpha_rao=11,
        available_alpha_rao=100,
        collector_coldkey="collector",
        destinations=tuple(reversed(destinations)),
    )
    with pytest.raises(ValueError, match="available"):
        plan_service_distribution(
            attributed_alpha_rao=101,
            available_alpha_rao=100,
            collector_coldkey="collector",
            destinations=destinations,
        )
    with pytest.raises(ValueError, match="invalid service destination"):
        plan_service_distribution(
            attributed_alpha_rao=11,
            available_alpha_rao=100,
            collector_coldkey="gm-holder",
            destinations=destinations,
        )
