use std::{env, time::Duration};

use anyhow::Result;
use sp1_sdk::network::{prove::NetworkProveBuilder, FulfillmentStrategy};

pub(crate) struct NetworkProveBuilderOverrides {
    timeout: Option<Duration>,
    strategy: Option<FulfillmentStrategy>,
    skip_simulation: Option<bool>,
    cycle_limit: Option<u64>,
    gas_limit: Option<u64>,
    min_auction_period: Option<u64>,
    max_price_per_pgu: Option<u64>,
    auction_timeout: Option<Duration>,
}

impl NetworkProveBuilderOverrides {
    pub(crate) fn from_env(prefix: &str) -> Result<Self> {
        let env = |suffix: &str| env::var(format!("{}_{}", prefix, suffix)).ok();

        Ok(Self {
            timeout: env("TIMEOUT_SECONDS")
                .and_then(|v| v.parse().ok())
                .map(Duration::from_secs),
            strategy: env("PROOF_STRATEGY").and_then(|v| FulfillmentStrategy::from_str_name(&v)),
            skip_simulation: env("SKIP_SIMULATION").and_then(|v| v.parse().ok()),
            cycle_limit: env("CYCLE_LIMIT").and_then(|v| v.parse().ok()),
            gas_limit: env("GAS_LIMIT").and_then(|v| v.parse().ok()),
            min_auction_period: env("MIN_AUCTION_PERIOD").and_then(|v| v.parse().ok()),
            max_price_per_pgu: env("MAX_PRICE_PER_PGU").and_then(|v| v.parse().ok()),
            auction_timeout: env("AUCTION_TIMEOUT")
                .and_then(|v| v.parse().ok())
                .map(Duration::from_secs),
        })
    }
}

pub(crate) trait NetworkProveBuilderOverridesTrait {
    fn with_overrides(self, overrides: NetworkProveBuilderOverrides) -> Self;
}

impl<'a> NetworkProveBuilderOverridesTrait for NetworkProveBuilder<'a> {
    fn with_overrides(mut self, overrides: NetworkProveBuilderOverrides) -> Self {
        if let Some(timeout) = overrides.timeout {
            self = self.timeout(timeout)
        }
        if let Some(strategy) = overrides.strategy {
            self = self.strategy(strategy)
        }
        if let Some(skip_simulation) = overrides.skip_simulation {
            self = self.skip_simulation(skip_simulation)
        }
        if let Some(cycle_limit) = overrides.cycle_limit {
            self = self.cycle_limit(cycle_limit)
        }
        if let Some(gas_limit) = overrides.gas_limit {
            self = self.gas_limit(gas_limit)
        }
        if let Some(min_auction_period) = overrides.min_auction_period {
            self = self.min_auction_period(min_auction_period)
        }
        if let Some(max_price_per_pgu) = overrides.max_price_per_pgu {
            self = self.max_price_per_pgu(max_price_per_pgu)
        }
        if let Some(auction_timeout) = overrides.auction_timeout {
            self = self.auction_timeout(auction_timeout)
        }
        self
    }
}
