# Rulesets spec technical exploration

This document provides a technical exploration of the ruleset design and TypeScript SDK API for Chaindog.

Each rule below includes a pseudocode implementation. Writing these pseudocode examples helps us validate the design of our TypeScript SDK and ensure it remains flexible enough to support a wide range of rulesets.

This is an early exploration, and the work will evolve as we continue developing the SDK.

If you have a monitoring ruleset in mind we're not covering, [please submit an issue](https://github.com/walnuthq/chaindog/issues) as we're looking to validate the initial rulesets with the community.

## Initial Rulesets to Be Implemented

The below list contains a comprehensive set of example rulesets from basic to advanced, covering multiple scenarios and touching two leading protocols — Aave and Uniswap.

All of these rulesets will be implemented as we progress on the Chaindog roadmap.

## Basic rulesets

### Balance rule

This rule listens for balance change of given accounts, if the balance goes below a certain amount an alert is triggered, eg. a faucet contract being almost depleted.
Inspired from [this monitorism balances monitor](https://github.com/ethereum-optimism/monitorism/tree/main/op-monitorism/balances).

Arguments:

- `accounts`: list of addresses of which balances are tracked.
- `erc20Address`: Token to fetch the balances from, leave empty to track gas token balance.
- `minBalance`: minimal balance to maintain before triggering an alert.
- `maxBalance`: maximum balance not to exceed before triggering an alert.

```typescript
const getBalance = (address: Address) => {
  const erc20 =
    erc20Address === ""
      ? null
      : getContract({ address: erc20Address, abi: erc20Abi, client });
  return erc20
    ? erc20.read.balanceOf([address])
    : client.getBalance({ address });
};

for (const trackedAddress of accounts) {
  const balance = await getBalance(trackedAddress);
  if (balance < minBalance) {
    alert(
      "min balance invariant failed",
      "account",
      trackedAddress,
      "balance",
      balance
    );
  }
  if (balance > maxBalance) {
    alert(
      "max balance invariant failed",
      "account",
      trackedAddress,
      "balance",
      balance
    );
  }
}
```

### SuperchainERC20 balance rule

This rule extends the standard balance rule to the Superchain by computing the total balance of a SuperchainERC20 token for tracked addresses across multiple chains.

Arguments:

- `chains`: dictionary of chains identified by their `chainId` and `rpcUrls`array.
- `accounts`: list of tracked addresses on which the monitor should maintain a Superchain consolidated balance.
- `superchainERC20Address`: token address to track balances.
- `minBalance`: minimal balance to maintain before triggering an alert.
- `maxBalance`: maximum balance not to exceed before triggering an alert.

### Global events rule

Listen to a given list of events that might be emitted by a list of addresses. We can further refine the monitor by specifying specific values for the event topics that might trigger alerts.
Inspired from [this monitorism global events monitor](https://github.com/ethereum-optimism/monitorism/tree/main/op-monitorism/global_events).

Arguments:

- `sources`: list of sources addresses to listen for events.
- `events`: list of events to watch, as objects with the event signature as key and the event args to filter as value.

```json
{
  "sources": ["usdcAddress"],
  "events": {
    "event Transfer(address indexed from, address indexed to, uint256 value)": {
      "from": "addressA",
      "to": "addressB"
    }
  }
}
```

The above example would trigger an alert for USDC transfers from address A to address B.

```typescript
const sourceAbis: Record<Address, Abi> = {};
for (const sourceAddress of sources) {
  sourceAbis[sourceAddress] = await fetchAbiFromSourcify(sourceAddress);
}

for (const sourceAddress of sources) {
  for (const eventSignature of Object.keys(events)) {
    const logs = await this.client.getLogs({
      address: sourceAddress,
      event: parseAbiItem(event) as AbiEvent,
      args: events[eventSignature],
      blockHash,
    });
    for (const log of logs) {
      alert("event triggered", log);
    }
  }
}
```

### Faultproof withdrawals rule:

This rule will monitor and validate withdrawals from L2 to L1 and will emit alerts when detecting forgeries, similar to [this implementation in monitorism repo](https://github.com/ethereum-optimism/monitorism/blob/main/op-monitorism/faultproof_withdrawals/monitor.go).

### Liveness Expiration rule:

This monitor will listen to on-chain activity of Safe owners and trigger an alert if liveness expires. Similar to [this implementation in monitorism in go](https://github.com/ethereum-optimism/monitorism/tree/main/op-monitorism/liveness_expiration).

## Aave V3 Rulesets

### Under Collateralisation Rule

The purpose of this rule is to monitor addresses having an under-collateralized position in the protocol.

Arguments:

- `accounts`: list of addresses which Aave positions are tracked.
- `healthFactorThreshold`: if the current HF goes below this value, trigger an alert.
- `ltvTheshold`: if the current loan to value goes above this value, trigger an alert.

```typescript
for (const trackedAddress of accounts) {
  const aavePool = getContract({ address: "0x", abi: aaveV3PoolAbi, client });
  const userData = await aavePool.read.getUserAccountData([trackedAddress]);
  const [, , , currentLiquidationThreshold, ltv, healthFactor] = userData;
  const healthFactorNumber = Number(healthFactor) / 1e18;
  if (healthFactorNumber < healthFactorThreshold) {
    alert(
      "hf invariant failed",
      "account",
      trackedAddress,
      "hf",
      healthFactor,
      "currentLiquidationThreshold",
      currentLiquidationThreshold
    );
  }
  const ltvNumber = Number(ltv) / 1e18;
  if (ltvNumber > ltvTheshold) {
    alert(
      "ltv invariant failed",
      "account",
      trackedAddress,
      "ltv",
      ltv,
      "currentLiquidationThreshold",
      currentLiquidationThreshold
    );
  }
}
```

### Bad debt rule

The purpose of this rule is to monitor the list of positions that can be liquidated (HF < 1) and the amount of time it takes to liquidate them. If no liquidations happen there might be a risk of bad debt. The rule tracks all unhealthy positions that haven’t been liquidated until a certain amount of time and sums their cumulated debts value to compute a potential bad debt indicator.

Arguments:

- `unliquidatedMaxTime`: amount of time a position can stay unliquidated before being considered potentially bad debt.
- `maxBadDebt`: amount of potential bad debt tolerated before an alert is triggered.

https://aave.com/docs/developers/umbrella

### Total supplied rule

Triggers when total supplied amount for a reserve goes below a certain percentage.

Arguments:

- `assets`: list of reserves to track supplied amount.
- `minTotalSuppliedPercent`: when a reserve is supplied below this %, trigger an alert.

https://aave.com/docs/developers/liquidity-pool#supply

```typescript
for (const trackedAsset of assets) {
  const aaveDataProvider = getContract({
    address: "0x",
    abi: aaveV3DataProviderAbi,
    client,
  });
  const reserveData = await aaveDataProvider.read.getReserveData([
    trackedAsset,
  ]);
  const [, , , , , , , , aTokenAddress] = reserveData;
  const aToken = getContract({ address: aTokenAddress, abi: erc20Abi, client });
  const totalSupply = await aToken.read.totalSupply();
  const remainingToSupply = await aToken.read.balanceOf(trackedAsset);
  const totalSupplied = totalSupply - remainingToSupply;
  const totalSuppliedPercent = (totalSupplied / totalSupply) * 100n;
  if (totalSuppliedPercent < minTotalSuppliedPercent) {
    alert(
      "min total supplied invariant failed",
      "asset",
      trackedAsset,
      "total supplied",
      totalSuppliedPercent
    );
  }
}
```

### Total borrowed rule

Triggers when total borrowed amount for a reserve reaches a given percentage.

Arguments:

- `maxTotalBorrowedPercent`: when a reserve asset is borrowed above this %, trigger an alert.

https://aave.com/docs/developers/liquidity-pool#borrow

```typescript
for (const trackedAsset of assets) {
  const aaveDataProvider = getContract({
    address: "0x",
    abi: aaveV3DataProviderAbi,
    client,
  });
  const reserveData = await aaveDataProvider.read.getReserveData([
    trackedAsset,
  ]);
  const [, , , , , , , , , , variableDebtTokenAddress] = reserveData;
  const variableDebtToken = getContract({
    address: variableDebtTokenAddress,
    abi: erc20Abi,
    client,
  });
  const totalVariableDebt = await variableDebtToken.read.totalSupply();
  const remainingToBorrow = await variableDebtToken.read.balanceOf(
    trackedAsset
  );
  const totalBorrowed = totalVariableDebt - remainingToBorrow;
  const totalBorrowedPercent = (totalBorrowed / totalVariableDebt) * 100n;
  if (totalBorrowedPercent > maxTotalBorrowedPercent) {
    alert(
      "max total borrowed invariant failed",
      "asset",
      trackedAsset,
      "total borrowed",
      totalBorrowedPercent
    );
  }
}
```

### Liquidity rate rule

Triggers when the supply interest rate for a reserve is out of the specified range.

Arguments:

- `assets`: list of reserves to track liquidity rate.
- `minLiquidityRate`: min allowed supply rate for a market.
- `maxLiquidityRate`: max allowed supply rate for a market.

https://aave.com/docs/developers/reserve

```typescript
for (const trackedAsset of assets) {
  const aaveDataProvider = getContract({
    address: "0x",
    abi: aaveV3DataProviderAbi,
    client,
  });
  const reserveData = await aaveDataProvider.read.getReserveData([
    trackedAsset,
  ]);
  const [, , currentLiquidityRate] = reserveData;
  const liquidityRatePercent = (Number(currentLiquidityRate) / 1e27) * 100;
  if (liquidityRatePercent < minLiquidityRate) {
    alert(
      "min liquidity rate invariant failed",
      "asset",
      trackedAsset,
      "liquidity rate",
      liquidityRatePercent
    );
  }
  if (liquidityRatePercent > maxLiquidityRate) {
    alert(
      "max liquidity rate invariant failed",
      "asset",
      trackedAsset,
      "liquidity rate",
      liquidityRatePercent
    );
  }
}
```

### Borrow rate rule

Same as liquidity rate rule but for borrow rate instead of supply rate.

### Price Oracle Fluctuation Rule

This rule can monitor rapidly changing oracle price for a market and trigger alerts if the price fluctuates in an unusual way., eg. if the price goes down 20% in a 5min interval then there is a risk of oracle price manipulation.

Arguments:

- `interval`: Time range to compute price fluctuation.
- `maxPriceChangePercent`: maximum price percentage fluctuation over the time interval allowed before triggering an alert.

For this monitor we’ll need to build an history of oracle prices and persist them eg. with [Prometheus](https://prometheus.io/docs/introduction/overview/) so we can compare prices over a configurable time period and trigger alerts accordingly.

### Suspicious Activity Rules

Set of simple rules that can be setup to trigger alerts when large operations occur on the protocol, eg. large amount of asset A supplied and then immediately borrowing equally large amount of asset B.

Likewise, we can build simple rules that listen for blacklisted addresses trying to interact with the protocol.

## Uniswap V3 rulesets

### Exchange rate monitor

This rule computes the current exchange rate (from token0 to token1) of a pool and makes sure it stays within a given range. If the current exchange rate deviates too much from the acceptable range, it might indicate a liquidity issue.

Arguments:

- `poolAddress`: UniswapV3Pool address.
- `minExchangeRate`: minimum acceptable exchange rate.
- `maxExchangeRate`: maximum acceptable exchange rate.

https://blog.uniswap.org/uniswap-v3-math-primer#how-do-i-calculate-the-current-exchange-rate

### Position out-of-range monitor

This rule tracks all positions held by tracked addresses and will alert when they go out-of-range.

Arguments:

- `accounts`: list of liquidity providers.
- `poolAddress`: UniswapV3Pool address.

https://blog.uniswap.org/uniswap-v3-math-primer-2#example-position

### Position holdings monitor

This rule tracks current holdings of positions held by LPs and trigger alerts when they’re not within an acceptable range.

Arguments:

- `accounts`: list of LPs.
- `poolAddress`: UniswapV3Pool address.
- `minToken0Balance`: minimum token0 acceptable balance.
- `maxToken0Balance`: maximum token0 acceptable balance.
- `minToken1Balance`: minimum token1 acceptable balance.
- `maxToken1Balance`: maximum token1 acceptable balance.

https://blog.uniswap.org/uniswap-v3-math-primer-2#background

### Impermanent loss detection

This rule tracks a liquidity provider position in the protocol and will trigger an alert if a threshold of impermanent loss is reached. Impermanent loss is detected by computing the price of the cumulated token0Owed and token1Owed to the position within the protocol and comparing it to the same tokens dollar-value outside of the protocol.

Arguments:

- `accounts`: liquidity providers addresses to track.
- `poolAddress`: UniswapV3Pool address.
- `maxImpermanentLossPercent`: percentage of impermanent loss tolerated before triggering an alert.
