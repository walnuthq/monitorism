<p align="center">
  <h1 align="center">Chaindog</h1>
</p>
<p align="center">
  <strong><i>An Open Source EVM chain monitoring and alerting framework.</i></strong>
</p>

The goal of Chaindog is to provide a fully customizable monitoring and alerting framework, allowing users to configure and spawn monitors tracking on-chain activity.
Monitors define customizable rulesets (eg. Faucet address balance should stay above a threshold, an ERC20 mint event is detected, etc.) and when an invariant check fails, an alert is triggered.
Chaindog is built with customization in mind and our SDK allows for user-defined monitors and rulesets composition.

Chaindog is brought to you by [Walnut](https://www.walnut.dev).

This project is supported by an OP Labs grant following the acceptation of our proposal for the [Open-Source Monitoring & Alerting Mission Request on OP Gov Forum](https://gov.optimism.io/t/closed-governance-fund-mission-request-open-source-monitoring-alerting/10293).

## Features

- **Real-time Monitoring**: Continuously observe blockchain activity for defined events and transactions.
- **Custom Rulesets (Invariants)**: Define flexible logic to detect on-chain conditions and behaviors that matter to your system.
- **Cross-Chain Monitors**: Initial support for monitoring SuperchainERC20 transfers and related cross-chain activity.
- **Data Persistence**: Each monitor execution can store data in a DataBag, allowing context to be shared between executions.
- **Multi-channel Alerts**: Send notifications through Slack, Discord, Telegram, Email, Webhooks, or custom integrations.
- **Extensible Framework**: Easily extend support for additional chains, monitor types, and integrations.

## Rulesets

An initial version of the rulesets we plan to implement in Chaindog is available [here](rulesets/README.md).

If you have a monitoring ruleset in mind we're not covering, [please submit an issue](https://github.com/walnuthq/chaindog/issues) as we're looking to validate the initial rulesets with the community.

## Roadmap

- [x] Validate the [initial rulesets](rulesets/README.md) with the community.
- [ ] SDK and configuration schema for defining monitors, invariants, alerts and actions.
- [ ] Implement basic monitors (ERC20/SuperchainERC20 balances, Global events, Fault proof withdrawals, etc.)
- [ ] Support defining alerts and provide integrations for Slack, Telegram and PagerDuty.
- [ ] Implement reference monitors from the [initial rulesets](rulesets/README.md) demonstrating protocol-level use cases.
- [ ] Create a framework to allow composition of monitors to enable complex rulesets.
- [ ] Easily replicate a monitoring config across any chain and enable multi-chain monitoring.
- [ ] Build a monitor orchestration service (APIs for scheduling, execution, and persistence).
- [ ] Provide historical data visualization and alerts history view.

## License

[Apache License 2.0](LICENSE)
