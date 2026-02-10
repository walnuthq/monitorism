# WALNUT MONITORING SYSTEM
## MVP Specification
### Universal Blockchain Security Monitoring Platform, built for the Superchain

**Version:** 1.0  
**Date:** February 2026  
---

## TABLE OF CONTENTS

0. [Technical Vision: Why YAML + expr-lang + Go](#0-technical-vision-why-yaml--expr-lang--go)
1. [Executive Summary](#1-executive-summary)
2. [Problem Statement & Market Opportunity](#2-problem-statement--market-opportunity)
3. [Target Customers & Design Partner](#3-target-customers--validated-pain-points)
4. [Technical Architecture Overview](#4-technical-architecture-overview)
5. [DSL Specification (YAML)](#5-dsl-specification-yaml)
   - 5.9 Contract ABI Specification
   - 5.10 Network Configuration
   - 5.11 Webhook Input Source
   - 5.12 Error Handling
   - 5.13 Threat Intelligence (Phase 1 Basic)
   - 5.14 External Data Sources (3rd Party APIs) - Phase 2
   - 5.15 Built-in Functions (Blockchain-Specific)
6. [Reference Implementation: Optimism Superchain](#6-reference-implementation-optimism-superchain)
   - 6.0 YAML Monitor Reference Guide
   - TIER 1: Critical Security (MVP Phase 1)
   - TIER 2: Security Monitoring (Lower Priority)
   - TIER 3: Operational Monitoring (Phase 2+)
   - 6.11 Multi-Network Superchain Monitoring
   - 6.12 Stateful Monitoring (Phase 2 PREVIEW)
   - 6.13 Adapting for Other Chains
7. [Competitive Analysis](#7-competitive-analysis)
8. [Phased Roadmap](#8-phased-roadmap)
9. [Success Metrics & KPIs](#9-success-metrics--kpis)
10. [Risk Analysis & Mitigations](#10-risk-analysis--mitigations)
11. [Resource Requirements](#11-resource-requirements)
12. [Phase 2+ Operational Monitors](#12-phase-2-operational-monitors-summary)
13. [Appendix A: DSL Quick Reference](#appendix-a-dsl-quick-reference)
14. [Appendix B: Glossary](#appendix-b-glossary)
15. [Appendix C: Optimism Discovery Questions](#13-questions-for-optimism-foundation-discovery-call)

---

## 0. TECHNICAL VISION: WHY YAML + EXPR-LANG + GO

Our core thesis is simple: combine YAML configuration with expr-lang expressions and Go's performance to create a monitoring platform that is 10x easier to use than custom code â€” without locking users into a proprietary language like Hexagate's .gate.

### 0.1 The Problem with Hexagate's .gate Language

Hexagate uses a proprietary DSL called **Gatelang** (`.gate` files):

```gate
// Hexagate .gate example (from Base's fault proof monitors)
use Len, StateRoot, BlockHash, StorageHash, Keccak256, Events, Call from hexagate;

param disputeGameFactoryProxy: address;
param l2ChainId: integer;

source disputeGameCreatedEvents: list<tuple<address, integer, bytes>> = Events {
    contract: disputeGameFactoryProxy,
    signature: "event DisputeGameCreated(address indexed disputeProxy, uint32 indexed gameType, bytes32 indexed rootClaim)"
};

source blockNumber: integer = Call {
    contract: disputeProxy,
    signature: "function l2BlockNumber() public pure returns (uint256 l2BlockNumber_)"
};

invariant {
    description: "Dispute game created with incorrect L2 output proposal",
    condition: Len { sequence: disputeGameCreatedEvents } > 0 ? computedL2OutputProposal == l2OutputProposal : true
};
```

**Problems with .gate:**
| Issue | Impact |
|-------|--------|
| **Proprietary language** | Vendor lock-in, no community, no tooling |
| **Learning curve** | New syntax to learn (`source`, `invariant`, `use from hexagate`) |
| **SaaS dependency** | Must use Hexagate's API for testing and deployment |
| **No local validation** | Can't test without API key |
| **Compiled language** | Requires Hexagate's compiler |
| **Tuple/Loop Hell** | Complex nested iterations with obscure tuple indexing |

### 0.1.1 The "Tuple Hell" Problem in Gatelang

Real example from Base's fault proof monitors (`challenged_proposal.gate`):

```gate
// 7-element tuple type declaration - what does each index mean?
source claimData: list<tuple<integer,address,address,integer,bytes,integer,integer>> = [
    Call {
        contract: disputeGame,
        signature: "function claimData(uint256 idx) view returns (uint32,address,address,uint128,bytes32,uint128,uint128)",
        params: tuple(index)
    }
    for index in Range { start: 0, stop: claimCount }
];

// Magic number indexing: claim[2] = ??? claim[0] = ???
source rootClaimProposer: address = claimData[0][2];

// Nested list comprehension with conditional - good luck debugging this
source challengerAttacks: list<boolean> = [
    (claim[2] == honestChallenger) and Contains { sequence: attackClaimParentIndices, item: claim[0] }
    for claim in claimData
    if (rootClaimProposer == honestProposer)
];

// Ternary + Contains with verbose object syntax
invariant {
    condition: Len { sequence: moveEvents } > 0 ? !Contains { sequence: challengerAttacks, item: true } : true
};
```

**What's wrong with this?**

| Problem | Gatelang | Impact |
|---------|----------|--------|
| **Tuple indexing** | `claim[2]`, `claim[0]` | What is index 2? You have to count in the type declaration |
| **Nested comprehensions** | `for x in Y for z in W if condition` | Hard to read, easy to make mistakes |
| **Verbose built-ins** | `Contains { sequence: x, item: y }` | 37 characters vs `y in x` (6 chars) |
| **Type declarations** | `list<tuple<integer,address,address,integer,bytes,integer,integer>>` | Cognitive overload |

**Same logic in Walnut (YAML + expr-lang):**

```yaml
# Clear, named fields instead of tuple indices
validation:
  claims: "${contract_call(disputeGame).claimData()}"
  
  # Named field access, not claim[2]
  root_proposer: "${claims[0].claimant}"
  
  # Simple filter + any - no nested comprehension hell
  challenger_attacks: |
    ${filter(claims, { 
      .claimant == honestChallenger && 
      .parentIndex % 2 == 0 
    })}
  
  # Clean condition
  condition: |
    ${len(moveEvents) > 0 ? !any(challenger_attacks) : true}
```

**Comparison:**

| Aspect | Gatelang | expr-lang |
|--------|----------|-----------|
| **Array operations** | `Contains { sequence: x, item: y }` | `y in x` |
| **Filtering** | `[... for x in Y if condition]` | `filter(Y, { condition })` |
| **Any/All check** | Manual with `Contains` | `any(list)`, `all(list, { cond })` |
| **Length** | `Len { sequence: x }` | `len(x)` |
| **Mapping** | `[transform(x) for x in Y]` | `map(Y, { transform })` |
| **Field access** | `tuple[0]`, `tuple[2]` | `.fieldName` |

The bottom line: security engineers shouldn't need to learn a new programming language with tuple indexing and nested comprehensions. With expr-lang, they use familiar JavaScript-like syntax: `filter`, `map`, `any`, `all`, `len`.

### 0.2 Our Approach: YAML + expr-lang + Go

We use three layers that each solve a specific problem.

YAML is the de facto standard for infrastructure and security configuration:

| Tool | Audience | Uses YAML |
|------|----------|-----------|
| Kubernetes | DevOps/SRE | Yes - All manifests |
| Ansible | DevOps/SRE | Yes - Playbooks |
| GitHub Actions | DevOps | Yes - Workflows |
| Prometheus AlertManager | SRE | Yes - Alert rules |
| Falco | Security | Yes - Security rules |
| Sigma | Security (SIEM) | Yes - Detection rules |
| YARA-L | Security (Chronicle) | Yes - Detection rules |
| Terraform | DevOps | HCL (similar syntax) |

Your security team already knows YAML. Zero learning curve for the config format â€” they only need to learn the Walnut DSL fields, not a new language syntax.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        WALNUT DSL ARCHITECTURE                               │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │                         YAML CONFIGURATION                           │    │
│  │                                                                      │    │
│  │  • Human-readable structure                                         │    │
│  │  • IDE support (syntax highlighting, validation)                    │    │
│  │  • Version control friendly                                         │    │
│  │  • No learning curve for config (everyone knows YAML)               │    │
│  └─────────────────────────────────────────┬───────────────────────────┘    │
│                                            │                                 │
│  ┌─────────────────────────────────────────▼───────────────────────────┐    │
│  │                         EXPR-LANG EXPRESSIONS                        │    │
│  │                                                                      │    │
│  │  • Dynamic conditions: `event.value > 1000000000000000000`          │    │
│  │  • Array operations: `all(events, {.status == "success"})`          │    │
│  │  • String matching: `startsWith(address, "0x742d")`                 │    │
│  │  • Math: `event.gasUsed / event.gasLimit > 0.9`                     │    │
│  │  • Type-safe, memory-safe, no infinite loops                        │    │
│  └─────────────────────────────────────────┬───────────────────────────┘    │
│                                            │                                 │
│  ┌─────────────────────────────────────────▼───────────────────────────┐    │
│  │                         GO RUNTIME + EXTENSIONS                      │    │
│  │                                                                      │    │
│  │  • Custom blockchain functions (eth_getProof, keccak256)            │    │
│  │  • Performance (bytecode VM, optimizing compiler)                   │    │
│  │  • Easy to extend with new functions                                │    │
│  │  • Self-hosted capability                                           │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 0.3 Side-by-Side Comparison: .gate vs YAML + expr-lang

**Same monitor (Invalid Output Root Detection):**

| Aspect | Hexagate .gate | Walnut YAML + expr-lang |
|--------|----------------|------------------------|
| **File format** | Proprietary `.gate` | Standard YAML |
| **Expression syntax** | Custom (`Len { sequence: x }`) | Familiar (`len(x)`) |
| **Tooling** | None (Hexagate only) | Any YAML editor, IDE |
| **Validation** | Requires API call | Local `walnut validate` |
| **Testing** | Requires API key | Local unit tests |
| **Extensibility** | Closed | Open (add Go functions) |

**Hexagate .gate:**
```gate
use Len, StateRoot, BlockHash, StorageHash, Keccak256, Events, Call from hexagate;

param disputeGameFactoryProxy: address;
param l2ChainId: integer;

source disputeGameCreatedEvents: list<tuple<address, integer, bytes>> = Events {
    contract: disputeGameFactoryProxy,
    signature: "event DisputeGameCreated(...)"
};

source computedL2OutputProposal: bytes = Keccak256 {
    input: bytes(0x00..00) + stateRoot + messagePasserStorageHash + blockHash
};

invariant {
    description: "Invalid output root",
    condition: computedL2OutputProposal == l2OutputProposal
};
```

**Walnut YAML + expr-lang:**
```yaml
name: invalid_output_root
type: cross_chain
rule_kind: realtime

cross_chain:
  sources:
    - id: dispute_game_created
      chain: { kind: evm, networks: [1] }
      filters:
        - eventEmitted:
            contract: { address: "0xe5965Ab5962eDc7477C8520243A95517CD252fA9" }
            name: DisputeGameCreated
            args:
              - index: 2
                capture: true  # rootClaim

    - id: l2_computed_root
      validation:
        type: output_root_computation
        compute:
          result: keccak256(version + stateRoot + storageRoot + blockHash)

  correlation:
    condition: dispute_game_created.args.rootClaim != l2_computed_root.result

alert:
  template: "Invalid output root detected!"
```

### 0.4 expr-lang: Built-in Functions

**expr-lang** comes with powerful built-in functions (no custom code needed):

| Category | Functions | Example |
|----------|-----------|---------|
| **Array** | `all`, `any`, `none`, `filter`, `map`, `count`, `sum` | `all(events, {.status == "success"})` |
| **String** | `startsWith`, `endsWith`, `contains`, `lower`, `upper`, `trim` | `startsWith(address, "0x742d")` |
| **Math** | `+`, `-`, `*`, `/`, `%`, `abs`, `ceil`, `floor` | `event.value / 1e18 > 100` |
| **Logic** | `and`, `or`, `not`, `?:` (ternary) | `isWhale ? "alert" : "ignore"` |
| **Comparison** | `==`, `!=`, `>`, `<`, `>=`, `<=`, `in` | `event.from in sanctionedList` |

### 0.5 Extending expr-lang with Custom Functions (Go)

Adding blockchain-specific functions is trivial in Go:

```go
// Custom function: eth_getProof validation
func EthGetProof(address string, storageKey string, blockNumber int) (bool, error) {
    proof, err := rpcClient.GetProof(address, []string{storageKey}, blockNumber)
    if err != nil {
        return false, err
    }
    return proof.StorageProof[0].Value != "0x0", nil
}

// Custom function: keccak256 hash
func Keccak256(data ...[]byte) []byte {
    return crypto.Keccak256(bytes.Join(data, nil))
}

// Custom function: output root computation
func ComputeOutputRoot(version, stateRoot, storageHash, blockHash []byte) []byte {
    return Keccak256(version, stateRoot, storageHash, blockHash)
}

// Register custom functions with expr-lang
env := map[string]interface{}{
    "eth_getProof":       EthGetProof,
    "keccak256":          Keccak256,
    "computeOutputRoot":  ComputeOutputRoot,
    "sanctionedList":     threatIntelService.GetSanctionedAddresses(),
}

// Compile and run expression
program, _ := expr.Compile(rule.Condition, expr.Env(env))
result, _ := expr.Run(program, env)
```

**Why This Matters:**
- **Any Go developer can extend** the DSL with new functions
- **No vendor approval** needed to add features
- **Type-safe** - Go compiler catches errors at build time
- **Testable** - Standard Go unit tests

### 0.6 Why expr-lang over CEL (Google's Common Expression Language)

We evaluated both CEL (Google's Common Expression Language, used in Firebase/IAM) and expr-lang for the expression engine. Both are safe, sandboxed languages. We chose expr-lang for the following reasons:

| Aspect | expr-lang | CEL |
|--------|-----------|-----|
| **Go integration** | Native | Requires protobuf |
| **Custom types (big.Int)** | Pass directly via `map[string]interface{}` | Requires proto type providers |
| **Blockchain types (uint256)** | Easy: wrap `big.Int` in custom function | Complex: needs proto definitions |
| **Syntax** | Simple, JS-like | More verbose |
| **Performance** | Optimizing compiler + bytecode VM | Good, but more overhead |
| **Learning curve** | Minimal | Steeper |
| **Custom functions** | Simple `map[string]interface{}` | Proto definitions required |
| **Used by** | Google Cloud, Uber, Argo, CrowdSec | Google Cloud (IAM) |

**Why This Matters for Blockchain:**

Blockchain operations frequently use `uint256` (256-bit integers) which exceed Go's native `int64`/`uint64`. 
Neither expr-lang nor CEL has native uint256 support, but:

```go
// expr-lang: Simple - just pass big.Int in the environment
env := map[string]interface{}{
    "weiToEth": func(wei *big.Int) *big.Float {
        return new(big.Float).Quo(new(big.Float).SetInt(wei), big.NewFloat(1e18))
    },
    "parseUint256": func(hex string) *big.Int {
        n := new(big.Int)
        n.SetString(strings.TrimPrefix(hex, "0x"), 16)
        return n
    },
}

// CEL: Requires proto definitions, type providers, and more boilerplate
// See: https://github.com/google/cel-go/blob/master/examples/custom_types_test.go
```

This seamless Go integration is why expr-lang is preferred for blockchain monitoring where `big.Int` 
operations (balance checks, threshold comparisons, gas calculations) are common.

### 0.7 Architecture Philosophy

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                                                                              │
│   HEXAGATE APPROACH                    WALNUT APPROACH                      │
│   ─────────────────                    ───────────────                      │
│                                                                              │
│   ┌─────────────┐                      ┌─────────────┐                      │
│   │  .gate DSL  │ ──Proprietary──►     │    YAML     │ ──Open Standard──►  │
│   └──────┬──────┘                      └──────┬──────┘                      │
│          │                                    │                              │
│   ┌──────▼──────┐                      ┌──────▼──────┐                      │
│   │  Compiler   │ ──Closed Source──►   │ expr-lang   │ ──Open Source───►   │
│   └──────┬──────┘                      └──────┬──────┘                      │
│          │                                    │                              │
│   ┌──────▼──────┐                      ┌──────▼──────┐                      │
│   │  Hexagate   │ ──SaaS Only─────►    │  Go Runtime │ ──Self-hosted───►   │
│   │    API      │                      │  + Custom   │    or SaaS           │
│   └─────────────┘                      │  Functions  │                      │
│                                        └─────────────┘                      │
│                                                                              │
│   AUDIENCE:                            AUDIENCE:                             │
│   - Need to learn Gatelang             + SRE: already uses YAML (K8s)       │
│   - Only Hexagate team knows it        + DevOps: already uses YAML (CI/CD)  │
│   - No community resources             + Security: already uses YAML (Sigma)│
│                                                                              │
│   Result:                              Result:                               │
│   - Vendor lock-in                     + No lock-in                         │
│   - SaaS dependency                    + Self-hosted option                 │
│   - Learning curve                     + Familiar YAML + JS-like expr       │
│   - Closed ecosystem                   + Open, extensible                   │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 1. EXECUTIVE SUMMARY

### 1.1 Vision

Walnut Monitoring is a **universal blockchain security monitoring platform** designed for **any EVM-compatible chain** with native support for L2 rollups, cross-chain bridges, and multi-chain ecosystems. The platform combines:

- **Declarative YAML-based DSL** for monitor configuration (no custom code required)
- **Native cross-chain correlation** (L1â†”L2, L2â†”L2, heterogeneous chains)
- **Real-time and pattern-based alerting** with sub-second latency
- **Threat intelligence integration** for proactive security
- **Self-hosted or managed deployment** options

### 1.2 Key Differentiators

| Capability | Custom Solutions | Hexagate | Forta | **Walnut** |
|------------|------------------|----------|-------|------------|
| Cross-chain correlation | Custom code per case | Native (SaaS only) | Limited | **Native + Self-hosted** |
| DSL expressiveness | Code-only | .gate compiled DSL | Bot SDK | **YAML + expr-lang** |
| Learning curve for Security/SRE | High (Go/Python) | Medium (Gatelang) | High (SDK) | **Low (YAML - industry standard)** |
| Pattern detection | Manual implementation | Limited | Bot-based | **First-class windowed rules** |
| Threat intelligence | None | Integrated | Community | **Pluggable architecture** |
| State validation (eth_getProof) | Custom | Limited | None | **Native** |
| Deployment model | Self-hosted only | SaaS only | Decentralized | **Both options** |
| Chain support | Single chain | Multi-chain | Multi-chain | **Universal EVM + roadmap** |

### 1.3 Primary Value Proposition

**"10x faster monitor creation with native cross-chain correlation and state validation â€” without vendor lock-in."**

Why 10x Faster?
- YAML = Zero config learning curve â€” Your SRE/Security team already knows YAML from Kubernetes, Prometheus, Falco, Sigma
- No code required â€” Unlike OP Monitorism (Go) or Forta (TypeScript/Python)
- No proprietary language â€” Unlike Hexagate (Gatelang)
- expr-lang = familiar â€” JavaScript-like expressions, not a new syntax to learn

Validated by Optimism Foundation (First Design Partner):
*"Fix cross-chain L1â†”L2 correlation and make monitor creation 10x easier"* â€” Josep, Optimism Foundation

---

## 2. PROBLEM STATEMENT & MARKET OPPORTUNITY

### 2.1 The Problem

Modern blockchain ecosystems â€” **L2 rollups, cross-chain bridges, DeFi protocols** â€” face **critical security and operational challenges**:

#### Universal Challenges (All Chains)
- **Cross-chain correlation**: Events on L1 must be correlated with L2 state (and vice versa)
- **Bridge security**: Withdrawal validation, deposit relay, fake proof detection
- **Governance monitoring**: Multisig executions, proxy upgrades, parameter changes
- **Threat detection**: Sanctioned addresses, exploit patterns, anomaly detection

#### Current Solutions Fall Short
- **Custom code solutions** (e.g., OP Monitorism): 
  - 2-4 weeks to implement each new monitor
  - No DSL for indexed parameter filtering
  - Cross-chain requires custom code per case
  - No pattern/windowed alerting

- **Hexagate**:
  - SaaS-only (network latency, data sovereignty concerns)
  - Proprietary .gate language (vendor lock-in)
  - No self-hosting for sensitive infrastructure

- **Forta**:
  - Decentralized = variable latency
  - Bot SDK requires coding
  - Limited cross-chain correlation

### 2.2 Market Opportunity

| Segment | Market Size | Opportunity |
|---------|-------------|-------------|
| **L2 Rollups** | $50M+ ARR | 50+ rollups by 2026, each needs monitoring |
| **Cross-Chain Bridges** | $30M+ ARR | High-value targets, critical security needs |
| **DeFi Protocols** | $200M+ ARR | Multi-chain deployments, exploit prevention |
| **Enterprise/Institutional** | $500M+ ARR | Compliance requirements, self-hosted needs |
| **L1 Chains** | $100M+ ARR | Validator monitoring, network health |

### 2.3 Timing

- **L2 explosion**: 50+ rollups expected by end of 2026
- **Regulatory pressure**: Institutions require auditable monitoring
- **Security incidents**: $3.8B lost to hacks in 2023-2025
- **Cross-chain complexity**: Every chain needs monitoring, few solutions exist

---

## 3. TARGET CUSTOMERS & DESIGN PARTNER

### 3.1 Target Customer Segments

| Segment | Key Pain Points | Why Walnut |
|---------|-----------------|------------|
| **L2 Rollups** | Cross-chain correlation, fault proof monitoring, state validation | Native L1â†”L2 correlation, eth_getProof |
| **Bridge Operators** | Multi-chain event correlation, security monitoring | Cross-chain DSL, multiple network support |
| **DeFi Protocols** | Cross-chain liquidity monitoring, exploit detection | Real-time alerts, threat intel integration |
| **Exchanges** | Compliance, threat intel, audit trails | Pluggable threat intel, self-hosted option |
| **Institutional** | SLA requirements, compliance, data sovereignty | Self-hosted deployment, audit logs |

### 3.2 First Design Partner: Optimism Foundation

**Why Optimism First:**
- Large ecosystem (Superchain = multiple chains)
- Existing monitoring solution (OP Monitorism) with known limitations
- Clear budget and willingness to pay
- Reference customer for other L2s

**Validated Pain Points (from Josep meeting):**

1. **Cross-chain monitoring complexity**
   - Need to correlate L1 events with L2 state
   - Current solution: custom Go code for each monitor
   - Time to implement new monitor: 2-4 weeks

2. **Monitor creation bottleneck**
   - Security team wants to create monitors without engineering
   - Current DSL too limited (topics[0] only)
   - Need: SDK or UI for rapid monitor deployment

3. **State validation issues**
   - Tenderly state diffs unreliable for their use cases
   - Need: Native `eth_getProof` based validation
   
---

## 4. TECHNICAL ARCHITECTURE OVERVIEW

### 4.1 High-Level Architecture 

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           DATA INGESTION LAYER                               │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   ┌─────────┐    ┌─────────┐    ┌─────────┐                                │
│   │  Node   │    │  NaaS   │    │  NaaS   │    (Infura/Alchemy/QuickNode)  │
│   │ (Self)  │    │Provider │    │Provider │                                │
│   └────┬────┘    └────┬────┘    └────┬────┘                                │
│        │              │              │                                       │
│        │    WS + gRPC/HTTPS (Multi-RPC Reliability)                        │
│        │              │              │                                       │
│   ┌────▼──────────────▼──────────────▼────┐                                │
│   │     Network Subscriber Services        │  (per chain, horizontally     │
│   │     - eth_subscribe newHeads          │   scalable)                    │
│   │     - eth_subscribe logs              │                                │
│   │     - eth_subscribe newPendingTransactions │                            │
│   └────────────────┬──────────────────────┘                                │
│                    │                                                        │
│   ┌────────────────▼──────────────────────┐                                │
│   │         Kafka: Block Event Topics      │                                │
│   └────────────────┬──────────────────────┘                                │
│                    │                                                        │
├────────────────────┼────────────────────────────────────────────────────────┤
│                    │           STORAGE LAYER                                 │
├────────────────────┼────────────────────────────────────────────────────────┤
│                    │                                                        │
│   ┌────────────────▼────┐    ┌─────────────────┐    ┌──────────────────┐   │
│   │   Redis Hot Buffer  │    │   ClickHouse    │    │    PostgreSQL    │   │
│   │   (K blocks/reorg)  │    │  (Cold Storage) │    │  (Rules, State)  │   │
│   └─────────────────────┘    └─────────────────┘    └──────────────────┘   │
│                                                                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                           PROCESSING LAYER                                   │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │                      Event Router Services                           │   │
│   │   - DSL Rule Matching (Bloom filter pre-check)                      │   │
│   │   - Threat Intel Enrichment                                         │   │
│   │   - Fast Filter Evaluation (expr-lang)                              │   │
│   └────────────────────────────┬────────────────────────────────────────┘   │
│                                │                                            │
│   ┌────────────────────────────▼────────────────────────────────────────┐   │
│   │                       Alert Services                                 │   │
│   │   - Realtime Alert Execution                                        │   │
│   │   - Windowed Pattern Evaluation (Redis state)                       │   │
│   │   - Cross-Chain Correlation Engine                                  │   │
│   │   - AlertExecutionLog → Kafka                                       │   │
│   └────────────────────────────┬────────────────────────────────────────┘   │
│                                │                                            │
├────────────────────────────────┼────────────────────────────────────────────┤
│                                │        DELIVERY LAYER                       │
├────────────────────────────────┼────────────────────────────────────────────┤
│                                │                                            │
│   ┌────────────────────────────▼────────────────────────────────────────┐   │
│   │                  Kafka: Alert Topics                                 │   │
│   └────────────────────────────┬────────────────────────────────────────┘   │
│                                │                                            │
│   ┌────────────────────────────▼────────────────────────────────────────┐   │
│   │              Delivery Channel Services                               │   │
│   │   - Slack / Telegram / Discord                                      │   │
│   │   - PagerDuty / OpsGenie                                            │   │
│   │   - Webhook / Custom Endpoints                                      │   │
│   │   - Email                                                           │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 4.2 Key Architectural Decisions

| Decision | Rationale |
|----------|-----------|
| **Multi-RPC (3 providers)** | Reliability: 2 WS hot, 1 HTTP/gRPC fallback for heavy pulls |
| **Redis hot buffer** | K blocks + margin for reorg handling per network |
| **Kafka for events** | Decoupling, replay capability, horizontal scaling |
| **ClickHouse cold storage** | Time-series optimized, fast aggregations for patterns |
| **expr-lang over CEL** | Simpler syntax, better Go integration, no compilation step |
| **YAML over custom DSL** | Lower barrier, tooling ecosystem, easier validation |

### 4.3 Data Flow

1. **Block arrives** â†’ Network Subscriber receives via WebSocket (`eth_subscribe newHeads`)
2. **Block + Transactions + Logs** â†’ Kafka Block Event Topic
3. **Event Router** â†’ Matches against indexed DSL rules (Bloom filter pre-check)
4. **Matched events** â†’ Enriched with threat intel (Phase 1: basic, Phase 3: full) â†’ Alert Service
5. **Alert Service** â†’ Evaluates complex conditions (including cross-chain correlation for Phase 1 critical monitors) â†’ Creates AlertExecutionLog
6. **AlertExecutionLog** â†’ Kafka Alert Topic â†’ Delivery Channel Service
7. **Delivery** â†’ Slack/Telegram/PagerDuty/Webhook

**Mempool Flow (Phase 2+):**
- **Pending transactions** â†’ Network Subscriber receives via WebSocket (`eth_subscribe newPendingTransactions`)
- **Mempool events** â†’ Kafka Mempool Event Topic
- **Event Router** â†’ Applies same DSL filters (with `source: mempool`)
- **Matched mempool events** â†’ Alert Service (for proactive detection)

---

## 5. DSL SPECIFICATION (YAML)

### 5.1 Top-Level Structure

Every rule file follows this structure:

```yaml
version: 1

# === METADATA ===
name: string                    # Unique identifier
description: string             # Human-readable description
priority: P1 | P2 | P3 | P4 | P5   # Alert severity
tags:                           # For categorization
  - string

# === RULE CLASSIFICATION ===
rule_kind: realtime | windowed  # Execution model
type: single_chain | multi_chain | cross_chain  # Correlation scope
event: transaction | block | mempool | periodic  # Trigger source

# === CHAIN SPECIFICATION ===
chain:
  kind: evm | solana | cosmos   # VM/runtime type
  networks: [chain_ids]         # Which networks to monitor

# === FILTERS (for single_chain/multi_chain) ===
transaction:                    # Transaction filter spec
  source: block | mempool
  status: [mined, confirmed10, pending]
  filters: [...]

# === PATTERNS (for windowed rules) ===
pattern:
  window: duration              # e.g., "5m", "1h"
  logic:
    kind: count | all_of | absence
    ...

# === CROSS-CHAIN (for cross_chain type) ===
cross_chain:
  sources: [...]
  correlation:
    mode: positive | negative
    join: [...]
    window: {...}

# === THREAT INTEL (optional enrichment) ===
threat_intel:
  enrich: [from, to, contract]
  conditions:
    ...

# === ALERT CONFIGURATION ===
alert:
  channels: [slack, pagerduty, webhook]
  template: string
  dedup_key: string
  cooldown: duration
```

### 5.2 Rule Kind Semantics

#### `realtime`
- **Single event** (or correlated event pair) triggers immediate alert
- Sub-second latency from event to alert
- Use for: critical security events, threshold breaches, anomalies

#### `windowed`
- **Multiple events over time** required to trigger
- Maintains state in Redis for rolling window evaluation
- Use for: burst detection, heartbeat monitoring, pattern matching

### 5.3 Type Semantics

#### `single_chain`
- Rule evaluated per event on **one chain kind**
- Can monitor multiple networks of same kind (e.g., OP Mainnet + Base + Zora)
- No correlation between networks

#### `multi_chain`
- Rule applied across **different chain kinds** (e.g., EVM + Solana)
- Same filters, no inter-chain correlation
- Use for: portfolio-wide monitoring

#### `cross_chain`
- **Explicit correlation** between events on different chains
- Supports L1â†”L2, L2â†”L2, heterogeneous (EVMâ†”Solana)
- Positive mode: both events must occur
- Negative mode: event A occurs, event B must NOT occur within window

### 5.4 Transaction Filter Specification (EVM)

```yaml
transaction:
  source: block | mempool
  status: [mined, confirmed10, pending]
  filters:
    - id: string                # Optional filter identifier
      
      # Network constraint
      network: chain_id         # Must be in chain.networks
      
      # Transaction status
      status: success | fail    # Override global status
      
      # Address filters
      from: address | [addresses]
      to: address | [addresses]
      
      # Value filters (wei as string)
      value:
        eq: "amount"
        gt: "amount"
        gte: "amount"
        lt: "amount"
        lte: "amount"
      
      # Gas filters
      gas:
        gt: "amount"
        lt: "amount"
      gasLimit:
        lt: "amount"
      effectiveGasPrice:
        gte: "amount"
      
      # Function call filter
      function:
        name: string            # e.g., "transfer"
        signature: string       # e.g., "transfer(address,uint256)"
        contract:
          address: address
      
      # Event emitted filter (requires verified contract)
      eventEmitted:
        contract:
          address: address
        name: string            # Event name
        args:                   # Event parameter matching (by position, 0-based)
          # NOTE: index refers to parameter POSITION in event signature, 
          # NOT topic position. Works with both indexed and non-indexed params.
          # Example: event Transfer(address indexed from, address indexed to, uint256 value)
          #   index 0 = from, index 1 = to, index 2 = value
          - index: 0
            value: "0x..."      # Match exact value
            capture: true       # Extract for use in alert template
          - index: 1
            op: gt              # Comparison operator (eq|gt|gte|lt|lte|contains)
            value: "1000000000000000000"
            capture: true
      
      # Raw log filter (for unverified contracts)
      logEmitted:
        contract:
          address: address
        topics:
          - "0xddf252ad..."     # topics[0] = event signature hash
          - "0x000000..."       # topics[1] = indexed param 1
          - null                # topics[2] = any value
        data:
          startsWith: "0x..."
```

### 5.5 Pattern Logic Specification

#### Count Pattern
```yaml
pattern:
  window: "5m"
  logic:
    kind: count
    target_filter: filter_id | "any"
    threshold:
      gte: 20
```

#### All-Of Pattern
```yaml
pattern:
  window: "60s"
  logic:
    kind: all_of
    events:
      - filter_id_1
      - filter_id_2
      - filter_id_3
```

#### Absence Pattern
```yaml
pattern:
  window: "5m"
  logic:
    kind: absence
    expect_missing: filter_id
```

### 5.6 Cross-Chain Correlation Specification

```yaml
cross_chain:
  sources:
    - id: source_identifier
      chain:
        kind: evm
        networks: [chain_id]
      transaction:
        source: block
        status: [mined]
        filters: [...]
    
    - id: another_source
      chain:
        kind: evm
        networks: [different_chain_id]
      transaction:
        source: block
        status: [mined, confirmed10]
        filters: [...]
  
  correlation:
    mode: positive | negative
    
    # For positive mode
    join:
      - left: source_a.field.path
        op: eq | contains | startsWith
        right: source_b.field.path
    
    # For negative mode
    base: source_a              # The trigger source
    expect:
      target: source_b          # Must (not) occur
    
    window:
      max_delay: "300s"         # Maximum time between correlated events
```

### 5.7 Threat Intel Specification

```yaml
threat_intel:
  # Which addresses to enrich
  enrich:
    - from
    - to
    - contract
    - eventEmitted.contract
  
  # Alert conditions based on enrichment
  conditions:
    # Trigger if any enriched address has these labels
    labels:
      any_of:
        - "hacker"
        - "sanctioned"
        - "exploit"
        - "dprk"
    
    # Trigger if risk score exceeds threshold
    risk_score:
      gte: 0.7
    
    # Trigger for specific categories
    category:
      any_of:
        - "mixer"
        - "scam"
```

### 5.8 Alert Configuration

```yaml
alert:
  channels:
    - type: slack
      config:
        channel: "#security-alerts"
        mention: "@oncall"
    
    - type: pagerduty
      config:
        severity: critical
        routing_key: "${PAGERDUTY_KEY}"
    
    - type: webhook
      config:
        url: "https://api.example.com/alerts"
        headers:
          Authorization: "Bearer ${WEBHOOK_TOKEN}"
  
  template: |
    [ALERT] ${rule.name}
    
    **Chain:** ${event.chain} (${event.network})
    **Block:** ${event.block.number}
    **Transaction:** ${event.tx.hash}
    
    ${rule.description}
    
    **Details:**
    ${event.details}
  
  # Deduplication
  dedup_key: "${rule.name}-${event.tx.hash}"
  cooldown: "5m"
  
  # Error handling (for validation-type rules)
  on_error:
    action: alert | retry | skip    # What to do if validation fails
    retry_count: 3
    retry_delay: "5s"
    fallback_alert: true            # Send alert if all retries fail
```

### 5.9 Contract ABI Specification

For functions that decode calldata or call contracts, ABI resolution is required:

```yaml
# === CONTRACT ABI CONFIGURATION ===
contracts:
  # Option 1: Auto-resolve from block explorer (verified contracts)
  - address: "0xbEb5Fc579115071764c7423A4f12eDde41f106Ed"
    abi_source: etherscan    # Auto-fetch from Etherscan/Blockscout
    network: 1               # Which network to fetch ABI from
  
  # Option 2: Manual ABI file
  - address: "0x4200000000000000000000000000000000000016"
    abi_source: file
    abi_path: "./abis/L2ToL1MessagePasser.json"
  
  # Option 3: Inline ABI (for specific functions only)
  - address: "0xe5965Ab5962eDc7477C8520243A95517CD252fA9"
    abi_source: inline
    abi:
      - name: l2BlockNumber
        type: function
        inputs: []
        outputs:
          - type: uint256
            name: l2BlockNumber_

# === GLOBAL ABI SETTINGS ===
abi_config:
  # Default source for unknown contracts
  default_source: etherscan
  
  # Cache settings
  cache:
    enabled: true
    ttl: "24h"
  
  # Fallback behavior for unverified contracts
  on_unverified:
    action: warn | error | skip
    message: "Contract ${address} is not verified"
```

**ABI Resolution Order:**
1. Check `contracts` config for explicit ABI
2. If `abi_source: etherscan`, fetch from Etherscan API
3. If unverified, use `on_unverified` behavior
4. For `decode_calldata`, ABI is required; for `logEmitted`, raw topics work without ABI

---

### 5.10 Network Configuration

For multi-network monitors with per-network settings:

```yaml
# === NETWORK CONFIGURATION ===
config:
  # Per-network contract addresses
  networks:
    1:      # Ethereum Mainnet
      name: "Ethereum L1"
      bridge_contract: "0x99C9fc46f92E8a1c0deC1b1747d010903E884bE1"
      portal_contract: "0xbEb5Fc579115071764c7423A4f12eDde41f106Ed"
      security_council: "0x9BA6e03D8B90dE867373Db8cF1A58d2F7F006b3A"
    10:     # OP Mainnet
      name: "OP Mainnet"
      bridge_contract: "0x4200000000000000000000000000000000000010"
      message_passer: "0x4200000000000000000000000000000000000016"
      security_council: "0xc2819DC788505Aac350142A7A707BF9D03E3Bd03"
    8453:   # Base
      name: "Base"
      bridge_contract: "0x4200000000000000000000000000000000000010"
      security_council: "0x0a7361e734cf3f0394B0FC4a45C74E7a4eC70940"
  
  # Global settings
  global:
    alert_cooldown: "5m"
    max_block_lag: 10

# === USAGE IN FILTERS ===
# Reference config values using ${config.networks[network_id].field}
filters:
  - eventEmitted:
      contract:
        address: "${config.networks[event.network].bridge_contract}"
```

---

### 5.11 Webhook Input Source (Phase 1)

For external systems to push data into Walnut:

```yaml
# === WEBHOOK SOURCE DEFINITION ===
webhook_sources:
  - id: vault_status
    endpoint: /webhooks/vault-status    # POST endpoint
    auth:
      type: hmac | bearer | api_key
      secret: "${env:WEBHOOK_SECRET}"   # For HMAC signature validation
    
    # Expected payload schema (for validation)
    schema:
      type: object
      required: [vault_id, latest_nonce, updated_at]
      properties:
        vault_id:
          type: string
        latest_nonce:
          type: integer
        updated_at:
          type: string
          format: datetime
    
    # Rate limiting
    rate_limit:
      max_requests: 100
      window: "1m"

# === USING WEBHOOK IN RULES ===
version: 1
name: vault_nonce_check
rule_kind: realtime
type: single_chain

# Trigger on webhook receipt
triggers:
  - id: vault_update
    source: webhook              # Special source type
    webhook_id: vault_status     # Reference to webhook_sources

# Correlate webhook data with on-chain
correlation:
  join:
    - left: webhook.latest_nonce
      op: lt
      right: "${contract_call(config.networks[1].security_council).nonce()}"
```

---

### 5.12 Error Handling

For rules that involve external calls (eth_getProof, contract calls), error handling is critical:

```yaml
on_error:
  # When RPC call fails
  rpc_timeout:
    action: retry
    max_retries: 3
    backoff: exponential
    fallback: alert_degraded    # Alert with "validation_skipped" flag
  
  # When L2 node is not synced
  node_not_synced:
    action: wait
    max_wait: "60s"
    fallback: alert_with_warning
  
  # When data is invalid/unparseable
  invalid_data:
    action: alert_error
    include_raw_data: true
```

---

### 5.13 Threat Intelligence Specification (Phase 1 Basic)

Phase 1 provides **basic threat intelligence** capabilities:

```yaml
# === PHASE 1: BASIC THREAT INTEL ===
threat_intel:
  # Source type
  source: manual | api
  
  # Option 1: Manual address list (CSV/JSON)
  manual:
    # Local file with sanctioned/flagged addresses
    file: "./threat_intel/sanctioned_addresses.csv"
    format: csv    # csv | json
    columns:
      address: 0
      label: 1
      risk_score: 2
      source: 3
    
    # Auto-reload interval
    refresh: "1h"
  
  # Option 2: Simple API integration (single provider)
  api:
    provider: chainalysis | trm_labs | custom
    url: "${THREAT_INTEL_API_URL}"
    auth:
      type: api_key
      header: "X-API-Key"
      value: "${THREAT_INTEL_API_KEY}"
    
    # Rate limiting (to stay within API limits)
    rate_limit:
      max_requests: 100
      window: "1m"
    
    # Cache responses
    cache:
      enabled: true
      ttl: "24h"

# === PHASE 1 vs PHASE 3 COMPARISON ===
# 
# Phase 1 (Basic):
#   - Manual CSV/JSON lists
#   - Single API provider
#   - Basic label matching (sanctioned, hacker, etc.)
#   - Simple caching
#
# Phase 3 (Full):
#   - Multiple providers (Chainalysis + TRM + custom)
#   - Dynamic risk scoring
#   - Real-time threat intel updates
#   - Federated threat intel sharing
#   - Advanced pattern detection (money laundering flows)
```

**Phase 1 Threat Intel Conditions:**
```yaml
threat_intel:
  enrich: [from, to]
  conditions:
    # Phase 1: Simple label matching
    labels:
      any_of:
        - "ofac_sanctioned"
        - "hacker"
        - "known_attacker"
    
    # Phase 1: Basic risk threshold
    risk_score:
      gte: 0.85    # High confidence only
```

---

### 5.14 External Data Sources (3rd Party APIs)

Phase 1 focuses on blockchain-native monitoring. External API integrations are Phase 2.

OP Monitorism requires 3rd party integrations that go beyond blockchain data:
- **1Password CLI** - Verify pre-signed emergency transactions exist
- **External HTTP APIs** - PSP executor service

#### Phase 2: External Source DSL

```yaml
# === EXTERNAL DATA SOURCES ===
external_sources:
  # Secure vault check (like 1Password)
  vault_check:
    type: secret_manager
    provider: onepassword | hashicorp_vault | aws_secrets
    config:
      vault_id: "${env:ONEPASS_VAULT_ID}"
      token: "${env:ONEPASS_TOKEN}"
    
  # External HTTP API
  http_api:
    type: http
    config:
      base_url: "https://internal-api.example.com"
      auth:
        type: mtls | bearer | api_key
        cert_path: "${env:CLIENT_CERT}"
        key_path: "${env:CLIENT_KEY}"
      timeout: 30s
      retry: 3

# === MONITOR WITH EXTERNAL SOURCE ===
version: 1
name: presigned_pause_check
description: "Verify pre-signed pause transactions exist in vault"
rule_kind: realtime
type: single_chain

chain:
  kind: evm
  networks: [1]

triggers:
  # Trigger on Safe nonce change
  - id: safe_nonce_changed
    transaction:
      filters:
        - to: "${SAFE_ADDRESS}"
          function:
            name: execTransaction

# External validation
external_validation:
  source: vault_check
  query:
    list_items:
      vault: "security-council-${NETWORK}"
      filter: "title startsWith 'ready-'"
  
  # Extract latest nonce from vault
  extract:
    latest_vault_nonce: |
      max(items.map(i => parseInt(i.title.replace('ready-', '').replace('.json', ''))))

  # Compare with on-chain nonce
  condition: |
    latest_vault_nonce >= contract_call(SAFE_ADDRESS).nonce()

alert:
  severity: critical
  message: |
    WARNING: PRE-SIGNED PAUSE GAP DETECTED
    Safe Nonce: ${safe_nonce}
    Latest Vault Nonce: ${latest_vault_nonce}
    Gap: ${safe_nonce - latest_vault_nonce} transactions behind
```

#### Why External Sources are Phase 2 (Not MVP)

| Aspect | Blockchain Data (Phase 1) | External APIs (Phase 2) |
|--------|---------------------------|-------------------------|
| **Reliability** | Node redundancy built-in | Need custom retry/failover |
| **Security** | Public data, no auth | Auth, secrets management |
| **Latency** | Predictable (block time) | Variable, can timeout |
| **Scope** | Core monitoring value | Operational enhancement |

#### Phase 1 Alternative: Webhook Input

For MVP, external systems can **push** data to Walnut instead of Walnut pulling:

```yaml
# External system pushes vault status via webhook
webhook_source:
  id: vault_status_webhook
  endpoint: /webhooks/vault-status
  auth:
    type: hmac
    secret: "${env:WEBHOOK_SECRET}"
  
  # Webhook payload schema
  payload_schema:
    latest_nonce: integer
    vault_id: string
    updated_at: timestamp

# Monitor uses webhook data
triggers:
  - id: vault_status_update
    source: webhook
    webhook_id: vault_status_webhook
    
correlation:
  # Compare webhook data with on-chain
  join:
    - left: webhook.latest_nonce
      op: lt
      right: "${contract_call(SAFE_ADDRESS).nonce()}"
```

**Webhook Advantages:**
- External system controls polling frequency
- Walnut stays stateless for external data
- Simpler security model (inbound vs outbound)
- Works with any secret manager (1Password, Vault, AWS SM)

---

### 5.15 Built-in Functions (Blockchain-Specific)

Walnut DSL includes built-in functions for blockchain operations. These are **equivalent to Hexagate's Gatelang built-ins** but with cleaner syntax.

#### Comparison: Hexagate vs Walnut Built-ins

| Hexagate (Gatelang) | Walnut DSL | Description |
|---------------------|------------|-------------|
| `Call { contract, signature }` | `contract_call(address).function()` | Call view/pure contract function |
| `Calls { contract, signature }` | `tx_calls(contract, signature)` | Get function calls from tx in block |
| `Events { contract, signature }` | `eventEmitted` filter | Get events (native DSL filter) |
| `HistoricalEvents { ... }` | `historical_events(contract, event, blocks)` | Query past events |
| `StateRoot { block, chainId }` | `state_root(chainId, block)` | Get L2 state root (cross-chain) |
| `BlockHash { block, chainId }` | `block_hash(chainId, block)` | Get block hash (cross-chain) |
| `StorageHash { address, block, chainId }` | `storage_hash(chainId, address, block)` | Get storage root via eth_getProof |
| `Keccak256 { input }` | `keccak256(data)` | Compute keccak256 hash |
| `BlockTimestamp` | `block_timestamp()` | Current block timestamp |
| `BlockNumber` | `block_number()` | Current block number |
| N/A | `decode_calldata(input, path)` | Decode transaction calldata |
| N/A | `eth_getProof(address, keys, block)` | Full eth_getProof response |

#### Built-in Function Specifications

```yaml
# === CONTRACT CALLS ===
# Call a view/pure function on a contract
contract_call:
  syntax: "${contract_call(address).functionName(args...)}"
  example: "${contract_call(disputeProxy).l2BlockNumber()}"
  returns: "Function return value (auto-decoded)"
  phase: 1

# === CROSS-CHAIN STATE ACCESS ===
# Get state root from another chain
state_root:
  syntax: "${state_root(chainId, blockNumber)}"
  example: "${state_root(10, 12345678)}"
  returns: "bytes32 state root"
  requires: "Archive node access on target chain"
  phase: 1

# Get block hash from another chain
block_hash:
  syntax: "${block_hash(chainId, blockNumber)}"
  example: "${block_hash(10, 12345678)}"
  returns: "bytes32 block hash"
  phase: 1

# Get storage hash (eth_getProof storageHash field)
storage_hash:
  syntax: "${storage_hash(chainId, address, blockNumber)}"
  example: "${storage_hash(10, '0x4200...0016', 12345678)}"
  returns: "bytes32 storage root hash"
  requires: "Archive node with eth_getProof support"
  phase: 1

# === CRYPTOGRAPHIC ===
# Compute keccak256 hash
keccak256:
  syntax: "${keccak256(data1, data2, ...)}"
  example: "${keccak256(version, stateRoot, storageHash, blockHash)}"
  returns: "bytes32 hash"
  phase: 1

# === TRANSACTION DATA ===
# Decode calldata from transaction input
decode_calldata:
  syntax: "${decode_calldata(tx.input, 'path.to.field')}"
  example: "${decode_calldata(tx.input, 'outputRootProof.l2BlockNumber')}"
  returns: "Decoded value from calldata"
  note: "Requires ABI knowledge of target function"
  phase: 1

# === STATE VALIDATION ===
# Full eth_getProof query
eth_getProof:
  syntax: "${eth_getProof(address, storageKeys, blockNumber)}"
  example: "${eth_getProof('0x4200...0016', [storageKey], 12345678)}"
  returns: |
    {
      accountProof: [...],
      balance: "0x...",
      codeHash: "0x...",
      nonce: "0x...",
      storageHash: "0x...",
      storageProof: [{ key, value, proof }]
    }
  phase: 1

# === HISTORICAL QUERIES (Phase 2) ===
# Query historical events
historical_events:
  syntax: "${historical_events(contract, eventName, fromBlock, toBlock)}"
  example: "${historical_events(factory, 'DisputeGameCreated', block - 1000, block)}"
  returns: "List of matching events"
  phase: 2

# Query historical function calls (from tx traces)
historical_calls:
  syntax: "${historical_calls(contract, signature, fromBlock, toBlock)}"
  example: "${historical_calls(game, 'move(uint256,bytes32)', block - 100, block)}"
  returns: "List of matching calls with sender"
  phase: 2
```

#### Example: Output Root Computation (Hexagate vs Walnut)

**Hexagate Gatelang:**
```gate
use StateRoot, BlockHash, StorageHash, Keccak256, Call from hexagate;

source blockNumber: integer = Call {
    contract: disputeProxy,
    signature: "function l2BlockNumber() public pure returns (uint256)"
};

source stateRoot: bytes = StateRoot {
    block: blockNumber,
    chainId: l2ChainId
};

source storageHash: bytes = StorageHash {
    address: 0x4200000000000000000000000000000000000016,
    block: blockNumber,
    chainId: l2ChainId
};

source blockHash: bytes = BlockHash {
    block: blockNumber,
    chainId: l2ChainId
};

source computed: bytes = Keccak256 {
    input: version + stateRoot + storageHash + blockHash
};
```

**Walnut DSL (equivalent):**
```yaml
validation:
  type: output_root_computation
  
  # Get L2 block number from dispute game contract
  at_block: "${contract_call(dispute_game.args[0]).l2BlockNumber()}"
  
  compute:
    # Cross-chain state access
    state_root: "${state_root(10, at_block)}"
    storage_hash: "${storage_hash(10, '0x4200...0016', at_block)}"
    block_hash: "${block_hash(10, at_block)}"
    
    # Compute output root
    result: "${keccak256(version, state_root, storage_hash, block_hash)}"
```

**Key Differences:**
| Aspect | Hexagate | Walnut |
|--------|----------|--------|
| Syntax | Verbose object syntax | Concise function calls |
| Readability | Requires learning custom syntax | Familiar function notation |
| Local testing | Requires API | Can mock functions locally |
| Extensibility | Closed | Add custom Go functions |

**Learning Curve Comparison:**
| Audience | Hexagate (Gatelang) | Walnut (YAML + expr) |
|----------|---------------------|----------------------|
| **SRE/DevOps** | 1-2 weeks (new language) | **Hours** (already knows YAML from K8s) |
| **Security Engineer** | 1-2 weeks (new language) | **Hours** (already knows YAML from Sigma/Falco) |
| **Go Developer** | 1 week | **Minutes** (expr-lang is intuitive) |
| **Non-Engineer** | Not possible | **Days** (just YAML fields to learn) |

---

## 6. REFERENCE IMPLEMENTATION: OPTIMISM SUPERCHAIN

This section demonstrates Walnut's capabilities using Optimism Superchain as the reference implementation. These same patterns apply to any EVM-compatible chain.

MVP Focus: Real-time security monitors. Operational monitoring moves to Phase 2+.

### 6.0 YAML Monitor Reference Guide

Before diving into examples, here's what each YAML monitor contains:

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         YAML MONITOR STRUCTURE                          │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  ┌──────────────────┐                                                   │
│  │    METADATA      │  version, name, description, priority, tags       │
│  └────────┬─────────┘                                                   │
│           │                                                              │
│  ┌────────▼─────────┐                                                   │
│  │  CLASSIFICATION  │  rule_kind (realtime/windowed)                    │
│  │                  │  type (single_chain/cross_chain)                  │
│  │                  │  event (transaction/block/mempool)                │
│  └────────┬─────────┘                                                   │
│           │                                                              │
│  ┌────────▼─────────┐                                                   │
│  │  CHAIN CONFIG    │  kind: evm, networks: [chain_ids]                 │
│  └────────┬─────────┘                                                   │
│           │                                                              │
│  ┌────────▼─────────┐                                                   │
│  │  FILTERS         │  What events/transactions to match                │
│  │  - eventEmitted  │  Smart contract events (Transfer, Upgraded...)   │
│  │  - logEmitted    │  Raw logs (topics, data)                         │
│  │  - from/to       │  Address filters                                  │
│  │  - value         │  ETH amount filters                               │
│  └────────┬─────────┘                                                   │
│           │                                                              │
│  ┌────────▼─────────┐                                                   │
│  │  CROSS-CHAIN     │  (if type: cross_chain)                          │
│  │  - sources[]     │  Events from different chains                    │
│  │  - correlation   │  How to join/match events                        │
│  │  - validation    │  eth_getProof state checks                       │
│  └────────┬─────────┘                                                   │
│           │                                                              │
│  ┌────────▼─────────┐                                                   │
│  │  ALERT CONFIG    │  channels (Slack, PagerDuty, Webhook)            │
│  │                  │  template (message format)                        │
│  │                  │  dedup_key, cooldown                             │
│  └──────────────────┘                                                   │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

**Monitor Types Explained:**

| Monitor | What It Does | Key DSL Features Used |
|---------|--------------|----------------------|
| **6.1 Fake Withdrawal** | Detects withdrawals on L1 that don't exist on L2 | `cross_chain`, `validation: state_proof`, `eth_getProof` |
| **6.2 Invalid Output Root** | Validates L2 state commitments on L1 | `cross_chain`, `validation: output_root_computation` |
| **6.3 Proxy Upgrade** | Alerts when contract implementation changes | `single_chain`, `eventEmitted: Upgraded` |
| **6.4 Bridge Pause** | Detects emergency pause events | `single_chain`, `eventEmitted: Paused` |
| **6.5 Sanctioned Address** | Flags transactions from/to blacklisted addresses | `single_chain`, `threat_intel` |
| **6.6 Multisig Execution** | Monitors Security Council transactions | `single_chain`, `eventEmitted: ExecutionSuccess` |
| **6.7 SystemConfig Change** | Alerts on chain parameter changes | `single_chain`, multiple `eventEmitted` filters |
| **6.8 Challenger Loses** | Detects if honest challenger lost dispute | `single_chain`, `eventEmitted: Resolved` |
| **6.9 Large Withdrawal** | Whale alert for big withdrawals | `single_chain`, `value` filter, `threat_intel` |
| **6.10 Withdrawal Not Proven** | Cross-chain correlation for stuck withdrawals | `cross_chain`, `correlation: negative` |

**Key Concepts:**

| Concept | Meaning |
|---------|---------|
| `rule_kind: realtime` | Alert immediately when event matches |
| `rule_kind: windowed` | Aggregate events over time window |
| `type: single_chain` | Monitor events on one chain (can be multiple networks) |
| `type: cross_chain` | Correlate events across different chains (e.g., L1â†”L2) |
| `eventEmitted` | Match smart contract event by name and indexed args |
| `logEmitted` | Match raw log by topics (for unverified contracts) |
| `correlation: positive` | Both events must occur to trigger |
| `correlation: negative` | Alert if event A occurs but B does NOT within window |
| `validation: state_proof` | Use `eth_getProof` to verify on-chain state |
| `capture: true` | Extract this value for use in alert template |

---

### TIER 1: CRITICAL SECURITY (MVP Phase 1)

These monitors detect **active attacks** or **unauthorized state changes**. 
Zero tolerance for missed events. All are `realtime` + `cross_chain` or `single_chain`.

These YAML examples use Optimism contract addresses as reference. To adapt for other chains, only the `address` fields need to change:

| Chain | OptimismPortal Equivalent | Bridge Contract |
|-------|--------------------------|-----------------|
| Arbitrum | Outbox | L1GatewayRouter |
| zkSync | DiamondProxy | L1ERC20Bridge |
| Polygon | RootChainManager | RootChainManagerProxy |

Monitors 6.1 and 6.2 require cross-chain correlation and `eth_getProof` 
state validation â€” capabilities included in Phase 1 for critical security. Full cross-chain expands in Phase 2.

---

### 6.1 Fake Withdrawal Detection (CRITICAL)

**Why Critical:** This is the #1 attack vector for optimistic rollups. A successful fake 
withdrawal drains the bridge. This monitor MUST work from day 1.

**How This YAML Works:**
```
1. TRIGGER: Listen for WithdrawalProven event on L1 (OptimismPortal contract)
2. VALIDATE: Query L2 state using eth_getProof to check if withdrawal exists
3. CORRELATE: Match withdrawal hash from L1 event with L2 storage
4. ALERT: If L2 validation fails â†’ CRITICAL security alert
```

```yaml
version: 1

name: optimism_fake_withdrawal_detection
description: |
  CRITICAL SECURITY MONITOR: Detects withdrawal proofs submitted on L1 
  that do not have corresponding valid withdrawals on L2. This is the 
  PRIMARY DEFENSE against withdrawal forgery attacks.
  
  Attack scenario:
  1. Attacker submits fake WithdrawalProven on L1
  2. If undetected, attacker can drain bridge after challenge period
  
  Detection method:
  1. Capture WithdrawalProven event on L1
  2. Query L2 state using eth_getProof
  3. Verify withdrawal exists in L2ToL1MessagePasser storage
  4. Alert if proof is invalid or withdrawal doesn't exist
priority: P1
tags:
  - security-critical
  - attack-detection
  - bridge
  - forgery

rule_kind: realtime
type: cross_chain
event: transaction

cross_chain:
  sources:
    # L1: Someone claims to prove a withdrawal
    - id: l1_withdrawal_proof
      chain:
        kind: evm
        networks:
          - 1         # Ethereum Mainnet
      transaction:
        source: block
        status: [mined]
        filters:
          - id: withdrawal_proven
            status: success
            eventEmitted:
              contract:
                address: "0xbEb5Fc579115071764c7423A4f12eDde41f106Ed"  # OptimismPortal
              name: WithdrawalProven
              args:
                - index: 0    # withdrawalHash
                  capture: true
                - index: 1    # from
                  capture: true
                - index: 2    # to
                  capture: true

    # L2: Validate the withdrawal actually exists
    - id: l2_state_validation
      chain:
        kind: evm
        networks:
          - 10        # OP Mainnet
      validation:
        type: state_proof
        method: eth_getProof
        contract: "0x4200000000000000000000000000000000000016"  # L2ToL1MessagePasser
        # Storage key derivation for Solidity mapping(bytes32 => bool):
        # storage_slot = keccak256(abi.encode(withdrawalHash, mappingSlot))
        # where mappingSlot is the storage slot of sentMessages mapping (slot 0)
        storage_key: 
          mapping: "sentMessages"
          slot: 0
          key: "${l1_withdrawal_proof.args.withdrawalHash}"
        # Block number extraction (Fault Proof Withdrawals):
        # proveWithdrawalTransaction signature:
        #   proveWithdrawalTransaction(
        #     Types.WithdrawalTransaction _tx,
        #     uint256 _disputeGameIndex,          <-- index into DisputeGameFactory
        #     Types.OutputRootProof _outputRootProof,  <-- contains: version, stateRoot, storageRoot, blockHash (NO l2BlockNumber!)
        #     bytes[] _withdrawalProof
        #   )
        # 
        # OutputRootProof does NOT contain l2BlockNumber.
        # We must: 1) extract _disputeGameIndex, 2) query dispute game, 3) call l2BlockNumber()
        at_block:
          method: dispute_game_query
          dispute_game_index: "${decode_calldata(l1_withdrawal_proof.tx.input, '_disputeGameIndex')}"
          factory: "0xe5965Ab5962eDc7477C8520243A95517CD252fA9"  # DisputeGameFactory
          extract: l2BlockNumber
        expected: exists_and_matches

  correlation:
    # NOTE: This is a "validation correlation" - different from event correlation.
    # mode: negative here means "alert when validation result is NOT valid"
    # The system performs L2 state validation and alerts if it fails.
    mode: negative
    base: l1_withdrawal_proof
    expect:
      target: l2_state_validation
      result: valid    # If result != valid, trigger alert
    window:
      max_delay: "30s"  # Time allowed for validation to complete

alert:
  channels:
    - type: pagerduty
      config:
        severity: critical
        routing_key: "${PAGERDUTY_CRITICAL_KEY}"
    - type: slack
      config:
        channel: "#security-critical"
        mention: "@security-oncall @engineering-oncall @executive-team"
    - type: webhook
      config:
        url: "${INCIDENT_WEBHOOK_URL}"
    - type: telegram
      config:
        chat_id: "${TELEGRAM_WAR_ROOM}"
  
  template: |
    CRITICAL: POTENTIAL FAKE WITHDRAWAL DETECTED
    
    A withdrawal proof was submitted on L1 that FAILED validation 
    against L2 state. This may indicate an ACTIVE ATTACK.
    
    **IMMEDIATE ACTION REQUIRED - INITIATE INCIDENT RESPONSE**
    
    **L1 Details:**
    - Transaction: ${l1_withdrawal_proof.tx.hash}
    - Block: ${l1_withdrawal_proof.block.number}
    - Timestamp: ${l1_withdrawal_proof.block.timestamp}
    
    **Claimed Withdrawal:**
    - Hash: ${l1_withdrawal_proof.args.withdrawalHash}
    - From: ${l1_withdrawal_proof.args.from}
    - To: ${l1_withdrawal_proof.args.to}
    
    **Validation Failure:**
    - Result: ${l2_state_validation.result}
    - Error: ${l2_state_validation.error}
    - L2 Block Checked: ${l2_state_validation.block_number}
    
    **Response Runbook:** https://runbooks.walnut.dev/fake-withdrawal
    
    Challenge window: 7 days from proof submission
  
  dedup_key: "${l1_withdrawal_proof.tx.hash}"
  cooldown: "0s"   # NEVER suppress critical security alerts
```

---

### 6.2 Invalid Output Root Detection (CRITICAL)

**Why Critical:** Invalid output roots are the foundation of fraud. If a malicious proposer 
submits a bad output root and it's not challenged, withdrawals based on that root succeed.

**How This YAML Works:**
```
1. TRIGGER: Listen for DisputeGameCreated event on L1 (captures claimed rootClaim)
2. COMPUTE: Fetch L2 state and calculate correct output root:
   - Get stateRoot from L2 block
   - Get messagePasserStorageRoot via eth_getProof
   - Get blockHash from L2 block
   - Compute: keccak256(version || stateRoot || storageRoot || blockHash)
3. COMPARE: claimed rootClaim vs computed result
4. ALERT: If mismatch â†’ CRITICAL fraud alert (challenger must act)
```

```yaml
version: 1

name: fault_proof_invalid_output_root
description: |
  CRITICAL SECURITY MONITOR: Validates that L2 output roots claimed in 
  dispute games match locally computed state.
  
  Output Root = keccak256(
    version || 
    stateRoot || 
    messagePasserStorageRoot || 
    blockHash
  )
  
  Attack scenario:
  1. Malicious proposer submits fake output root
  2. If unchallenged for 7 days, fake state becomes "finalized"
  3. Attacker can prove fake withdrawals against fake state
  
  Detection: Compare claimed root vs locally computed root
priority: P1
tags:
  - security-critical
  - fault-proof
  - output-root
  - fraud-detection

rule_kind: realtime
type: cross_chain
event: transaction

cross_chain:
  sources:
    # L1: New dispute game created with claimed output root
    - id: dispute_game_created
      chain:
        kind: evm
        networks:
          - 1
      transaction:
        source: block
        status: [mined]
        filters:
          - id: game_created
            status: success
            eventEmitted:
              contract:
                address: "0xe5965Ab5962eDc7477C8520243A95517CD252fA9"  # DisputeGameFactory
              name: DisputeGameCreated
              args:
                - index: 0    # disputeProxy (address of the dispute game)
                  capture: true
                - index: 1    # gameType (uint32)
                  capture: true
                - index: 2    # rootClaim (bytes32 - claimed L2 output root)
                  capture: true

    # L2: Compute the CORRECT output root
    - id: l2_computed_root
      chain:
        kind: evm
        networks:
          - 10
      validation:
        type: output_root_computation
        # L2 block number: Query the dispute game contract (args[0] = disputeProxy address)
        # The dispute game contract has l2BlockNumber() view function
        at_block: "${contract_call(dispute_game_created.args[0]).l2BlockNumber()}"
        compute:
          version: "0x0000000000000000000000000000000000000000000000000000000000000000"
          state_root: 
            method: eth_getBlockByNumber
            block: "${at_block}"
            extract: stateRoot
          message_passer_storage_root:
            method: eth_getProof
            contract: "0x4200000000000000000000000000000000000016"
            block: "${at_block}"
            extract: storageHash
          block_hash:
            method: eth_getBlockByNumber
            block: "${at_block}"
            extract: hash
        result: keccak256(version || state_root || message_passer_storage_root || block_hash)

  correlation:
    mode: positive
    join:
      - left: dispute_game_created.args[2]    # rootClaim
        op: neq     # Alert when they DON'T match
        right: l2_computed_root.result
    validation:
      on_match: alert    # Mismatch = potential fraud
      on_no_match: pass  # Match = valid claim

alert:
  channels:
    - type: pagerduty
      config:
        severity: critical
    - type: slack
      config:
        channel: "#fault-proof-alerts"
        mention: "@security-oncall @challenger-team"
  
  template: |
    INVALID OUTPUT ROOT DETECTED - POTENTIAL FRAUD
    
    A dispute game was created with an output root that DOES NOT MATCH 
    locally computed state. This requires immediate challenger action.
    
    **Dispute Game:**
    - Dispute Proxy: ${dispute_game_created.args[0]}
    - Game Type: ${dispute_game_created.args[1]}
    - L1 Block: ${dispute_game_created.block.number}
    
    **Output Root Mismatch:**
    - Claimed: ${dispute_game_created.args[2]}
    - Computed: ${l2_computed_root.result}
    
    **L2 State Used:**
    - Block: ${l2_computed_root.block_number}
    - State Root: ${l2_computed_root.state_root}
    - MessagePasser Storage: ${l2_computed_root.message_passer_storage_root}
    - Block Hash: ${l2_computed_root.block_hash}
    
    **ACTION: Challenger must submit counter-claim within 7 days**
  
  dedup_key: "${dispute_game_created.args[0]}"
  cooldown: "0s"
```

---

### 6.3 Unauthorized Proxy Upgrade Detection (CRITICAL)

**Why Critical:** Proxy upgrades change contract logic. An unauthorized upgrade can 
introduce backdoors, drain funds, or disable security mechanisms.

```yaml
version: 1

name: unauthorized_proxy_upgrade
description: |
  CRITICAL SECURITY MONITOR: Detects implementation upgrades on critical 
  Optimism infrastructure contracts.
  
  ANY upgrade to these contracts should trigger immediate review:
  - OptimismPortal (bridge entry/exit)
  - L1CrossDomainMessenger (message passing)
  - SystemConfig (chain parameters)
  - DisputeGameFactory (fault proofs)
  
  Even "authorized" upgrades need real-time visibility.
priority: P1
tags:
  - security-critical
  - upgrades
  - proxy
  - unauthorized-change

rule_kind: realtime
type: single_chain
event: transaction

chain:
  kind: evm
  networks:
    - 1         # L1 contracts
    - 10        # L2 contracts
    - 8453      # Base
    - 7777777   # Zora

transaction:
  source: block
  status: [mined]
  filters:
    # === L1 CRITICAL CONTRACTS ===
    
    - id: optimism_portal_upgraded
      network: 1
      status: success
      eventEmitted:
        contract:
          address: "0xbEb5Fc579115071764c7423A4f12eDde41f106Ed"
        name: Upgraded
        args:
          - index: 0    # newImplementation
            capture: true

    - id: l1_messenger_upgraded
      network: 1
      status: success
      eventEmitted:
        contract:
          address: "0xdE1FCfB0851916CA5101820A69b13a4E276bd81F"
        name: Upgraded
        args:
          - index: 0
            capture: true

    - id: system_config_upgraded
      network: 1
      status: success
      eventEmitted:
        contract:
          address: "0x229047fed2591dbec1eF1118d64F7aF3dB9EB290"
        name: Upgraded
        args:
          - index: 0
            capture: true

    - id: dispute_game_factory_upgraded
      network: 1
      status: success
      eventEmitted:
        contract:
          address: "0xe5965Ab5962eDc7477C8520243A95517CD252fA9"
        name: Upgraded
        args:
          - index: 0
            capture: true

    - id: l1_standard_bridge_upgraded
      network: 1
      status: success
      eventEmitted:
        contract:
          address: "0x99C9fc46f92E8a1c0deC1b1747d010903E884bE1"
        name: Upgraded
        args:
          - index: 0
            capture: true

    # === L2 CRITICAL CONTRACTS (OP Mainnet) ===
    
    - id: l2_messenger_upgraded
      network: 10
      status: success
      eventEmitted:
        contract:
          address: "0x4200000000000000000000000000000000000007"
        name: Upgraded
        args:
          - index: 0
            capture: true

    - id: l2_standard_bridge_upgraded
      network: 10
      status: success
      eventEmitted:
        contract:
          address: "0x4200000000000000000000000000000000000010"
        name: Upgraded
        args:
          - index: 0
            capture: true

    - id: l2_to_l1_message_passer_upgraded
      network: 10
      status: success
      eventEmitted:
        contract:
          address: "0x4200000000000000000000000000000000000016"
        name: Upgraded
        args:
          - index: 0
            capture: true

alert:
  channels:
    - type: pagerduty
      config:
        severity: critical
    - type: slack
      config:
        channel: "#security-critical"
        mention: "@security-oncall @engineering-oncall"
  
  template: |
    CRITICAL CONTRACT UPGRADE DETECTED
    
    A critical infrastructure contract has been upgraded.
    VERIFY THIS WAS AUTHORIZED.
    
    **Contract:** ${event.contract}
    **Network:** ${event.chain_name} (${event.network})
    **New Implementation:** ${event.args[0]}
    
    **Transaction Details:**
    - Hash: ${event.tx.hash}
    - Block: ${event.block.number}
    - Executed By: ${event.tx.from}
    - Timestamp: ${event.block.timestamp}
    
    **Verification Checklist:**
    - [ ] Check governance proposal exists
    - [ ] Verify Security Council signatures
    - [ ] Compare implementation bytecode
    - [ ] Review audit status
    
    [View on Etherscan](${event.explorer_url})
  
  dedup_key: "${event.tx.hash}"
  cooldown: "0s"
```

---

### 6.4 Emergency Bridge Pause Detection (CRITICAL)

**Why Critical:** A bridge pause indicates an ACTIVE security incident. This needs 
immediate escalation and coordinated response.

```yaml
version: 1

name: bridge_emergency_pause
description: |
  CRITICAL: Detects pause events on bridge contracts.
  
  A pause means:
  1. Security incident detected (externally or internally)
  2. Funds at risk
  3. Immediate coordinated response needed
  
  This is an INCIDENT TRIGGER, not just an alert.
priority: P1
tags:
  - security-critical
  - incident
  - emergency
  - pause

rule_kind: realtime
type: single_chain
event: transaction

chain:
  kind: evm
  networks:
    - 1
    - 10

transaction:
  source: block
  status: [mined]
  filters:
    # OptimismPortal pause (most critical)
    - id: portal_paused
      network: 1
      status: success
      eventEmitted:
        contract:
          address: "0xbEb5Fc579115071764c7423A4f12eDde41f106Ed"
        name: Paused
        args:
          - index: 0    # account that paused
            capture: true

    # L1 Bridge pause
    - id: l1_bridge_paused
      network: 1
      status: success
      eventEmitted:
        contract:
          address: "0x99C9fc46f92E8a1c0deC1b1747d010903E884bE1"
        name: Paused
        args:
          - index: 0
            capture: true

    # L1 Messenger pause
    - id: l1_messenger_paused
      network: 1
      status: success
      eventEmitted:
        contract:
          address: "0xdE1FCfB0851916CA5101820A69b13a4E276bd81F"
        name: Paused
        args:
          - index: 0
            capture: true

    # L2 Bridge pause
    - id: l2_bridge_paused
      network: 10
      status: success
      eventEmitted:
        contract:
          address: "0x4200000000000000000000000000000000000010"
        name: Paused
        args:
          - index: 0
            capture: true

    # L2 Messenger pause
    - id: l2_messenger_paused
      network: 10
      status: success
      eventEmitted:
        contract:
          address: "0x4200000000000000000000000000000000000007"
        name: Paused
        args:
          - index: 0
            capture: true

alert:
  channels:
    - type: pagerduty
      config:
        severity: critical
        routing_key: "${PAGERDUTY_INCIDENT_KEY}"
    - type: slack
      config:
        channel: "#incidents"
        mention: "@channel"
    - type: telegram
      config:
        chat_id: "${TELEGRAM_WAR_ROOM}"
    - type: webhook
      config:
        url: "${INCIDENT_WEBHOOK_URL}"
  
  template: |
    BRIDGE PAUSED - SECURITY INCIDENT ACTIVE
    
    A critical bridge contract has been PAUSED.
    This indicates an ACTIVE SECURITY INCIDENT.
    
    **INCIDENT RESPONSE INITIATED**
    
    **Paused Contract:** ${event.contract}
    **Network:** ${event.chain_name}
    **Paused By:** ${event.args[0]}
    
    **Transaction:**
    - Hash: ${event.tx.hash}
    - Block: ${event.block.number}
    - Timestamp: ${event.block.timestamp}
    
    **Immediate Actions:**
    1. Join war room: ${WAR_ROOM_LINK}
    2. Check incident channel for updates
    3. Do NOT unpause without security clearance
    
    **Runbook:** https://runbooks.walnut.dev/bridge-pause-response
  
  dedup_key: "${event.contract}-paused"
  cooldown: "0s"
```

---

### 6.5 Sanctioned/Blacklisted Address Bridge Interaction (HIGH - Phase 1 Basic / Phase 3 Full)

**Why Important:** Compliance requirement. Interaction with OFAC-sanctioned addresses 
can result in legal action. Also detects known attacker addresses.

**Phase 1 MVP Approach:** 
- Manual address list (CSV/JSON import) for known sanctioned addresses
- Basic threat intel provider integration (single provider, simple API)
- Internal address labeling system (basic version)

**Phase 3 Enhancement:**
- Full threat intelligence integration (multiple providers)
- Risk scoring and dynamic labeling
- Real-time threat intel updates

```yaml
version: 1

name: sanctioned_address_detection
description: |
  CRITICAL COMPLIANCE & SECURITY: Detects bridge interactions from/to 
  addresses flagged by threat intelligence:
  
  - OFAC sanctioned addresses
  - Known hacker/exploit addresses
  - DPRK/Lazarus Group addresses
  - Tornado Cash interactions
  
  Immediate compliance review required.
priority: P1
tags:
  - security-critical
  - compliance
  - sanctions
  - threat-intel

rule_kind: realtime
type: single_chain
event: transaction

chain:
  kind: evm
  networks:
    - 1
    - 10
    - 8453

transaction:
  source: block
  status: [mined]
  filters:
    # Any transaction TO bridge contracts
    - id: bridge_deposit
      to:
        - "0xbEb5Fc579115071764c7423A4f12eDde41f106Ed"  # OptimismPortal
        - "0x99C9fc46f92E8a1c0deC1b1747d010903E884bE1"  # L1StandardBridge
        - "0x4200000000000000000000000000000000000010"  # L2StandardBridge
        - "0x4200000000000000000000000000000000000016"  # L2ToL1MessagePasser

    # Withdrawal events (captures recipient)
    - id: withdrawal_initiated
      eventEmitted:
        contract:
          address: "0x4200000000000000000000000000000000000016"
        name: MessagePassed
        # Event: MessagePassed(nonce, sender, target, value, gasLimit, data, withdrawalHash)
        # Index = parameter position (0-6)
        args:
          - index: 1    # sender (indexed)
            capture: true
          - index: 2    # target (indexed)
            capture: true
          - index: 3    # value (non-indexed)
            capture: true

threat_intel:
  enrich:
    - from
    - to
    - eventEmitted.args.sender
    - eventEmitted.args.target
  
  # Alert triggers
  conditions:
    labels:
      any_of:
        - "ofac_sanctioned"
        - "hacker"
        - "exploit_address"
        - "tornado_cash"
        - "dprk"
        - "lazarus_group"
        - "known_attacker"
    risk_score:
      gte: 0.85

alert:
  channels:
    - type: pagerduty
      config:
        severity: critical
    - type: slack
      config:
        channel: "#compliance-critical"
        mention: "@compliance-team @legal"
    - type: webhook
      config:
        url: "${COMPLIANCE_WEBHOOK}"
  
  template: |
    SANCTIONED/FLAGGED ADDRESS DETECTED
    
    A flagged address has interacted with bridge infrastructure.
    
    **Network:** ${event.chain_name}
    **Transaction:** ${event.tx.hash}
    
    **Addresses Involved:**
    - From: ${event.tx.from}
    - To: ${event.tx.to}
    
    **Threat Intelligence Match:**
    - Labels: ${threat_intel.matched_labels}
    - Risk Score: ${threat_intel.risk_score}
    - Source: ${threat_intel.provider}
    - First Seen: ${threat_intel.first_seen}
    
    **Value:** ${event.value} wei
    
    **COMPLIANCE ACTION REQUIRED**
    
    Runbook: https://runbooks.walnut.dev/sanctioned-address
  
  dedup_key: "${event.tx.hash}"
  cooldown: "0s"
```

---

### 6.6 Security Council Multisig Execution (HIGH)

**Why Important:** Security Council controls protocol upgrades. Any execution 
needs visibility and verification that it was properly authorized.

Phase 1 vs Phase 2:
- Phase 1: On-chain execution monitoring (ExecutionSuccess/ExecutionFailure events)
- Phase 2: Pre-signed nonce validation via external APIs (1Password, Vault)

OP Monitorism's multisig monitor includes 1Password CLI integration to verify pre-signed pause transactions exist. This external API integration is Phase 2. Phase 1 provides visibility into what IS executed; Phase 2 validates what SHOULD exist.

```yaml
version: 1

name: security_council_execution
description: |
  Monitors Security Council multisig executions across all Superchain networks.
  
  Security Council can:
  - Execute emergency upgrades
  - Pause bridge contracts
  - Change critical parameters
  
  All executions need immediate visibility.
priority: P1
tags:
  - security-critical
  - governance
  - security-council
  - multisig

rule_kind: realtime
type: single_chain
event: transaction

chain:
  kind: evm
  networks:
    - 1         # L1 Security Council
    - 10        # OP Mainnet
    - 8453      # Base

transaction:
  source: block
  status: [mined]
  filters:
    # L1 Security Council - Execution Success
    - id: l1_council_success
      network: 1
      status: success
      eventEmitted:
        contract:
          address: "0x9BA6e03D8B90dE867373Db8cF1A58d2F7F006b3A"
        name: ExecutionSuccess
        args:
          - index: 0    # txHash
            capture: true
          - index: 1    # payment
            capture: true

    # L1 Security Council - Execution Failure
    - id: l1_council_failure
      network: 1
      status: success
      eventEmitted:
        contract:
          address: "0x9BA6e03D8B90dE867373Db8cF1A58d2F7F006b3A"
        name: ExecutionFailure
        args:
          - index: 0
            capture: true
          - index: 1
            capture: true

    # OP Mainnet Security Council
    - id: op_council_success
      network: 10
      status: success
      eventEmitted:
        contract:
          address: "0xc2819DC788505Aac350142A7A707BF9D03E3Bd03"
        name: ExecutionSuccess

    - id: op_council_failure
      network: 10
      status: success
      eventEmitted:
        contract:
          address: "0xc2819DC788505Aac350142A7A707BF9D03E3Bd03"
        name: ExecutionFailure

    # Base Security Council
    - id: base_council_success
      network: 8453
      status: success
      eventEmitted:
        contract:
          address: "0x0a7361e734cf3f0394B0FC4a45C74E7a4eC70940"
        name: ExecutionSuccess

    - id: base_council_failure
      network: 8453
      status: success
      eventEmitted:
        contract:
          address: "0x0a7361e734cf3f0394B0FC4a45C74E7a4eC70940"
        name: ExecutionFailure

alert:
  channels:
    - type: slack
      config:
        channel: "#security-council-ops"
        mention: "@security-team"
    - type: pagerduty
      config:
        severity: high
  
  template: |
    Security Council Execution
    
    Status: ${event.filter_id contains "failure" ? "FAILED" : "SUCCESS"}
    **Network:** ${event.chain_name} (${event.network})
    **Council Contract:** ${event.contract}
    
    **Execution Details:**
    - TX Hash: ${event.args[0]}
    - Payment: ${event.args[1]} wei
    
    **Transaction:** ${event.tx.hash}
    **Block:** ${event.block.number}
    
    **Verify this execution was authorized via governance.**
  
  dedup_key: "${event.tx.hash}"
  cooldown: "0s"
```

---

### 6.7 SystemConfig Critical Parameter Changes (HIGH)

**Why Important:** SystemConfig controls fundamental chain parameters. Unauthorized 
changes can disrupt operations or enable attacks.

```yaml
version: 1

name: systemconfig_critical_change
description: |
  Monitors changes to critical SystemConfig parameters:
  - Gas limit (can affect block production)
  - Batcher address (controls who can submit batches)
  - Unsafe block signer (controls sequencer)
  - Fee parameters (economic attacks)
priority: P1
tags:
  - security-high
  - configuration
  - parameters

rule_kind: realtime
type: single_chain
event: transaction

chain:
  kind: evm
  networks:
    - 1
    - 10

transaction:
  source: block
  status: [mined]
  filters:
    - id: gas_limit_changed
      status: success
      eventEmitted:
        contract:
          address: "0x229047fed2591dbec1eF1118d64F7aF3dB9EB290"
        name: GasLimitUpdated
        args:
          - index: 0
            capture: true

    - id: batcher_changed
      status: success
      eventEmitted:
        contract:
          address: "0x229047fed2591dbec1eF1118d64F7aF3dB9EB290"
        name: BatcherUpdated
        args:
          - index: 0
            capture: true

    - id: unsafe_signer_changed
      status: success
      eventEmitted:
        contract:
          address: "0x229047fed2591dbec1eF1118d64F7aF3dB9EB290"
        name: UnsafeBlockSignerUpdated
        args:
          - index: 0
            capture: true

    - id: fee_config_changed
      status: success
      eventEmitted:
        contract:
          address: "0x229047fed2591dbec1eF1118d64F7aF3dB9EB290"
        name: ConfigUpdate
        args:
          - index: 0
            capture: true
          - index: 1
            capture: true

alert:
  channels:
    - type: slack
      config:
        channel: "#protocol-config"
        mention: "@protocol-team"
    - type: pagerduty
      config:
        severity: high
  
  template: |
    SystemConfig Parameter Changed
    
    **Parameter:** ${event.name}
    **Network:** ${event.chain_name}
    **New Value:** ${event.args[0]}
    
    **Transaction:** ${event.tx.hash}
    **Block:** ${event.block.number}
    **Changed By:** ${event.tx.from}
    
    **Verify this change was authorized.**
  
  dedup_key: "${event.tx.hash}"
  cooldown: "0s"
```

---

### 6.8 Dispute Game Challenger Loses (HIGH)

**Why Important:** If the honest challenger loses, it means either a bug in the 
challenger or a successful attack on the fault proof system.

```yaml
version: 1

name: challenger_loses_dispute
description: |
  Monitors for dispute games where the challenger (defender of correct state) loses.
  
  This is extremely rare in normal operation and indicates:
  - Bug in challenger implementation
  - Challenger ran out of funds
  - Successful attack on fault proof system
priority: P1
tags:
  - security-high
  - fault-proof
  - challenger
  - dispute-game

rule_kind: realtime
type: single_chain
event: transaction

chain:
  kind: evm
  networks:
    - 1

transaction:
  source: block
  status: [mined]
  filters:
    - id: game_resolved_challenger_loses
      network: 1
      status: success
      eventEmitted:
        name: Resolved
        args:
          # GameStatus enum: 0=IN_PROGRESS, 1=CHALLENGER_WINS, 2=DEFENDER_WINS
          # When DEFENDER_WINS (2), it means the honest challenger LOST their challenge
          - index: 0    # status enum (uint8 indexed)
            value: "2"   # DEFENDER_WINS = challenger lost

alert:
  channels:
    - type: pagerduty
      config:
        severity: critical
    - type: slack
      config:
        channel: "#fault-proof-alerts"
        mention: "@challenger-team @security-oncall"
  
  template: |
    CHALLENGER LOST DISPUTE GAME
    
    A dispute game resolved with the CHALLENGER LOSING.
    This is an anomaly and requires immediate investigation.
    
    **Game Contract:** ${event.contract}
    **Resolution:** CHALLENGER_LOSES
    
    **Transaction:** ${event.tx.hash}
    **Block:** ${event.block.number}
    
    **Investigate:**
    1. Was challenger properly funded?
    2. Did challenger submit all required moves?
    3. Was there a bug in challenger logic?
    4. Is this a coordinated attack?
  
  dedup_key: "${event.contract}-resolved"
  cooldown: "0s"
```

---

### TIER 2: SECURITY MONITORING (MVP Phase 1 - Lower Priority)

These monitors provide security visibility but are less critical than Tier 1.

---

### 6.9 Large Withdrawal Detection

**Why Important:** Large withdrawals may indicate whale activity, treasury movements, 
or potential exploit draining funds.

```yaml
version: 1

name: large_withdrawal_alert
description: |
  Alerts on withdrawals exceeding threshold amounts.
  Large withdrawals may indicate:
  - Legitimate whale activity
  - Protocol treasury movements
  - Potential exploit in progress
priority: P2
tags:
  - security-medium
  - whale-alert
  - withdrawals

rule_kind: realtime
type: single_chain
event: transaction

chain:
  kind: evm
  networks:
    - 10
    - 8453
    - 7777777

transaction:
  source: block
  status: [mined]
  filters:
    - id: large_withdrawal
      status: success
      eventEmitted:
        contract:
          address: "0x4200000000000000000000000000000000000016"
        name: MessagePassed
        # Event: MessagePassed(nonce, sender, target, value, gasLimit, data, withdrawalHash)
        # Index = parameter position (0-6)
        args:
          - index: 3    # value (non-indexed, position 3)
            op: gte
            value: "100000000000000000000"   # >= 100 ETH
          - index: 1    # sender (indexed, position 1)
            capture: true
          - index: 2    # target (indexed, position 2)
            capture: true

threat_intel:
  enrich:
    - eventEmitted.args.sender
    - eventEmitted.args.target
  conditions:
    labels:
      any_of:
        - "hacker"
        - "exploit"
        - "sanctioned"

alert:
  channels:
    - type: slack
      config:
        channel: "#whale-alerts"
  
  template: |
    Large Withdrawal Detected
    
    **Network:** ${event.chain_name}
    **Amount:** ${event.args[3] / 1e18} ETH
    **Sender:** ${event.args[1]}
    **Target:** ${event.args[2]}
    
    ${threat_intel.enriched ? "THREAT INTEL MATCH: " + threat_intel.labels : "No threat intel flags"}
    
    **Transaction:** ${event.tx.hash}
  
  dedup_key: "${event.tx.hash}"
  cooldown: "0s"
```

---

### 6.10 Withdrawal Proven but Not Finalized (Cross-Chain)

**Why Important:** Tracks withdrawals through the 7-day challenge period. 
Useful for detecting stuck withdrawals or operational issues.

**How This YAML Works:**
```
1. SOURCE A (L2): Listen for MessagePassed event (withdrawal initiated)
2. SOURCE B (L1): Listen for WithdrawalProven event (withdrawal proven)
3. CORRELATION: Match by withdrawalHash
4. MODE: negative = Alert if A happens but B does NOT happen within window
5. WINDOW: 24 hours
6. ALERT: If withdrawal not proven after 24h â†’ informational alert
```

```yaml
version: 1

name: withdrawal_not_proven
description: |
  Monitors for L2 withdrawals that have been initiated but not proven 
  on L1 within expected timeframe.
  
  Note: This is informational - users may simply not have proven yet.
  Becomes security concern if systematic.
priority: P2
tags:
  - security-medium
  - cross-chain
  - withdrawals
  - operational

rule_kind: realtime
type: cross_chain
event: transaction

cross_chain:
  sources:
    - id: l2_withdrawal
      chain:
        kind: evm
        networks:
          - 10
      transaction:
        source: block
        status: [mined]
        filters:
          - id: withdrawal_initiated
            status: success
            eventEmitted:
              contract:
                address: "0x4200000000000000000000000000000000000016"
              name: MessagePassed
              # Event signature: MessagePassed(uint256 indexed nonce, address indexed sender, 
              #   address indexed target, uint256 value, uint256 gasLimit, bytes data, bytes32 withdrawalHash)
              # Index is PARAMETER POSITION (0-6), not topic position
              args:
                - index: 6    # withdrawalHash (non-indexed, position 6)
                  capture: true
                - index: 1    # sender (indexed, position 1)
                  capture: true
                - index: 3    # value (non-indexed, position 3)
                  capture: true

    - id: l1_proof
      chain:
        kind: evm
        networks:
          - 1
      transaction:
        source: block
        status: [mined]
        filters:
          - id: withdrawal_proven
            status: success
            eventEmitted:
              contract:
                address: "0xbEb5Fc579115071764c7423A4f12eDde41f106Ed"
              name: WithdrawalProven
              args:
                - index: 0    # withdrawalHash
                  capture: true

  correlation:
    mode: negative
    base: l2_withdrawal
    expect:
      target: l1_proof
    join:
      - left: l2_withdrawal.args.withdrawalHash
        op: eq
        right: l1_proof.args.withdrawalHash
    window:
      max_delay: "24h"

alert:
  channels:
    - type: slack
      config:
        channel: "#bridge-monitoring"
  
  template: |
    Withdrawal Not Proven (24h)
    
    A withdrawal has not been proven within 24 hours.
    
    **Withdrawal Hash:** ${l2_withdrawal.args.withdrawalHash}
    **Sender:** ${l2_withdrawal.args.sender}
    **Value:** ${l2_withdrawal.args.value} wei
    **L2 TX:** ${l2_withdrawal.tx.hash}
    
    This may be normal user behavior.
  
  dedup_key: "${l2_withdrawal.args.withdrawalHash}"
  cooldown: "48h"
```

---

### TIER 3: OPERATIONAL MONITORING (Phase 2+)

The following monitors are **operational** rather than security-focused. 
They detect liveness issues, patterns, and anomalies but do not indicate active attacks.

**Moved to Phase 2:**
- Sequencer batch submission absence (liveness)
- Unsafe/safe head lag (operational health)
- L1â†’L2 deposit relay delays (operational)
- Cross-chain state drift (consistency)
- Flash loan burst detection (DeFi operational)
- Bond/credit discrepancy (accounting)
- Security Council signature timeout (governance operational)

See **Section 12: Phase 2 Operational Monitors** for these specifications.

---

### 6.11 Multi-Network Superchain Monitoring (Example)

**Use Case:** Monitor proxy upgrades across ALL Superchain networks with unified alerting.

```yaml
version: 1

name: superchain_unified_proxy_upgrade
description: |
  Monitors proxy upgrades across entire Superchain ecosystem.
  Single rule covers all OP Stack chains with unified alerting.
priority: P1
tags:
  - superchain
  - multi-network
  - unified-monitoring

rule_kind: realtime
type: single_chain    # Same rule, multiple networks
event: transaction

chain:
  kind: evm
  networks:
    - 1         # Ethereum L1
    - 10        # OP Mainnet
    - 8453      # Base
    - 7777777   # Zora
    - 34443     # Mode
    - 252       # Frax
    - 291       # Orderly
    - 424       # PGN

transaction:
  source: block
  status: [mined]
  filters:
    # Network-specific contract addresses using variable mapping
    - id: bridge_upgrade
      status: success
      eventEmitted:
        contract:
          # Address resolved per-network from config
          address: "${config.networks[event.network].bridge_contract}"
        name: Upgraded
        args:
          - index: 0
            capture: true

# Network address configuration (loaded from external config)
config:
  networks:
    1:
      bridge_contract: "0x99C9fc46f92E8a1c0deC1b1747d010903E884bE1"
      name: "Ethereum L1"
    10:
      bridge_contract: "0x4200000000000000000000000000000000000010"
      name: "OP Mainnet"
    8453:
      bridge_contract: "0x4200000000000000000000000000000000000010"
      name: "Base"
    # ... additional networks

alert:
  template: |
    Superchain Proxy Upgrade: ${config.networks[event.network].name}
    
    **Contract:** ${event.contract}
    **New Implementation:** ${event.args[0]}
    **Network:** ${event.network}
    
    Verify upgrade was authorized across Superchain governance.
```

---

### 6.12 Stateful Monitoring: Multi-Game Tracking (Phase 2 PREVIEW)

This is a Phase 2 preview demonstrating future capabilities. `rule_kind: stateful` and `historical_events()` are not included in Phase 1. This example shows what will be possible in Phase 2 (Months 4-6).

Some monitors require stateful tracking across multiple entities (e.g., active dispute games). This is different from simple event-based monitoring.

**Use Case:** Track ALL active dispute games and alert if any becomes unresolvable.

**Phase 2 Requirements:**
- `rule_kind: stateful` â€” Maintains entity state in Redis
- `historical_events()` â€” Query past events to reconstruct state on startup
- State management API â€” Track lifecycle (created â†’ updated â†’ resolved)

```yaml
version: 1

name: dispute_game_lifecycle_tracker
description: |
  STATEFUL MONITOR: Maintains state for all active dispute games.
  Tracks: creation â†’ moves â†’ resolution
  Alerts: unresolved games past deadline, challenger losses
priority: P1
tags:
  - fault-proof
  - stateful
  - lifecycle

rule_kind: stateful    # NEW: Stateful monitoring (Phase 2)
type: single_chain
event: transaction

# State management
state:
  type: entity_tracker
  entity: dispute_game
  key: "${event.contract}"    # Each game contract = one entity
  lifecycle:
    created: DisputeGameCreated
    updated: [Move, Attack, Defend]
    resolved: Resolved
  ttl: "14d"                  # Remove resolved games after 14 days

chain:
  kind: evm
  networks: [1]

transaction:
  source: block
  status: [mined]
  filters:
    - id: game_created
      eventEmitted:
        contract:
          address: "0xe5965Ab5962eDc7477C8520243A95517CD252fA9"
        name: DisputeGameCreated
        args:
          - index: 0    # disputeProxy
            capture: true
    
    - id: game_resolved
      eventEmitted:
        name: Resolved
        args:
          - index: 0    # status
            capture: true

# Condition evaluated against state
condition:
  # Alert if game is not resolved 7 days after creation
  expr: |
    state.entities
      | filter({ .status != "resolved" && now() - .created_at > duration("7d") })
      | len() > 0

alert:
  template: |
    Unresolved Dispute Games Detected
    
    ${state.entities | filter({.status != "resolved"}) | len()} games pending resolution.
    
    **Oldest unresolved:**
    - Game: ${state.oldest_unresolved.address}
    - Created: ${state.oldest_unresolved.created_at}
    - Age: ${now() - state.oldest_unresolved.created_at}
```

Stateful monitoring requires Redis state storage (Phase 2 deliverable M2.2). Phase 1 focuses on event-driven monitoring; lifecycle tracking comes in Phase 2.

---

### 6.13 Adapting Monitors for Other Chains

The DSL is **chain-agnostic**. To deploy the same monitor on a different chain:

```yaml
# Example: Proxy Upgrade Detection for different chains

# Optimism (reference)
chain:
  kind: evm
  networks: [1, 10]  # Ethereum + OP Mainnet
filters:
  - eventEmitted:
      contract:
        address: "0xbEb5Fc579115071764c7423A4f12eDde41f106Ed"  # OptimismPortal

# Arbitrum (same pattern, different addresses)
chain:
  kind: evm
  networks: [1, 42161]  # Ethereum + Arbitrum One
filters:
  - eventEmitted:
      contract:
        address: "0x0B9857ae2D4A3DBe74ffE1d7DF045bb7F96E4840"  # Arbitrum Outbox

# zkSync Era (same pattern, different addresses)
chain:
  kind: evm
  networks: [1, 324]  # Ethereum + zkSync Era
filters:
  - eventEmitted:
      contract:
        address: "0x32400084C286CF3E17e7B677ea9583e60a000324"  # zkSync Diamond
```

**Chain Support Strategy:**

Walnut's DSL is chain-agnostic by design. Any EVM-compatible chain works out-of-the-box with address changes only. The phases below indicate tested & validated chains with full QA, not capability limitations.

| Phase | Tested & Validated | Supported (Untested) |
|-------|-------------------|---------------------|
| **Phase 1** | Ethereum, Optimism, Base | Any EVM L1/L2 (address change only) |
| **Phase 2** | + Arbitrum, zkSync, Polygon | Same |
| **Phase 3** | + Avalanche, BNB, Scroll, Linea | Same |
| **Phase 4** | Solana, Cosmos (new adapters) | EVM: full, Non-EVM: experimental |

**What "Tested & Validated" Means:**
- Contract addresses verified
- Event signatures confirmed against deployed bytecode
- End-to-end testing in production-like environment
- Reference monitors available in examples

**What "Supported (Untested)" Means:**
- Same DSL works (it's just EVM)
- User provides correct contract addresses
- No pre-built templates
- Community-contributed monitors welcome

---

## 7. COMPETITIVE ANALYSIS

### 7.1 Feature Comparison Matrix

| Feature | OP Monitorism | Hexagate | Forta | Walnut |
|---------|---------------|----------|-------|--------|
| **Architecture** | | | | |
| Declarative DSL | Limited | .gate DSL | No (SDK) | YAML DSL |
| No-code monitor creation | No | Yes | No | Native |
| | | | | |
| **DSL Expressiveness** | | | | |
| Event signature matching | topics[0] only | Full | Full | Full |
| Indexed parameter filtering | No | Yes | Yes | Native |
| Function call filtering | Custom code | Yes | Yes | Native |
| Value/gas conditions | Custom code | Yes | Yes | Native |
| | | | | |
| **Cross-Chain** | | | | |
| L1-L2 correlation | Custom Go | Native | Limited | Native |
| L2-L2 correlation | No | Yes | No | Native |
| Heterogeneous (EVM-Solana) | No | Limited | No | Roadmap |
| | | | | |
| **Pattern Detection** | | | | |
| Count threshold | No | Limited | Yes | Native |
| All-of correlation | No | Limited | Yes | Native |
| Absence detection | No | Limited | Yes | Native |
| | | | | |
| **Threat Intelligence** | | | | |
| Address labeling | No | Integrated | Yes | Pluggable |
| Risk scoring | No | Yes | Limited | Pluggable |
| | | | | |
| **State Validation** | | | | |
| eth_getProof support | Custom | Yes | No | Native |
| Output root computation | Custom | Yes | No | Native |
| | | | | |
| **Deployment** | | | | |
| Self-hosted | Yes | SaaS only | Complex | Full |
| Managed/SaaS | No | Yes | Yes | Optional |
| | | | | |
| **Ecosystem** | | | | |
| Optimism native | Yes | Yes | Limited | Primary |
| Multi-chain | No | Yes | Yes | Native |

Forta is a decentralized bot network that requires writing bots in TypeScript/Python using their SDK. It is fundamentally different from DSL-based solutions:
- Pros: Community bots, decentralized detection, alerting marketplace
- Cons: Requires coding, variable latency, complex deployment

Walnut targets users who want declarative configuration (YAML) without writing code. For teams who prefer coding, Forta is a viable alternative.

### 7.2 Why Walnut Wins

1. **Zero Learning Curve for Config**: YAML is the industry standard for SRE/DevOps/Security (Kubernetes, Prometheus, Falco, Sigma). Your team already knows it.
2. **Universal Platform**: Works with any EVM chain, not locked to one ecosystem
3. **Best of Both Worlds**: Self-hosted flexibility + SaaS-grade DSL power
4. **No Vendor Lock-in**: YAML + expr-lang (open standards) vs proprietary languages
5. **State Validation**: Native eth_getProof for any EVM chain
6. **Open Architecture**: Pluggable threat intel, delivery channels, chain adapters
7. **Cross-Chain Native**: L1â†”L2, L2â†”L2, heterogeneous chain correlation built-in

---

## 8. PHASED ROADMAP

### Phase 1: Foundation (Months 1-3)

**Objective:** Production-ready **universal EVM monitoring platform** with DSL v1 + cross-chain correlation

Design Partner: Optimism Foundation  
Validation Focus: L2 rollup security monitors (applicable to any optimistic rollup)

Phase 1 capabilities are chain-agnostic â€” the same DSL and architecture supports:
- Any EVM L1 (Ethereum, BNB, Avalanche, Polygon)
- Any EVM L2 (Optimism, Arbitrum, Base, zkSync, Scroll)
- Any cross-chain correlation (L1â†”L2, L2â†”L2, bridge protocols)

#### Deliverables

| Milestone | Description | Week |
|-----------|-------------|------|
| **M1.1** | Core DSL parser/validator | W2 |
| **M1.2** | Network Subscriber Service (Infura/Alchemy WS) | W4 |
| **M1.3** | Event Router with Bloom filter pre-check | W6 |
| **M1.4** | Alert Service (realtime rules) | W8 |
| **M1.5** | Basic cross-chain correlation engine (L1â†”L2) | W9 |
| **M1.6** | eth_getProof integration (basic, for withdrawal validation) | W10 |
| **M1.7** | Output root computation (basic, for dispute game validation) | W11 |
| **M1.8** | Delivery Channel Service (Slack, Webhook, PagerDuty) | W11 |
| **M1.9** | Production deployment (Kubernetes) | W12 |

#### DSL Support (Phase 1)

```yaml
# Supported in Phase 1
rule_kind: realtime
type: single_chain | cross_chain  # Basic cross-chain for critical security monitors
event: transaction

# Filters supported:
- network
- status (success/fail)
- from, to (single address)
- value (eq, gt, gte, lt, lte)
- eventEmitted (name, contract address, indexed args)
- logEmitted (topics, data)

# Cross-chain support (basic, for critical monitors only):
cross_chain:
  sources: [...]
  correlation:
    mode: positive | negative
    join: [...]
    window:
      max_delay: duration

# State validation (basic, for withdrawal/output root validation):
validation:
  type: state_proof | output_root_computation
  method: eth_getProof
```

#### Target Monitors (Phase 1)

**Universal Security Monitors (Any Chain):**
1. **Fake Withdrawal Detection** — Cross-chain state validation (L2→L1)
2. **Invalid State Root Detection** — Output root / state commitment validation
3. **Multisig Execution Monitoring** — Any Gnosis Safe / multisig
4. **Proxy Upgrade Detection** — Any UUPS/Transparent proxy
5. **Bridge Pause Events** — Any Pausable contract

**Reference Implementation: Optimism Superchain**
- Monitors 1-5 implemented first for Optimism as design partner
- Same monitors reusable for Arbitrum, Base, zkSync with address changes only

#### Success Criteria

- [ ] <500ms alert latency (event to Slack)
- [ ] 99.9% uptime over 30 days
- [ ] 5+ production monitors deployed for design partner
- [ ] Zero missed critical events
- [ ] eth_getProof validation operational
- [ ] DSL proven reusable across at least 2 different chains

---

### Phase 2: Cross-Chain & Patterns (Months 4-6)

**Objective:** Full cross-chain correlation (L2â†”L2, heterogeneous chains), windowed pattern detection, 
and advanced fault proof monitoring. Expands on Phase 1's basic cross-chain capabilities.

#### Deliverables

| Milestone | Description | Week |
|-----------|-------------|------|
| **M2.1** | Advanced cross-chain correlation engine (L2↔L2, heterogeneous) | W14 |
| **M2.2** | Windowed pattern evaluation (Redis state) | W16 |
| **M2.3** | Negative correlation (absence detection) - advanced | W18 |
| **M2.4** | Enhanced eth_getProof integration (batch queries, caching) | W20 |
| **M2.5** | Advanced output root computation (optimizations) | W22 |
| **M2.6** | Complete fault proof monitoring suite | W24 |

#### DSL Support (Phase 2)

```yaml
# New in Phase 2
rule_kind: windowed  # Full windowed support
type: cross_chain | multi_chain  # Multi-chain support

# Pattern logic:
pattern:
  logic:
    kind: count | all_of | absence

# Advanced cross-chain correlation:
cross_chain:
  sources: [...]
  correlation:
    mode: positive | negative
    join: [...]
    window:
      max_delay: duration
      min_delay: duration  # New: minimum delay constraints
```

#### Target Monitors (Phase 2)

**Cross-Chain Operational:**
1. Withdrawal Not Proven (L2→L1) - operational monitoring
2. Deposit Not Relayed (L1→L2) - operational monitoring
3. Challenger Loses Alert - fault proof monitoring
4. Sequencer Batch Absence - liveness monitoring

**Pattern-Based:**
5. Flash Loan Burst Detection
6. Security Council Signature Timeout
7. Bond/Credit Discrepancy Detection

#### Success Criteria

- [ ] Cross-chain correlation working for OPâ†”Ethereum
- [ ] eth_getProof validation operational
- [ ] 10+ production monitors deployed
- [ ] False positive rate <1%

---

### Phase 3: Threat Intel & Multi-Chain (Months 7-9)

**Objective:** Full threat intelligence integration (multiple providers, risk scoring) and multi-chain expansion. 
Enhances Phase 1's basic threat intel capabilities (manual lists, single provider) with enterprise-grade features.

#### Deliverables

| Milestone | Description | Week |
|-----------|-------------|------|
| **M3.1** | Threat Intel Service architecture | W26 |
| **M3.2** | Chainalysis/TRM integration | W28 |
| **M3.3** | Internal address labeling system | W30 |
| **M3.4** | Base, Zora, Mode support | W32 |
| **M3.5** | Multi-chain state drift detection | W34 |
| **M3.6** | Rule management API | W36 |

#### DSL Support (Phase 3)

```yaml
# New in Phase 3
threat_intel:
  enrich: [from, to, contract]
  conditions:
    labels:
      any_of: [...]
    risk_score:
      gte: 0.7

# Multi-chain
type: multi_chain
chain:
  kind: evm
  networks: [10, 8453, 7777777, 34443]  # OP, Base, Zora, Mode
```

#### Target Monitors (Phase 3)

1. Sanctioned Address Interaction (full threat intel integration)
2. High-Risk Address Bridge Usage
3. Cross-Chain State Drift
4. Protocol-Specific Templates (based on customer demand)
5. Advanced Pattern Detection (multi-event correlation)

#### Success Criteria

- [ ] Threat intel enrichment <100ms latency
- [ ] Support for 5+ Superchain networks
- [ ] Rule management API operational
- [ ] 25+ production monitors

---

### Phase 4: Enterprise & Scale (Months 10-12)

**Objective:** Enterprise features, UI, and scale optimizations

#### Deliverables

| Milestone | Description | Week |
|-----------|-------------|------|
| **M4.1** | Web UI for rule management | W38 |
| **M4.2** | Alert dashboard and analytics | W40 |
| **M4.3** | Horizontal scaling (1M+ events/sec) | W42 |
| **M4.4** | SOC 2 Type II compliance preparation | W44 |
| **M4.5** | Managed SaaS offering | W46 |
| **M4.6** | Solana chain support (experimental) | W48 |

#### DSL Support (Phase 4)

```yaml
# New in Phase 4
chain:
  kind: solana
  networks: [mainnet-beta]

# Solana-specific filters
program:
  address: "..."
  instruction:
    name: "..."
  logs:
    contains: "..."
```

#### Success Criteria

- [ ] Web UI deployed
- [ ] 1M events/sec sustained throughput
- [ ] SOC 2 readiness
- [ ] First paying SaaS customer
- [ ] Solana basic support operational

---

## 9. SUCCESS METRICS & KPIs

### 9.1 Technical KPIs
| Metric | Target | Measurement |
|--------|--------|-------------|
| **Alert Latency** | <500ms (P95) | Event timestamp → Alert delivery |
| **Uptime** | 99.9% | Monthly availability |
| **Throughput** | 100K events/sec (Phase 1) | Kafka consumer metrics |
| **False Positive Rate** | <1% | Manual review sample |
| **Missed Events** | 0 critical | Reconciliation with block explorer |

### 9.2 Business KPIs

| Metric | Phase 1 | Phase 2 | Phase 3 | Phase 4 |
|--------|---------|---------|---------|---------|
| **Production Monitors** | 5-7 | 15 | 30 | 50+ |
| **Paying Customers** | 1 (pilot) | 2-3 | 5+ | 10+ |
| **ARR** | $0 (pilot) | $100K+ | $400K+ | $1M+ |
| **Chains Supported** | 2 (L1+L2) | 5 | 10 | 20+ |
| **Cross-Chain Monitors** | 2 (critical) | 8+ | 15+ | 30+ |

### 9.3 Customer Success KPIs

| Metric | Target |
|--------|--------|
| **Time to First Monitor** | <1 hour |
| **Monitor Creation Time** | <15 minutes (with DSL) |
| **Support Ticket Resolution** | <4 hours (P1), <24 hours (P2) |
| **Customer NPS** | >50 |

---

## 10. RISK ANALYSIS & MITIGATIONS

### 10.1 Technical Risks

| Risk | Impact | Probability | Mitigation |
|------|--------|-------------|------------|
| **RPC Provider Outage** | High | Medium | Multi-provider failover (3 providers) |
| **Kafka Bottleneck** | High | Low | Horizontal partitioning, consumer groups |
| **State Reconstruction Failure** | Critical | Low | Archive node fallback, manual reconciliation |
| **False Positives Storm** | Medium | Medium | Rate limiting, dedup, cooldown periods |

### 10.2 Business Risks

| Risk | Impact | Probability | Mitigation |
|------|--------|-------------|------------|
| **Design Partner Doesn't Convert** | High | Low | Build pipeline of other potential customers during pilot |
| **Competitor Price War** | Medium | Medium | Differentiate on self-hosted + universal chain support |
| **Regulatory Changes** | Medium | Low | Flexible threat intel provider integration |
| **Single Chain Lock-in** | Medium | Low | Chain-agnostic DSL from day 1 |

### 10.3 Security Risks

| Risk | Impact | Probability | Mitigation |
|------|--------|-------------|------------|
| **Alert System Compromise** | Critical | Low | SOC 2, pen testing, audit |
| **Data Exfiltration** | High | Low | Encryption at rest/transit, access controls |
| **Denial of Service** | Medium | Medium | Rate limiting, WAF, scaling |

---

## 11. RESOURCE REQUIREMENTS

### 11.1 Team Structure

#### Phase 1 (Months 1-3)

| Role | Count | Focus |
|------|-------|-------|
| **Tech Lead / Architect** | 1 | System design, DSL specification |
| **Backend Engineer (Go)** | 2 | Core services implementation |
| **DevOps / SRE** | 1 | Infrastructure, Kubernetes, monitoring |
| **Product Manager** | 0.5 | Customer liaison, requirements |

#### Phase 2-4 (Months 4-12)

| Role | Count | Focus |
|------|-------|-------|
| **Tech Lead** | 1 | Architecture evolution |
| **Backend Engineer** | 3-4 | Cross-chain, patterns, scale |
| **Frontend Engineer** | 1 | Web UI (Phase 4) |
| **DevOps / SRE** | 1-2 | Operations, compliance |
| **Product Manager** | 1 | GTM, customer success |

### 11.2 Infrastructure Costs (Estimated Monthly)

| Component | Phase 1 | Phase 4 |
|-----------|---------|---------|
| **RPC Providers** (Infura/Alchemy) | $2,000 | $10,000 |
| **Kubernetes** (GKE/EKS) | $1,500 | $8,000 |
| **Kafka** (Managed) | $500 | $3,000 |
| **Redis** (Managed) | $300 | $1,500 |
| **ClickHouse** | $500 | $3,000 |
| **PostgreSQL** | $200 | $500 |
| **Monitoring** (Datadog/Grafana) | $500 | $2,000 |
| **Total** | **$5,500** | **$28,000** |

### 11.3 Development Tools & Services

- **Source Control**: GitHub Enterprise
- **CI/CD**: GitHub Actions
- **Container Registry**: GitHub Container Registry / ECR
- **Secret Management**: HashiCorp Vault / AWS Secrets Manager
- **Documentation**: Notion / GitBook
- **Project Management**: Linear

---
## 12. PHASE 2+ OPERATIONAL MONITORS (Summary)

Phase 2 adds **operational monitoring** capabilities using `rule_kind: windowed` patterns.
These are lower priority than security monitors but valuable for overall system health.

| Monitor | Type | Purpose |
|---------|------|---------|
| Security Council Signature Timeout | windowed/absence | Alert when SC tx pending >24h |
| Sequencer Batch Absence | windowed/absence | No batches for 30+ minutes |
| Unsafe/Safe Head Lag | periodic | Large gap between heads |
| L1â†’L2 Deposit Relay Delay | cross_chain/negative | Deposit not relayed in 20m |
| Cross-Chain State Drift | periodic/multi_chain | Config mismatch across chains |
| Flash Loan Burst | windowed/count | 10+ flash loans in 5 minutes |
| Bond/Credit Discrepancy | windowed/aggregation | Accounting anomalies |

**Implementation Timeline:** Months 4-6 (after core security monitors stable)

---

## APPENDIX A: DSL QUICK REFERENCE

### A.1 Top-Level Fields

```yaml
version: 1                           # DSL version
name: string                         # Unique identifier
description: string                  # Human description
priority: P1|P2|P3|P4|P5            # Alert severity
tags: [string]                       # Categorization

rule_kind: realtime|windowed         # Execution model
type: single_chain|multi_chain|cross_chain
event: transaction|block|mempool|periodic
```

### A.2 Chain Specification

```yaml
chain:
  kind: evm|solana|cosmos
  networks: [chain_ids]
```

### A.3 Transaction Filters (EVM)

```yaml
transaction:
  source: block|mempool
  status: [mined|confirmed10|pending]
  filters:
    - id: string
      network: chain_id
      status: success|fail
      from: address
      to: address|[addresses]
      value: {eq|gt|gte|lt|lte: "wei"}
      gas: {gt|lt: "amount"}
      function:
        name: string
        signature: string
        contract: {address: address}
      eventEmitted:
        contract: {address: address}
        name: string
        args:
          - index: n
            value: string
            op: eq|gt|gte|lt|lte|contains
            capture: bool
      logEmitted:
        contract: {address: address}
        topics: [topic0, topic1, null, ...]
        data: {startsWith: "0x..."}
```

### A.4 Pattern Logic

```yaml
pattern:
  window: "5m"|"1h"|"24h"
  logic:
    kind: count
    target_filter: filter_id|"any"
    threshold: {gte|gt|lt|lte: n}

    # OR
    kind: all_of
    events: [filter_id1, filter_id2]

    # OR
    kind: absence
    expect_missing: filter_id
```

### A.5 Cross-Chain Correlation

```yaml
cross_chain:
  sources:
    - id: string
      chain: {kind: evm, networks: [id]}
      transaction: {...}
  correlation:
    mode: positive|negative
    base: source_id       # For negative mode
    expect:
      target: source_id   # For negative mode
    join:
      - left: source.path
        op: eq|contains
        right: source.path
    window:
      max_delay: "300s"
```

### A.6 Threat Intelligence

```yaml
threat_intel:
  enrich: [from, to, contract, eventEmitted.contract]
  conditions:
    labels:
      any_of: [label1, label2]
    risk_score:
      gte: 0.0-1.0
    category:
      any_of: [mixer, scam, ...]
```

### A.7 Alert Configuration

```yaml
alert:
  channels:
    - type: slack|pagerduty|telegram|webhook|email
      config: {...}
  template: |
    Markdown template with ${variables}
  dedup_key: "${expression}"
  cooldown: "5m"
```

---

## APPENDIX B: GLOSSARY

| Term | Definition |
|------|------------|
| **Output Root** | Cryptographic commitment: keccak256(version ‖ stateRoot ‖ messagePasserStorageRoot ‖ blockHash) |
| **L2ToL1MessagePasser** | L2 precompile (0x4200...0016) storing withdrawal messages |
| **OptimismPortal** | L1 contract managing deposits/withdrawals |
| **Dispute Game** | Fault proof mechanism for challenging invalid L2 claims |
| **Security Council** | Multisig with emergency upgrade/pause authority |
| **Superchain** | Network of OP Stack chains sharing security |
| **eth_getProof** | RPC method returning Merkle proof for account/storage |

---

Document Version: 1.0  
Status: MVP Specification  
