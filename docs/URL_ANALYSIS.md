# URL-Based Contract Analysis

SolidityDefend supports analyzing smart contracts directly from blockchain explorer URLs, enabling seamless security analysis of live contracts without manual source code downloads.

## 🆓 Community Edition (Freemium)

### Features
- Analyze contracts from transaction and contract URLs
- Support for major blockchain explorers
- User-provided API keys (free tier)
- Basic rate limiting and error handling
- Contract source verification and validation

### Supported Platforms

| Platform | Networks | Free API Limits | Setup URL |
|----------|----------|-----------------|-----------|
| **Etherscan** | Ethereum mainnet, Goerli, Sepolia | 5 calls/sec, 100k/day | https://etherscan.io/apis |
| **Polygonscan** | Polygon mainnet, Mumbai testnet | 5 calls/sec, 100k/day | https://polygonscan.com/apis |
| **BscScan** | Binance Smart Chain, testnet | 5 calls/sec, 10k/day | https://bscscan.com/apis |
| **Arbiscan** | Arbitrum One, Goerli | 5 calls/sec, 100k/day | https://arbiscan.io/apis |

## 🚀 Quick Start

### 1. Setup API Keys

#### Interactive Setup
```bash
# Guided API key configuration
soliditydefend --setup-api-keys
```

#### Environment Variables
```bash
# Set API keys for your shell session
export ETHERSCAN_API_KEY=your_etherscan_key_here
export POLYGONSCAN_API_KEY=your_polygonscan_key_here
export BSCSCAN_API_KEY=your_bscscan_key_here
export ARBISCAN_API_KEY=your_arbiscan_key_here
```

#### Persistent Configuration
Add to your shell profile (`.bashrc`, `.zshrc`, `.profile`):
```bash
# Add these lines to make API keys permanent
export ETHERSCAN_API_KEY=your_etherscan_key_here
export POLYGONSCAN_API_KEY=your_polygonscan_key_here
```

### 2. Analyze Contracts

#### From Transaction URLs
```bash
# Analyze contract created in a transaction
soliditydefend --from-url https://etherscan.io/tx/0x1234567890abcdef...

# Analyze contract interacted with in transaction
soliditydefend --from-url https://polygonscan.com/tx/0xabcdef1234567890...
```

#### From Contract URLs
```bash
# Direct contract address analysis
soliditydefend --from-url https://etherscan.io/address/0xcontractaddress...

# BSC contract analysis
soliditydefend --from-url https://bscscan.com/address/0xcontractaddress...
```

#### Advanced Options
```bash
# JSON output for CI/CD integration
soliditydefend --from-url <url> --format json --output results.json

# Filter by severity
soliditydefend --from-url <url> --min-severity high

# Disable caching
soliditydefend --from-url <url> --no-cache
```

## 📋 URL Format Support

### Transaction URLs
- `https://etherscan.io/tx/0x[transaction_hash]`
- `https://polygonscan.com/tx/0x[transaction_hash]`
- `https://bscscan.com/tx/0x[transaction_hash]`
- `https://arbiscan.io/tx/0x[transaction_hash]`

### Contract URLs
- `https://etherscan.io/address/0x[contract_address]`
- `https://polygonscan.com/address/0x[contract_address]`
- `https://bscscan.com/address/0x[contract_address]`
- `https://arbiscan.io/address/0x[contract_address]`

## 🔧 Configuration

### API Key Sources (Priority Order)
1. **Environment Variables** (highest priority)
2. **Configuration File** (`.soliditydefend.yml`)
3. **Interactive Setup** (fallback)

### Rate Limiting
- **Automatic**: Respects API provider rate limits
- **User Controlled**: Uses your personal API quotas
- **Cost Effective**: No additional charges from SolidityDefend

## 📊 Example Workflow

```bash
# 1. Setup (one-time)
$ soliditydefend --setup-api-keys
🔑 Setting up blockchain API keys...
🌐 Etherscan API Key
   Get your free key: https://etherscan.io/apis
   Enter API key: [your-key-here]
   ✅ Etherscan configured

# 2. Add to shell profile
$ echo 'export ETHERSCAN_API_KEY=your-key-here' >> ~/.bashrc

# 3. Analyze contracts
$ soliditydefend --from-url https://etherscan.io/tx/0x1234...
🔍 Analyzing contract from URL: https://etherscan.io/tx/0x1234...
✅ Found 1 verified contract(s)

📄 Analyzing contract: MyContract (0xabcd...)
   Platform: Etherscan
   Compiler: v0.8.19+commit.7dd6d404
   Verified: true
   Found 3 issues

● missing-access-modifiers Function 'withdraw' performs critical operations...
● unchecked-external-call External call return value not checked...
● missing-zero-address-check Missing zero address validation...

📊 Analysis Summary:
   Contracts analyzed: 1
   Successful: 1
   Total issues found: 3
```

## 🛠️ Troubleshooting

### Common Issues

#### No API Key Error
```
❌ No API key configured for Etherscan
💡 Get your free API key and configure it:
   🔗 https://etherscan.io/apis
   🔧 export ETHERSCAN_API_KEY=your_key_here
```

**Solution**: Get free API key and set environment variable

#### Contract Not Verified
```
❌ Contract source code not available - contract may not be verified
```

**Solution**: Only verified contracts can be analyzed. Check if contract is verified on explorer.

#### Rate Limit Exceeded
```
❌ API error: Rate limit exceeded
```

**Solution**: Wait for rate limit reset or upgrade your API plan.

#### Unsupported URL
```
❌ Unsupported blockchain explorer: unknown.com
```

**Solution**: Use supported explorers (Etherscan, Polygonscan, BscScan, Arbiscan).

## 💼 Enterprise Edition Features

> **Note**: These features are planned for future Enterprise releases

### Advanced Capabilities
- **Batch URL Processing**: Analyze multiple URLs from file input
- **Managed API Keys**: Built-in API key pool with higher rate limits
- **Dependency Analysis**: Fetch and analyze imported contracts
- **Historical Analysis**: Time-based contract version comparison
- **Audit Trail**: Detailed logging and compliance reporting
- **Priority Support**: Dedicated support for API issues

### Enterprise CLI Examples
```bash
# Batch processing (Enterprise only)
soliditydefend --batch-urls contracts.txt --enterprise-keys

# Dependency analysis (Enterprise only)
soliditydefend --from-url <url> --include-dependencies --audit-trail

# Historical analysis (Enterprise only)
soliditydefend --from-url <url> --compare-versions --enterprise-reporting
```

### Enterprise Benefits
- **Unlimited Analysis**: No daily rate limits
- **Advanced Features**: Multi-contract analysis, dependency tracking
- **Professional Support**: Priority technical support
- **Compliance Ready**: Audit trails and detailed reporting
- **Team Management**: API key sharing and usage analytics

For Enterprise inquiries: [Contact Sales](mailto:enterprise@soliditydefend.dev)

## 🔒 Privacy & Security

### Data Handling
- **No Data Storage**: Contract source code is not stored permanently
- **Temporary Files**: Source code temporarily saved during analysis, then deleted
- **API Keys**: Stored locally on your machine, never transmitted to SolidityDefend
- **Network Security**: All requests use HTTPS encryption

### Best Practices
- **Protect API Keys**: Never commit API keys to version control
- **Regular Rotation**: Periodically regenerate API keys
- **Environment Isolation**: Use different keys for development/production
- **Rate Monitoring**: Monitor your API usage on explorer platforms

## 📚 Integration Examples

### CI/CD Pipeline
```yaml
# GitHub Actions example
- name: Analyze Contract from Transaction
  run: |
    export ETHERSCAN_API_KEY=${{ secrets.ETHERSCAN_API_KEY }}
    soliditydefend --from-url ${{ env.TX_URL }} --format json --output security-report.json
  env:
    TX_URL: https://etherscan.io/tx/0x1234...
```

### Security Research
```bash
# Analyze recent high-value transactions
export ETHERSCAN_API_KEY=your_key
for tx in $(curl -s "https://api.etherscan.io/api?module=account&action=txlist&address=0x...&startblock=0&endblock=latest&sort=desc&apikey=$ETHERSCAN_API_KEY" | jq -r '.result[0:5][].hash'); do
  soliditydefend --from-url "https://etherscan.io/tx/$tx" --min-severity medium
done
```

### Bug Bounty Hunting
```bash
# Quick analysis of reported contract
soliditydefend --from-url https://etherscan.io/address/0xreported-contract \
  --format json --output bounty-analysis.json --min-severity high
```

This freemium model provides immediate value to the community while establishing a clear upgrade path for professional users requiring advanced features and enterprise support.