import { MetaTransactionData, OperationType } from '@safe-global/types-kit'
import { encodeFunctionData, encodeAbiParameters, parseAbiParameters, keccak256, concat, Hex, Address, privateKeyToAccount } from 'viem'
import { privateKeyToAccount } from 'viem/accounts'
import { readFileSync } from 'fs'
import { join, dirname } from 'path'
import { fileURLToPath } from 'url'
import 'dotenv/config'

import SafeModule from '@safe-global/protocol-kit'
const Safe = SafeModule.default
import SafeApiKitModule from '@safe-global/api-kit'
const SafeApiKit = SafeApiKitModule.default

const __dirname = dirname(fileURLToPath(import.meta.url))
const ARTIFACTS_DIR = join(__dirname, '../../out')

// Deterministic CREATE2 factory (deployed on most networks)
const CREATE2_FACTORY = '0x4e59b44847b379578588920cA78FbF26c0B4956C' as const

const SAFE_CREATE_CALL = '0x9b35Af71d77eaf8d7e40252370304687390A1A52' as const

// Network configurations
const NETWORKS = {
  local: {
    rpc: process.env.LOCAL_RPC_URL || 'http://127.0.0.1:8545',
    chainId: 11155111n, // Sepolia chain ID (since we forked Sepolia)
    txServiceUrl: undefined,
  },
  sepolia: {
    rpc: process.env.SEPOLIA_RPC_URL!,
    chainId: 11155111n,
    txServiceUrl: undefined,
  },
  mainnet: {
    rpc: process.env.MAINNET_RPC_URL!,
    chainId: 480n,
    txServiceUrl: 'https://safe-transaction-worldchain.safe.global/api',
  },
} as const

type NetworkName = keyof typeof NETWORKS

interface DeploymentConfig {
  safeAddress: Address
  signerPrivateKey: Hex
  threshold: number
  numPeers: number
  salt: Hex
  network: NetworkName
}

interface Artifact {
  abi: any[]
  bytecode: { object: Hex }
}

function loadArtifact(path: string): Artifact {
  const fullPath = join(ARTIFACTS_DIR, path)
  const content = JSON.parse(readFileSync(fullPath, 'utf-8'))
  return {
    abi: content.abi,
    bytecode: { object: content.bytecode.object as Hex },
  }
}

function computeCreate2Address(factory: Address, salt: Hex, initCodeHash: Hex): Address {
  const encoded = concat([
    '0xff',
    factory,
    salt,
    initCodeHash,
  ])
  return `0x${keccak256(encoded).slice(-40)}` as Address
}

function buildCreate2Tx(salt: Hex, initCode: Hex): MetaTransactionData {
  return {
    to: CREATE2_FACTORY,
    value: '0',
    data: concat([salt, initCode]),
    operation: OperationType.Call,
  }
}

async function buildDeploymentTransactions(config: DeploymentConfig): Promise<{
  transactions: MetaTransactionData[]
  addresses: {
    accumulator: Address
    verifier: Address
    implementation: Address
    proxy: string // Not deterministic - deployed via CREATE from Safe
  }
}> {
  const { threshold, numPeers, salt, safeAddress } = config

  // Load artifacts
  const babyJubJubArtifact = loadArtifact('BabyJubJub.sol/BabyJubJub.json')
  
  // Select verifier based on threshold/numPeers
  let verifierArtifact: Artifact
  if (threshold === 2 && numPeers === 3) {
    verifierArtifact = loadArtifact('Groth16VerifierKeyGen13.sol/Groth16Verifier.json')
  } else if (threshold === 2 && numPeers === 5) {
    verifierArtifact = loadArtifact('Groth16VerifierKeyGen25.sol/Groth16Verifier.json')
  } else {
    throw new Error(`Unsupported threshold/numPeers combination: ${threshold}/${numPeers}`)
  }
  
  const registryArtifact = loadArtifact('OprfKeyRegistry.sol/OprfKeyRegistry.json')
  const proxyArtifact = loadArtifact('ERC1967Proxy.sol/ERC1967Proxy.json')

  // Use different salts for each contract to avoid collisions
  const accumulatorSalt = keccak256(concat([salt, '0x01']))
  const verifierSalt = keccak256(concat([salt, '0x02']))
  const implSalt = keccak256(concat([salt, '0x03']))

  // Compute deterministic addresses
  const accumulatorInitCode = babyJubJubArtifact.bytecode.object
  const accumulatorAddress = computeCreate2Address(
    CREATE2_FACTORY,
    accumulatorSalt,
    keccak256(accumulatorInitCode)
  )

  const verifierInitCode = verifierArtifact.bytecode.object
  const verifierAddress = computeCreate2Address(
    CREATE2_FACTORY,
    verifierSalt,
    keccak256(verifierInitCode)
  )

  const implInitCode = registryArtifact.bytecode.object
  const implAddress = computeCreate2Address(
    CREATE2_FACTORY,
    implSalt,
    keccak256(implInitCode)
  )

  // Encode initializer for proxy
  const initData = encodeFunctionData({
    abi: registryArtifact.abi,
    functionName: 'initialize',
    args: [
      safeAddress,           // the Safe(Not TACEO Admin address for now...)
      verifierAddress,       // keyGenVerifier
      accumulatorAddress,    // accumulator
      BigInt(threshold),
      BigInt(numPeers),
    ],
  })

  // Proxy constructor args: (implementation, initData)
  const proxyConstructorArgs = encodeAbiParameters(
    parseAbiParameters('address, bytes'),
    [implAddress, initData]
  )
  const proxyInitCode = concat([proxyArtifact.bytecode.object, proxyConstructorArgs])

  const createCallData = encodeFunctionData({
    abi: [{
      name: 'performCreate',
      type: 'function',
      inputs: [
        { name: 'value', type: 'uint256' },
        { name: 'deploymentData', type: 'bytes' }
      ],
      outputs: [{ name: 'newContract', type: 'address' }]
    }],
    functionName: 'performCreate',
    args: [0n, proxyInitCode],
  })

  // Build transactions
  // First 3: CREATE2 deployments (deterministic addresses)
  // Last 1: Deploy proxy via Safe's CreateCall (msg.sender = Safe in initializer)
  const transactions: MetaTransactionData[] = [
    buildCreate2Tx(accumulatorSalt, accumulatorInitCode),
    buildCreate2Tx(verifierSalt, verifierInitCode),
    buildCreate2Tx(implSalt, implInitCode),
    {
      to: SAFE_CREATE_CALL,
      value: '0',
      data: createCallData,
      operation: OperationType.DelegateCall,
    },
  ]

  return {
    transactions,
    addresses: {
      accumulator: accumulatorAddress,
      verifier: verifierAddress,
      implementation: implAddress,
      proxy: '(determined at execution - check tx logs)',
    },
  }
}

async function deployLocal(config: DeploymentConfig) {
  console.log('🔧 Local deployment mode\n')

  const { rpc } = NETWORKS[config.network]

  const safe = await Safe.init({
    provider: rpc,
    signer: config.signerPrivateKey,
    safeAddress: config.safeAddress,
  })

  console.log('Safe address:', await safe.getAddress())
  console.log('Threshold:', await safe.getThreshold())
  console.log('Owners:', await safe.getOwners())
  console.log()

  const { transactions, addresses } = await buildDeploymentTransactions(config)

  console.log('📍 Predicted addresses:')
  console.log('  Accumulator:', addresses.accumulator)
  console.log('  Verifier:', addresses.verifier)
  console.log('  Implementation:', addresses.implementation)
  console.log('  Proxy: (will be in transaction logs)')
  console.log()

  console.log(`📦 Creating batch transaction with ${transactions.length} operations...`)
  const safeTx = await safe.createTransaction({ transactions })

  console.log('✍️  Signing and executing...')
  const txResponse = await safe.executeTransaction(safeTx)

  console.log('✅ Deployment complete!')
  console.log('Transaction hash:', txResponse.hash)
  console.log()
  console.log('🎯 OprfKeyRegistry deployed at:', addresses.proxy)

  return addresses
}

async function proposeToSafe(config: DeploymentConfig) {
  console.log('📤 Production mode - proposing to Safe\n')

  const { rpc, chainId } = NETWORKS[config.network]

  const safe = await Safe.init({
    provider: rpc,
    signer: config.signerPrivateKey,
    safeAddress: config.safeAddress,
  })

  const apiKit = new SafeApiKit({
    chainId,
    txServiceUrl: NETWORKS[config.network].txServiceUrl
  })

  console.log('Safe address:', await safe.getAddress())
  console.log('Network:', config.network)
  console.log()

  const { transactions, addresses } = await buildDeploymentTransactions(config)

  console.log('📍 Predicted addresses (same on any network with this salt):')
  console.log('  Accumulator:', addresses.accumulator)
  console.log('  Verifier:', addresses.verifier)
  console.log('  Implementation:', addresses.implementation)
  console.log('  Proxy: (will be in transaction logs after execution)')
  console.log()

  console.log(`📦 Creating batch transaction with ${transactions.length} operations...`)
  const safeTx = await safe.createTransaction({ transactions })

  const safeTxHash = await safe.getTransactionHash(safeTx)
  const signature = await safe.signHash(safeTxHash)

  console.log('📤 Proposing to Safe Transaction Service...')
  await apiKit.proposeTransaction({
    safeAddress: config.safeAddress,
    safeTransactionData: safeTx.data,
    safeTxHash,
    senderAddress: privateKeyToAccount(config.signerPrivateKey).address,
    senderSignature: signature.data,
  })

  const networkPrefix = config.network === 'mainnet' ? 'eth' : 'sep'
  console.log('✅ Transaction proposed!')
  console.log()
  console.log(`🔗 View and sign at:`)
  console.log(`   https://app.safe.global/transactions/queue?safe=${networkPrefix}:${config.safeAddress}`)
  console.log()
  console.log('📋 Share this with other signers to approve the deployment.')

  return addresses
}

async function main() {
  const args = process.argv.slice(2)
  const networkArg = args.find(a => a.startsWith('--network='))?.split('=')[1]
    || args[args.indexOf('--network') + 1]
    || 'local'

  const network = networkArg as NetworkName
  if (!NETWORKS[network]) {
    console.error(`Unknown network: ${network}`)
    console.error('Available networks:', Object.keys(NETWORKS).join(', '))
    process.exit(1)
  }

  const config: DeploymentConfig = {
    safeAddress: process.env.SAFE_ADDRESS as Address,
    signerPrivateKey: process.env.SIGNER_PRIVATE_KEY as Hex,
    threshold: parseInt(process.env.THRESHOLD || '2'),
    numPeers: parseInt(process.env.NUM_PEERS || '3'),
    salt: process.env.DEPLOY_SALT as Hex,
    network,
  }

  if (!config.safeAddress) {
    console.error('SAFE_ADDRESS environment variable required')
    process.exit(1)
  }
  if (!config.signerPrivateKey) {
    console.error('SIGNER_PRIVATE_KEY environment variable required')
    process.exit(1)
  }
  if (!config.salt) {
    console.error('DEPLOY_SALT environment variable required')
    process.exit(1)
  }

  console.log('🚀 OPRF Key Registry Deployment')
  console.log('================================\n')
  console.log('Config:')
  console.log('  Network:', network)
  console.log('  Safe:', config.safeAddress)
  console.log('  Threshold:', config.threshold)
  console.log('  NumPeers:', config.numPeers)
  console.log('  Salt:', config.salt)
  console.log()

  if (network === 'local') {
    await deployLocal(config)
  } else {
    await proposeToSafe(config)
  }
}

main().catch((error) => {
  console.error('Deployment failed:', error)
  process.exit(1)
})
