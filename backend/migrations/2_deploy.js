const SushiToken = artifacts.require('SushiToken.sol')
const MasterChef = artifacts.require('MasterChef.sol')

module.exports = async function(deployer) {
  // Deploy Sushi Token
  await deployer.deploy(SushiToken)
  const sushiToken = await SushiToken.deployed()

  // Deploy Masterchef Contract
  await deployer.deploy(
    MasterChef,
    sushiToken.address,
    process.env.DEV_ADDRESS, // Your address where you get sushi tokens - should be a multisig
    web3.utils.toWei(process.env.TOKENS_PER_BLOCK), // Number of tokens rewarded per block, e.g., 100
    process.env.START_BLOCK, // Block number when token mining starts
    process.env.BONUS_END_BLOCK // Block when bonus ends
  )

  // Make Masterchef contract token owner
  const masterChef = await MasterChef.deployed()
  await sushiToken.transferOwnership(masterChef.address)

  // Add Liquidity pool for rewards, e.g., "ETH/DAI Pool"
  await masterChef.add(
    process.env.ALLOCATION_POINT,
    process.env.LP_TOKEN_ADDRESS,
    false
  )
  
  console.log('In frontend/src/sushi/lib/constants.js scroll to CHAIN_ID 42 (if deployed on Kovan) or CHAIN_ID 97 (if deployed on bsc_testnet)')
  console.log(`\nPaste this ${sushiToken.address} into contractAddresses/sushi`)
  console.log(`\nPaste this ${masterChef.address} into contractAddresses/masterChef`)

  // Add more liquidity pools here upon deployment, or add them later manually
}
