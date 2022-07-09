const Factory = artifacts.require('Factory.sol');
const Router = artifacts.require('Router.sol');
const Pair = artifacts.require('Pair.sol');
const Token1 = artifacts.require('Token1.sol');
const Token2 = artifacts.require('Token2.sol');

/* Only for BSC testnet ! */

module.exports = async done => {
  try {
    const accounts = await web3.eth.getAccounts()
    const amount = web3.utils.toWei('1000000', 'ether')

    const factory = await Factory.at('0x6725F303b657a9451d8BA641348b6761A6CC7a17');
    const router = await Router.at('0xD99D1c33F9fC3444f8101754aBC46c52416550D1');

    console.log('Deploying contracts...')
    const token1 = await Token1.new()
    const token2 = await Token2.new()

    console.log('Creating liquidity...')
    const pairAddress = await factory.createPair.call(token1.address, token2.address);
    const tx = await factory.createPair(token1.address, token2.address);

    console.log('Adding liquidity...')
    await token1.approve(router.address, amount);
    await token2.approve(router.address, amount);
    await router.addLiquidity(
      token1.address,
      token2.address,
      amount,
      amount,
      amount,
      amount,
      accounts[0],
      Math.floor(Date.now() / 1000) + 60 * 10
    );
    
    const pair = await Pair.at(pairAddress);
    const balance = await pair.balanceOf(accounts[0]);
    console.log('\nIn frontend/src/sushi/lib/constants.js scroll to CHAIN_ID 97 (bsc_testnet)')
    console.log(`Paste this ${pairAddress} LP token address into .env and supportedPools/lpAddresses`)
    console.log(`Paste this ${token1.address} Token1 address into supportedPools/tokenAddresses`)
    console.log(`Paste this ${token2.address} Token2 address into supportedPools/tokenAddresses`)
    console.log('\nAlso:')
    console.log(' * Check latests block on https://testnet.bscscan.com/')
    console.log(' * Add to that number ~1000 blocks and put this number in .env START_BLOCK')
    console.log(' * In .env END_BLOCK add higher number than START_BLOCK (e.g. 1M higher)')
    console.log(' * Optionally edit also TOKENS_PER_BLOCK & ALLOCATION_POINT (More info in Masterclass video)')
    console.log('\nOnce you completed steps above run:\ntruffle migrate --reset --network bsc_testnet')
    } catch(e) {
      console.log(e);
    }
  done();
};
