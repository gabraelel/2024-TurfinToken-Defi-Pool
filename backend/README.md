### Deploying YF_LP
### 🔧 Preconfiguration
0. **Install dependencies in project directory(working with node v10.19.0)**
</br>```npm i```
1. **Install truffle globally**
</br>```npm i -g truffle```
2. **Rename .env_example to .env and fill PRIVATE_KEYS&DEV_ADDRESS (rest later)**
3. **Compile contracts**
</br>```truffle compile```
</br>
</br>

## 📃 Instructions to deploy on ETH
0. **Get LP Token address([instructions](https://www.reddit.com/r/CryptoCurrency/comments/jm1wah/how_to_provide_liquidity_on_uniswap_and_stake_lp/) or in Masterclass video) and add it to .env LP_TOKEN_ADDRESS**
1. **In .env fill INFURA_KEY ([instruction](https://ethereumico.io/knowledge-base/infura-api-key-guide/))**
2. **Get Test Rinkeby ETH [link](https://faucet.rinkeby.io/)**
3. **Check the latest block on Rinkeby [link](https://rinkeby.etherscan.io/)**
4. **Add to that number ~1000 blocks and put this number in .env START_BLOCK**
5. **In .env END_BLOCK add higher number than START_BLOCK (e.g. 1M higher)**
6. **Optionally edit also TOKENS_PER_BLOCK & ALLOCATION_POINT (More info in Masterclass video)**
7. **Migrate contracts to ETH**
</br>```truffle migrate --reset --network rinkeby```
</br>```...and then follow log instructions```
</br>
</br>

## 📃 Instructions to deploy on BSC
1. **Get Test BNB [link](https://testnet.binance.org/faucet-smart)**
2. **Create&Add liquidity pool on PancakeSwap**
</br>```truffle exec scripts/create_lp.js --network bsc_testnet```
</br>```...and then follow log instructions```
3. **Migrate Contracts to BSC**
</br>```truffle migrate --reset --network bsc_testnet```
</br>```...and then follow log instructions```
