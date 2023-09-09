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

# Subverting

