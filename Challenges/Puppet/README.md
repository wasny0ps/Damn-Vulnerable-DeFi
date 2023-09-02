<img src="https://github.com/wasny0ps/Damn-Vulnerable-DeFi/blob/main/src/8.png">

# Target Contract Review

Given contract.

**PupperPool.sol**

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Address.sol";
import "../DamnValuableToken.sol";

/**
 * @title PuppetPool
 * @author Damn Vulnerable DeFi (https://damnvulnerabledefi.xyz)
 */
contract PuppetPool is ReentrancyGuard {
    using Address for address payable;

    uint256 public constant DEPOSIT_FACTOR = 2;

    address public immutable uniswapPair;
    DamnValuableToken public immutable token;

    mapping(address => uint256) public deposits;

    error NotEnoughCollateral();
    error TransferFailed();

    event Borrowed(address indexed account, address recipient, uint256 depositRequired, uint256 borrowAmount);

    constructor(address tokenAddress, address uniswapPairAddress) {
        token = DamnValuableToken(tokenAddress);
        uniswapPair = uniswapPairAddress;
    }

    // Allows borrowing tokens by first depositing two times their value in ETH
    function borrow(uint256 amount, address recipient) external payable nonReentrant {
        uint256 depositRequired = calculateDepositRequired(amount);

        if (msg.value < depositRequired)
            revert NotEnoughCollateral();

        if (msg.value > depositRequired) {
            unchecked {
                payable(msg.sender).sendValue(msg.value - depositRequired);
            }
        }

        unchecked {
            deposits[msg.sender] += depositRequired;
        }

        // Fails if the pool doesn't have enough tokens in liquidity
        if(!token.transfer(recipient, amount))
            revert TransferFailed();

        emit Borrowed(msg.sender, recipient, depositRequired, amount);
    }

    function calculateDepositRequired(uint256 amount) public view returns (uint256) {
        return amount * _computeOraclePrice() * DEPOSIT_FACTOR / 10 ** 18;
    }

    function _computeOraclePrice() private view returns (uint256) {
        // calculates the price of the token in wei according to Uniswap pair
        return uniswapPair.balance * (10 ** 18) / token.balanceOf(uniswapPair);
    }
}
```

The `PuppetPool` contract is a smart contract that allows users to borrow tokens by depositing collateral in the form of ETH.

It defines a constant `DEPOSIT_FACTOR` which is set to 2. This factor is used to calculate the required deposit amount based on the borrowed token amount.

In the constructor, it gets instance of `DamnValuableToken` and address of **Uniswap pair for the token**.

`barrow()` : Allows users to borrow tokens by depositing collateral in the form of ETH. The function takes the desired borrow amount and the recipient address as parameters. The function checks if the user has provided enough collateral and refunds any excess ETH. It then transfers the borrowed tokens to the recipient address.

`calculateDepositRequired()` : Calculates the required deposit amount based on the desired borrow amount. It uses the `_computeOraclePrice()` function to get the price of the token in wei.

`_computeOraclePrice()` : Calculates the price of the token in wei based on the ETH balance of the Uniswap pair and the token balance of the pair.


Challenge's message:

> There’s a lending pool where users can borrow Damn Valuable Tokens (DVTs). To do so, they first need to deposit twice the borrow amount in ETH as collateral. The pool currently has 100000 DVTs in liquidity.
There’s a DVT market opened in an old Uniswap v1 exchange, currently with 10 ETH and 10 DVT in liquidity.
Pass the challenge by taking all tokens from the lending pool. You start with 25 ETH and 1000 DVTs in balance.

# Subverting


