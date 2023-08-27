<img src="https://github.com/wasny0ps/Damn-Vulnerable-DeFi/blob/main/src/3.png">

# Target Contract Review

Given contract.

**TrusterLenderPool.sol**

```solidity
// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import "@openzeppelin/contracts/utils/Address.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "../DamnValuableToken.sol";

/**
 * @title TrusterLenderPool
 * @author Damn Vulnerable DeFi (https://damnvulnerabledefi.xyz)
 */
contract TrusterLenderPool is ReentrancyGuard {
    using Address for address;

    DamnValuableToken public immutable token;

    error RepayFailed();

    constructor(DamnValuableToken _token) {
        token = _token;
    }

    function flashLoan(uint256 amount, address borrower, address target, bytes calldata data)
        external
        nonReentrant
        returns (bool)
    {
        uint256 balanceBefore = token.balanceOf(address(this));

        token.transfer(borrower, amount);
        target.functionCall(data);

        if (token.balanceOf(address(this)) < balanceBefore)
            revert RepayFailed();

        return true;
    }
}
```

`TrusterLenderPool` is a contract that **allows users to borrow tokens from the pool and execute arbitrary code in a flash loan**.

The constructor function takes an instance of the `DamnValuableToken` contract and assigns it to the token variable.

`flashLoan()` : It allows a borrower to borrow a specified amount of tokens from the pool and execute a target function with provided data. The borrower must provide the amount to borrow, their address, the target contract address, and the data to be executed.

Inside the function, the current balance of the token contract is stored in the `balanceBefore` variable. Then, the specified amount of tokens is transferred from the pool to the borrower's address using the transfer function of the token contract. After that, the target function specified by the borrower is executed using the `functionCall()` function.







Challenge's message:

> More and more lending pools are offering flash loans. In this case, a new pool has launched that is offering flash loans of DVT tokens for free.
The pool holds 1 million DVT tokens. You have nothing.
To pass this challenge, take all tokens out of the pool. If possible, in a single transaction.

# Subverting


```solidity

```

```js

```

```powershell

```

**_by wasny0ps_**
