<img src="https://github.com/wasny0ps/Damn-Vulnerable-DeFi/blob/main/src/13.png">

# Target Contract Review

Given contracts.

**AuthorizerUpgradeable.sol**

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";

/**
 * @title AuthorizerUpgradeable
 * @author Damn Vulnerable DeFi (https://damnvulnerabledefi.xyz)
 */
contract AuthorizerUpgradeable is Initializable, OwnableUpgradeable, UUPSUpgradeable {
    mapping(address => mapping(address => uint256)) private wards;

    event Rely(address indexed usr, address aim);

    function init(address[] memory _wards, address[] memory _aims) external initializer {
        __Ownable_init();
        __UUPSUpgradeable_init();

        for (uint256 i = 0; i < _wards.length;) {
            _rely(_wards[i], _aims[i]);
            unchecked {
                i++;
            }
        }
    }

    function _rely(address usr, address aim) private {
        wards[usr][aim] = 1;
        emit Rely(usr, aim);
    }

    function can(address usr, address aim) external view returns (bool) {
        return wards[usr][aim] == 1;
    }

    function upgradeToAndCall(address imp, bytes memory wat) external payable override {
        _authorizeUpgrade(imp);
        _upgradeToAndCallUUPS(imp, wat, true);
    }

    function _authorizeUpgrade(address imp) internal override onlyOwner {}
}
```

This contract is called `AuthorizerUpgradeable` and it is used to manage authorization between different addresses in a decentralized application.

`init()` : This function is used to initialize the contract. It takes two arrays as parameters: `_wards` and `_aims`. Each element in the arrays represents an address pair that will be authorized.

`_rely()` : This function is used to establish an authorization relationship between two addresses.

`can()` : This function is used to check if an address is authorized to interact with another address. It returns true if the authorization exists.

`upgradeToAndCall()` : This function is used to upgrade the contract to a new implementation and call a function on the new implementation. It requires the caller to be the owner of the contract.

`_authorizeUpgrade()` : This function is used to authorize an upgrade to a new implementation. In this contract, it is an empty function, so upgrades are always authorized.

**WalletDeployer.sol**

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

interface IGnosisSafeProxyFactory {
    function createProxy(address masterCopy, bytes calldata data) external returns (address);
}

/**
 * @title  WalletDeployer
 * @author Damn Vulnerable DeFi (https://damnvulnerabledefi.xyz)
 * @notice A contract that allows deployers of Gnosis Safe wallets (v1.1.1) to be rewarded.
 *         Includes an optional authorization mechanism to ensure only expected accounts
 *         are rewarded for certain deployments.
 */
contract WalletDeployer {
    // Addresses of the Gnosis Safe Factory and Master Copy v1.1.1
    IGnosisSafeProxyFactory public constant fact = IGnosisSafeProxyFactory(0x76E2cFc1F5Fa8F6a5b3fC4c8F4788F0116861F9B);
    address public constant copy = 0x34CfAC646f301356fAa8B21e94227e3583Fe3F5F;

    uint256 public constant pay = 1 ether;
    address public immutable chief = msg.sender;
    address public immutable gem;

    address public mom;

    error Boom();

    constructor(address _gem) { gem = _gem; }

    /**
     * @notice Allows the chief to set an authorizer contract.
     * Can only be called once. TODO: double check.
     */
    function rule(address _mom) external {
        if (msg.sender != chief || _mom == address(0) || mom != address(0)) {
            revert Boom();
        }
        mom = _mom;
    }

    /**
     * @notice Allows the caller to deploy a new Safe wallet and receive a payment in return.
     *         If the authorizer is set, the caller must be authorized to execute the deployment.
     * @param wat initialization data to be passed to the Safe wallet
     * @return aim address of the created proxy
     */
    function drop(bytes memory wat) external returns (address aim) {
        aim = fact.createProxy(copy, wat);
        if (mom != address(0) && !can(msg.sender, aim)) {
            revert Boom();
        }
        IERC20(gem).transfer(msg.sender, pay);
    }

    // TODO(0xth3g450pt1m1z0r) put some comments
    function can(address u, address a) public view returns (bool) {
        assembly { 
            let m := sload(0)
            if iszero(extcodesize(m)) {return(0, 0)}
            let p := mload(0x40)
            mstore(0x40,add(p,0x44))
            mstore(p,shl(0xe0,0x4538c4eb))
            mstore(add(p,0x04),u)
            mstore(add(p,0x24),a)
            if iszero(staticcall(gas(),m,p,0x44,p,0x20)) {return(0,0)}
            if and(not(iszero(returndatasize())), iszero(mload(p))) {return(0,0)}
        }
        return true;
    }
}
```

The `WalletDeployer` contract is a contract that allows deployers of Gnosis Safe wallets (v1.1.1) to be rewarded. It includes an optional authorization mechanism to ensure that only expected accounts are rewarded for certain deployments.


`drop()` :  Allows the caller to deploy a new `Gnosis Safe wallet` and receive a payment in return. The function takes an **initialization data parameter (wat)** to be passed to the Safe wallet. If the authorizer is set and the caller is not authorized to execute the deployment, the function will revert.

`can()` : This function is used to check if an account is authorized by the authorizer contract to execute a deployment. Here is a detailed explanation of this function's assembly code:

```assembly
let m := sload(0) ; Loads the value at storage slot 0 and assigns it to m
if iszero(extcodesize(m)) {return(0, 0)} ; Checks if the smart contract at address m
let p := mload(0x40) ; Assigned the value stored at starting point for free memory in the current execution context.
mstore(0x40,add(p,0x44)) ; Updates the memory location 0x40 to point to a new free memory location. It increments the original value at 0x40 by 0x44 bytes, essentially allocating space for data in memory.
mstore(p,shl(0xe0,0x4538c4eb)) ; Stores a calculated value at the memory location pointed to by p. The result of left-shifting is 0xe0
mstore(add(p,0x04),u) ; Stores the address u at the memory location pointed to by p plus 0x04 bytes
mstore(add(p,0x04),a) ; Stores the address a at the memory location pointed to by p plus 0x04 bytes
if iszero(staticcall(gas(), m, p, 0x44, p, 0x20)) {return(0, 0)} ; Makes a static call to m. It checks if the call is successful and returns a non-zero value.
if and(not(iszero(returndatasize())), iszero(mload(p))) {return(0,0)} ; Checks the size of the return data from the static call and ensures that the value stored at memory location p is not zero
```

Challenge's message:

> There’s a contract that incentivizes users to deploy Gnosis Safe wallets, rewarding them with 1 DVT. It integrates with an upgradeable authorization mechanism. This way it ensures only allowed deployers (a.k.a. wards) are paid for specific deployments. Mind you, some parts of the system have been highly optimized by anon CT gurus.
The deployer contract only works with the official Gnosis Safe factory at `0x76E2cFc1F5Fa8F6a5b3fC4c8F4788F0116861F9B` and corresponding master copy at `0x34CfAC646f301356fAa8B21e94227e3583Fe3F5F`. Not sure how it’s supposed to work though - those contracts haven’t been deployed to this chain yet.
In the meantime, it seems somebody transferred 20 million DVT tokens to `0x9b6fb606a9f5789444c17768c6dfcf2f83563801`. Which has been assigned to a ward in the authorization contract. Strange, because this address is empty as well.
Pass the challenge by obtaining all tokens held by the wallet deployer contract. Oh, and the 20 million DVT tokens too.

# Subverting

