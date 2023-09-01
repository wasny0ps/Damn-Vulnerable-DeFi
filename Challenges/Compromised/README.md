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
 *         The oracle's price for a given symbol is the median price of the symbol over all sources.
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



# Subverting





