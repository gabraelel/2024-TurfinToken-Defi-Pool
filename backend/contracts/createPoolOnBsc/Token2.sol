pragma solidity 0.6.12;

import '@openzeppelin/contracts/token/ERC20/ERC20.sol';

contract Token2 is ERC20 {
  constructor() ERC20('Token 2', 'TK2') public {
    _mint(msg.sender, 1000000*1e18);
  }
}