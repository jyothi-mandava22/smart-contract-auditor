# Example vulnerable Solidity contracts for demo purposes
# These are intentionally vulnerable for educational/testing use

REENTRANCY_CONTRACT = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// VULNERABLE CONTRACT: Classic Reentrancy Attack
// This contract is intentionally vulnerable - DO NOT USE IN PRODUCTION
// Vulnerability: The withdraw() function sends ETH before updating the balance,
// allowing an attacker contract to recursively call withdraw() and drain funds.

contract VulnerableBank {
    mapping(address => uint256) public balances;

    event Deposit(address indexed user, uint256 amount);
    event Withdrawal(address indexed user, uint256 amount);

    function deposit() public payable {
        require(msg.value > 0, "Must deposit more than 0");
        balances[msg.sender] += msg.value;
        emit Deposit(msg.sender, msg.value);
    }

    // VULNERABILITY: State update happens AFTER external call
    // An attacker can re-enter this function before balance is set to 0
    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        
        // DANGEROUS: External call before state update
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        
        // Balance updated AFTER the call - too late!
        balances[msg.sender] -= amount;
        emit Withdrawal(msg.sender, amount);
    }

    function getBalance() public view returns (uint256) {
        return address(this).balance;
    }
}"""

INTEGER_OVERFLOW_CONTRACT = """// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;

// VULNERABLE CONTRACT: Integer Overflow / Underflow
// This contract uses Solidity 0.6.x which does NOT have built-in overflow protection
// Vulnerability: Token balances can overflow/underflow without SafeMath

contract VulnerableToken {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    
    uint256 public totalSupply;
    string public name = "VulnerableToken";
    string public symbol = "VULN";
    uint8 public decimals = 18;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    constructor(uint256 _initialSupply) public {
        balanceOf[msg.sender] = _initialSupply;
        totalSupply = _initialSupply;
    }

    // VULNERABILITY: No overflow check on addition
    // If balanceOf[to] + value overflows uint256, it wraps to a small number
    function transfer(address to, uint256 value) public returns (bool) {
        require(balanceOf[msg.sender] >= value, "Insufficient balance");
        
        balanceOf[msg.sender] -= value;
        balanceOf[to] += value;  // OVERFLOW POSSIBLE HERE
        
        emit Transfer(msg.sender, to, value);
        return true;
    }

    // VULNERABILITY: Underflow on approval + transferFrom
    // An attacker can manipulate allowances via integer underflow
    function transferFrom(address from, address to, uint256 value) public returns (bool) {
        require(value <= balanceOf[from]);
        require(value <= allowance[from][msg.sender]);
        
        balanceOf[from] -= value;
        balanceOf[to] += value;
        allowance[from][msg.sender] -= value;  // UNDERFLOW POSSIBLE
        
        emit Transfer(from, to, value);
        return true;
    }

    // VULNERABILITY: No check if spender is address(0)
    function approve(address spender, uint256 value) public returns (bool) {
        allowance[msg.sender][spender] = value;
        emit Approval(msg.sender, spender, value);
        return true;
    }

    // VULNERABILITY: Allows minting to address(0) - burning supply without control
    function mint(address to, uint256 amount) public {
        totalSupply += amount;   // OVERFLOW POSSIBLE
        balanceOf[to] += amount; // OVERFLOW POSSIBLE
        emit Transfer(address(0), to, amount);
    }
}"""

ACCESS_CONTROL_CONTRACT = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// VULNERABLE CONTRACT: Broken Access Control
// Multiple access control vulnerabilities combined
// Vulnerabilities: Unprotected admin functions, tx.origin auth, selfdestruct exposure

contract VulnerableVault {
    address public owner;
    address public admin;
    mapping(address => uint256) private userFunds;
    bool public paused;
    uint256 public feePercent = 1;

    event FundsDeposited(address user, uint256 amount);
    event FundsWithdrawn(address user, uint256 amount);
    event OwnershipTransferred(address newOwner);

    constructor() {
        owner = msg.sender;
        admin = msg.sender;
    }

    // VULNERABILITY 1: tx.origin authentication
    // tx.origin is the original EOA that started the transaction chain
    // An attacker contract can trick a legitimate user into calling it,
    // then this modifier passes because tx.origin is still the legitimate user
    modifier onlyOwner() {
        require(tx.origin == owner, "Not owner");  // DANGEROUS: use msg.sender instead
        _;
    }

    // VULNERABILITY 2: No access control on this critical function
    // Anyone can call this and make themselves admin
    function setAdmin(address newAdmin) public {
        admin = newAdmin;  // MISSING: onlyOwner modifier
    }

    // VULNERABILITY 3: Admin can change fee to 100% and drain users
    // No upper bound check on fee percentage
    function setFeePercent(uint256 newFee) public {
        require(msg.sender == admin, "Not admin");
        feePercent = newFee;  // MISSING: require(newFee <= 10, "Fee too high")
    }

    function deposit() public payable {
        require(!paused, "Contract is paused");
        require(msg.value > 0, "Must send ETH");
        userFunds[msg.sender] += msg.value;
        emit FundsDeposited(msg.sender, msg.value);
    }

    function withdraw(uint256 amount) public {
        require(!paused, "Contract is paused");
        require(userFunds[msg.sender] >= amount, "Insufficient funds");
        
        uint256 fee = (amount * feePercent) / 100;
        uint256 payout = amount - fee;
        
        userFunds[msg.sender] -= amount;
        payable(msg.sender).transfer(payout);
        emit FundsWithdrawn(msg.sender, payout);
    }

    // VULNERABILITY 4: Unprotected selfdestruct
    // Anyone who becomes admin (via the broken setAdmin above) can destroy the contract
    // and steal all ETH stored in it
    function emergencyDestruct(address payable recipient) public {
        require(msg.sender == admin, "Not admin");
        selfdestruct(recipient);  // DANGEROUS: Can drain all contract ETH
    }

    // VULNERABILITY 5: Owner transfer has no zero-address check
    function transferOwnership(address newOwner) public onlyOwner {
        owner = newOwner;  // MISSING: require(newOwner != address(0))
        emit OwnershipTransferred(newOwner);
    }

    function getMyFunds() public view returns (uint256) {
        return userFunds[msg.sender];
    }

    // VULNERABILITY 6: Pause function accessible only via onlyOwner (tx.origin bug)
    // But since setAdmin has no protection, anyone can pause the contract via admin
    function pause() public {
        require(msg.sender == admin, "Not admin");
        paused = true;
    }
}"""
