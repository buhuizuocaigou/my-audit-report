---
title: "Protocol Audit Report: PasswordStore"
author: "Nirenix"
date: "May 21, 2026"

# Eisvogel title page styling
titlepage: true
titlepage-color: "1F2D3D"
titlepage-text-color: "FFFFFF"
titlepage-rule-color: "FFFFFF"
titlepage-rule-height: 2
toc-own-page: true
listings-no-page-break: false

# CJK font configuration (for any inline Chinese annotations)
CJKmainfont: "Noto Sans CJK SC"
CJKoptions:
  - BoldFont=Noto Sans CJK SC Bold
monofont: "Noto Sans Mono CJK SC"
monofontoptions:
  - Scale=0.9
---

# Protocol Summary

PasswordStore is a smart contract designed to allow a single user to store and retrieve a password on-chain. The contract is intended to ensure that only the owner can set or read the stored password.

# Disclaimer

The auditor (Nirenix) makes all efforts to find as many vulnerabilities in the code in the given time period, but holds no responsibility for the findings provided in this document. A security audit by the auditor is not an endorsement of the underlying business or product. The audit was time-boxed and the review of the code was solely focused on the security aspects of the Solidity implementation of the contracts.

# Risk Classification

|                        | Impact: High  | Impact: Medium | Impact: Low  |
| ---------------------- | ------------- | -------------- | ------------ |
| **Likelihood: High**   | High          | High / Medium  | Medium       |
| **Likelihood: Medium** | High / Medium | Medium         | Medium / Low |
| **Likelihood: Low**    | Medium        | Medium / Low   | Low          |

# Audit Details

## Scope

```
./src/
└── PasswordStore.sol
```

## Roles

- **Owner**: The user who can set and read the password.
- **Outsiders**: No other party should be able to set or read the password.

# Executive Summary

## Issues Found

| Severity      | Number of Issues |
| ------------- | ---------------- |
| High          | 2                |
| Medium        | 0                |
| Low           | 0                |
| Informational | 1                |
| **Total**     | **3**            |

\newpage

# Findings

## High

### [H-1] Storing the password on-chain makes it visible to anyone, no matter the Solidity `private` visibility keyword

**Description:**

All data stored on-chain is publicly visible — regardless of the Solidity `private` visibility keyword. The `private` modifier only restricts read access at the Solidity language level (i.e., other contracts cannot call it directly); it does **not** prevent anyone from reading the underlying storage slot directly from the blockchain.

The `PasswordStore::s_password` variable is intended to be hidden and only retrievable through `PasswordStore::getPassword`, which is meant to be called only by the contract owner. However, because the value lives in storage slot `1` of the contract, anyone can read it off-chain by querying the node directly.

**Impact:**

Anyone is able to read the password stored on-chain, completely breaking the core functionality of the protocol.

**Proof of Concept:**

The following demonstrates how any party can read the password directly from the chain without calling any contract function.

1. Start a local Anvil chain in a terminal:

```bash
anvil
```

2. Deploy the contract to the local chain:

```bash
make deploy
```

3. Use `cast` to read storage slot `1` (where `s_password` is stored — slot `0` is occupied by `s_owner`):

```bash
cast storage <CONTRACT_ADDRESS> 1 --rpc-url http://127.0.0.1:8545
```

A `bytes32` value is returned, for example:

```
0x6d7950617373776f726400000000000000000000000000000000000000000014
```

4. Decode the hex value to its ASCII representation:

```bash
cast parse-bytes32-string 0x6d7950617373776f726400000000000000000000000000000000000000000014
```

Output:

```
myPassword
```

The password is now revealed without the caller ever invoking `getPassword()` or being the owner.

**Recommended Mitigation:**

The overall architecture of the contract should be reconsidered. One approach is to encrypt the password off-chain and store only the resulting ciphertext on-chain. This would require the user to remember an off-chain decryption key.

Additionally, the `getPassword` view function should be removed, since invoking it on-chain would require sending the decryption key through a transaction — exposing it publicly through transaction calldata.

\newpage

### [H-2] `PasswordStore::setPassword` has no access control, allowing any non-owner to change the stored password

**Description:**

The `setPassword` function is declared `external` and contains no access control logic. Although the contract's NatSpec describes it as a function for the owner to set a new password, the implementation does not verify that `msg.sender == s_owner`.

```solidity
function setPassword(string memory newPassword) external {
    // @audit No access control — any caller can overwrite the password
    s_password = newPassword;
    emit SetNetPassword();
}
```

**Impact:**

Any external account can call `setPassword` and overwrite the owner's password, severely breaking the contract's intended functionality.

**Proof of Concept:**

Add the following fuzz test to `PasswordStore.t.sol`:

```solidity
function test_anyone_can_set_password(address randomAddress) public {
    // Exclude the legitimate owner from the fuzz input
    vm.assume(randomAddress != owner);

    // A non-owner sets a new password
    vm.startPrank(randomAddress);
    string memory attackPassword = "attacker_win";
    passwordStore.setPassword(attackPassword);
    vm.stopPrank();

    // The owner reads the password back and observes it has been overwritten
    vm.startPrank(owner);
    string memory actualPassword = passwordStore.getPassword();
    assertEq(actualPassword, attackPassword);
}
```

Running this test confirms that any address can successfully overwrite the password.

**Recommended Mitigation:**

Add an ownership check at the start of `setPassword`:

```solidity
function setPassword(string memory newPassword) external {
    if (msg.sender != s_owner) {
        revert PasswordStore__NotOwner();
    }
    s_password = newPassword;
    emit SetNetPassword();
}
```

\newpage

## Informational

### [I-1] The `PasswordStore::getPassword` NatSpec references a parameter that does not exist

**Description:**

The NatSpec documentation for `getPassword` declares a `@param newPassword` tag, but the function takes no arguments:

```solidity
/*
 * @notice This allows only the owner to retrieve the password.
 * @param newPassword The new password to set.
 */
function getPassword() external view returns (string memory) {
```

The function signature is `getPassword()`, while the NatSpec describes `getPassword(string)`.

**Impact:**



**Recommended Mitigation:**

Remove the incorrect `@param` line:

```diff
  /*
   * @notice This allows only the owner to retrieve the password.
-  * @param newPassword The new password to set.
   */
  function getPassword() external view returns (string memory) {
```