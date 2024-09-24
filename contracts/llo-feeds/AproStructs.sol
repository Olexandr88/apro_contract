// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

contract AproStructs {

    struct Price {
        uint192 value;
        int8 decimal;
        uint32 observeAt;
        uint32 expireAt;
    }
}