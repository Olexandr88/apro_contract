// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

import "../AproStructs.sol";
import {AccessControllerInterface} from "./AccessControllerInterface.sol";


interface IPriceReader {

    /// @notice Returns the period (in seconds) that a price feed is considered valid since its observe time
    function getValidTimePeriod() external view returns (uint256 validTimePeriod);

    function updateReport(bytes calldata report) external;

    function getPrice(
        bytes32 id
    ) external view returns (AproStructs.Price memory price);

    function getPriceUnsafe(
        bytes32 id
    ) external view returns (AproStructs.Price memory price);

    function getPriceNoOlderThan(
        bytes32 id,
        uint age
    ) external view returns (AproStructs.Price memory price);

}


  
