// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

import {ConfirmedOwner} from "./access/ConfirmedOwner.sol";
import {IVerifierProxy} from "./interfaces/IVerifierProxy.sol";
import {IVerifier} from "./interfaces/IVerifier.sol";
import {TypeAndVersionInterface} from "./TypeAndVersionInterface.sol";
import {AccessControllerInterface} from "./interfaces/AccessControllerInterface.sol";
import {IERC165} from "./vendor/openzeppelin-solidity/v4.8.3/contracts/interfaces/IERC165.sol";
import {IVerifierFeeManager} from "./interfaces/IVerifierFeeManager.sol";
import {IPriceReader} from "./interfaces/IPriceReader.sol";
import {AproStructs} from "./AproStructs.sol";

import {Common} from "./libraries/Common.sol";

/**
 * The verifier proxy contract is the gateway for all report verification requests
 * on a chain.  It is responsible for taking in a verification request and routing
 * it to the correct verifier contract.
 */
contract VerifierProxy is IVerifierProxy, IPriceReader, ConfirmedOwner, TypeAndVersionInterface {
  /// @notice This event is emitted whenever a new verifier contract is set
  /// @param oldConfigDigest The config digest that was previously the latest config
  /// digest of the verifier contract at the verifier address.
  /// @param oldConfigDigest The latest config digest of the verifier contract
  /// at the verifier address.
  /// @param verifierAddress The address of the verifier contract that verifies reports for
  /// a given digest
  event VerifierSet(bytes32 oldConfigDigest, bytes32 newConfigDigest, address verifierAddress);

  /// @notice This event is emitted whenever a new verifier contract is initialized
  /// @param verifierAddress The address of the verifier contract that verifies reports
  event VerifierInitialized(address verifierAddress);

  /// @notice This event is emitted whenever a verifier is unset
  /// @param configDigest The config digest that was unset
  /// @param verifierAddress The Verifier contract address unset
  event VerifierUnset(bytes32 configDigest, address verifierAddress);

  /// @notice This event is emitted when a new access controller is set
  /// @param oldAccessController The old access controller address
  /// @param newAccessController The new access controller address
  event AccessControllerSet(address oldAccessController, address newAccessController);

  /// @notice This event is emitted when a new read access controller is set
  /// @param oldReadAccessController The old read access controller address
  /// @param newReadAccessController The new read access controller address
  event ReadAccessControllerSet(address oldReadAccessController, address newReadAccessController);

  /// @notice This event is emitted when a new fee manager is set
  /// @param oldFeeManager The old fee manager address
  /// @param newFeeManager The new fee manager address
  event FeeManagerSet(address oldFeeManager, address newFeeManager);

  /// @notice This event is emitted when a new report is verified
  event PriceFeedUpdate(bytes32 indexed id, uint32 observeAt, uint32 expiresAt, uint192 value, int8 decimal);

  /// @notice This error is thrown whenever an address tries
  /// to exeecute a transaction that it is not authorized to do so
  error AccessForbidden();

  /// @notice This error is thrown whenever an address tries
  /// to read the price that it is not authorized to do so
  error ReadAccessForbidden();

  /// @notice This error is thrown whenever a zero address is passed
  error ZeroAddress();

  /// @notice This error is thrown when trying to set a verifier address
  /// for a digest that has already been initialized
  /// @param configDigest The digest for the verifier that has
  /// already been set
  /// @param verifier The address of the verifier the digest was set for
  error ConfigDigestAlreadySet(bytes32 configDigest, address verifier);

  /// @notice This error is thrown when trying to set a verifier address that has already been initialized
  error VerifierAlreadyInitialized(address verifier);

  /// @notice This error is thrown when the verifier at an address does
  /// not conform to the verifier interface
  error VerifierInvalid();

  /// @notice This error is thrown when the fee manager at an address does
  /// not conform to the fee manager interface
  error FeeManagerInvalid();

  /// @notice This error is thrown whenever a verifier is not found
  /// @param configDigest The digest for which a verifier is not found
  error VerifierNotFound(bytes32 configDigest);

  /// @notice This error is thrown whenever billing fails.
  error BadVerification();

  /// @notice This error is thrown when the price feed not found.
  error PriceFeedNotFound();

  /// @notice This error is thrown when the price feed expires.
  error PirceFeedExpire();

  /// @notice This error is thrown when the timestamp of price feed not be tolerable.
  error StalePrice();

  /// @notice Mapping of authorized verifiers
  mapping(address => bool) private s_initializedVerifiers;

  /// @notice Mapping between config digests and verifiers
  mapping(bytes32 => address) private s_verifiersByConfig;

  /// @notice Mapping between config digests and report
  mapping(bytes32 => AproStructs.Price) internal s_report_price;

  /// @notice The contract to control addresses that are allowed to verify reports
  AccessControllerInterface public s_accessController;

  /// @notice The contract to control addresses that are allowed to read price
  AccessControllerInterface public s_readAccessController;

  /// @notice The contract to control fees for report verification
  IVerifierFeeManager public s_feeManager;

  uint256 public validTimePeriod = 120;

  constructor(AccessControllerInterface accessController) ConfirmedOwner(msg.sender) {
    s_accessController = accessController;
  }

  modifier checkAccess() {
    AccessControllerInterface ac = s_accessController;
    if (address(ac) != address(0) && !ac.hasAccess(msg.sender, msg.data)) revert AccessForbidden();
    _;
  }

  modifier checkReadAccess() {
    AccessControllerInterface rac = s_readAccessController;
    if (address(rac) != address(0) && !rac.hasAccess(msg.sender, msg.data)) revert ReadAccessForbidden();
    _;
  }

  modifier onlyInitializedVerifier() {
    if (!s_initializedVerifiers[msg.sender]) revert AccessForbidden();
    _;
  }

  modifier onlyValidVerifier(address verifierAddress) {
    if (verifierAddress == address(0)) revert ZeroAddress();
    if (!IERC165(verifierAddress).supportsInterface(IVerifier.verify.selector)) revert VerifierInvalid();
    _;
  }

  modifier onlyUnsetConfigDigest(bytes32 configDigest) {
    address configDigestVerifier = s_verifiersByConfig[configDigest];
    if (configDigestVerifier != address(0)) revert ConfigDigestAlreadySet(configDigest, configDigestVerifier);
    _;
  }

  /// @inheritdoc TypeAndVersionInterface
  function typeAndVersion() external pure override returns (string memory) {
    return "VerifierProxy 2.0.0";
  }

  /// @inheritdoc IVerifierProxy
  function verify(
    bytes calldata payload,
    bytes calldata parameterPayload
  ) external payable checkAccess returns (bytes memory) {
    IVerifierFeeManager feeManager = s_feeManager;

    // Bill the verifier
    if (address(feeManager) != address(0)) {
      feeManager.processFee{value: msg.value}(payload, parameterPayload, msg.sender);
    }

    return _verify(payload);
  }

  /// @inheritdoc IVerifierProxy
  function verifyBulk(
    bytes[] calldata payloads,
    bytes calldata parameterPayload
  ) external payable checkAccess returns (bytes[] memory verifiedReports) {
    IVerifierFeeManager feeManager = s_feeManager;

    // Bill the verifier
    if (address(feeManager) != address(0)) {
      feeManager.processFeeBulk{value: msg.value}(payloads, parameterPayload, msg.sender);
    }

    //verify the reports
    verifiedReports = new bytes[](payloads.length);
    for (uint256 i; i < payloads.length; ++i) {
      verifiedReports[i] = _verify(payloads[i]);
    }

    return verifiedReports;
  }

  function _verify(bytes calldata payload) internal returns (bytes memory verifiedReport) {
    // First 32 bytes of the signed report is the config digest
    bytes32 configDigest = bytes32(payload);
    address verifierAddress = s_verifiersByConfig[configDigest];
    if (verifierAddress == address(0)) revert VerifierNotFound(configDigest);

    return IVerifier(verifierAddress).verify(payload, msg.sender);
  }

  /// @inheritdoc IVerifierProxy
  function initializeVerifier(address verifierAddress) external override onlyOwner onlyValidVerifier(verifierAddress) {
    if (s_initializedVerifiers[verifierAddress]) revert VerifierAlreadyInitialized(verifierAddress);

    s_initializedVerifiers[verifierAddress] = true;
    emit VerifierInitialized(verifierAddress);
  }

  /// @inheritdoc IVerifierProxy
  function setVerifier(
    bytes32 currentConfigDigest,
    bytes32 newConfigDigest,
    Common.AddressAndWeight[] calldata addressesAndWeights
  ) external override onlyUnsetConfigDigest(newConfigDigest) onlyInitializedVerifier {
    s_verifiersByConfig[newConfigDigest] = msg.sender;

    // Empty recipients array will be ignored and must be set off chain
    if (addressesAndWeights.length > 0) {
      if (address(s_feeManager) == address(0)) {
        revert ZeroAddress();
      }

      s_feeManager.setFeeRecipients(newConfigDigest, addressesAndWeights);
    }

    emit VerifierSet(currentConfigDigest, newConfigDigest, msg.sender);
  }

  /// @inheritdoc IVerifierProxy
  function unsetVerifier(bytes32 configDigest) external override onlyOwner {
    address verifierAddress = s_verifiersByConfig[configDigest];
    if (verifierAddress == address(0)) revert VerifierNotFound(configDigest);
    delete s_verifiersByConfig[configDigest];
    emit VerifierUnset(configDigest, verifierAddress);
  }

  /// @inheritdoc IVerifierProxy
  function getVerifier(bytes32 configDigest) external view override returns (address) {
    return s_verifiersByConfig[configDigest];
  }

  /// @inheritdoc IVerifierProxy
  function setAccessController(AccessControllerInterface accessController) external onlyOwner {
    address oldAccessController = address(s_accessController);
    s_accessController = accessController;
    emit AccessControllerSet(oldAccessController, address(accessController));
  }

  /// @inheritdoc IVerifierProxy
  function setReadAccessController(AccessControllerInterface readAccessController) external onlyOwner {
    address oldReadAccessController = address(s_readAccessController);
    s_readAccessController = readAccessController;
    emit ReadAccessControllerSet(oldReadAccessController, address(readAccessController));
  }

  /// @inheritdoc IVerifierProxy
  function setFeeManager(IVerifierFeeManager feeManager) external onlyOwner {
    if (address(feeManager) == address(0)) revert ZeroAddress();

    if (
      !IERC165(feeManager).supportsInterface(IVerifierFeeManager.processFee.selector) ||
      !IERC165(feeManager).supportsInterface(IVerifierFeeManager.processFeeBulk.selector)
    ) revert FeeManagerInvalid();

    address oldFeeManager = address(s_feeManager);
    s_feeManager = IVerifierFeeManager(feeManager);
    emit FeeManagerSet(oldFeeManager, address(feeManager));
  }

  /// @inheritdoc IPriceReader
  function updateReport(bytes calldata report) external onlyInitializedVerifier {
    (bytes32 feedId, , uint32 observeAt, , , uint32 expiresAt, uint192 value) = abi.decode(
      report,
      (bytes32, uint32, uint32, uint192, uint192, uint32, uint192)
    );
    AproStructs.Price storage price = s_report_price[feedId];
    if (observeAt > price.observeAt) {
      price.value = value;
      price.decimal = 18;
      price.observeAt = observeAt;
      price.expireAt = expiresAt;
      emit PriceFeedUpdate(feedId, observeAt, expiresAt, value, 18);
    }
  }

  function setValidTimePeriod(uint256 _validTimePeriod) external onlyOwner {
    validTimePeriod = _validTimePeriod;
  }

  function getValidTimePeriod() public view override returns (uint256) {
    return validTimePeriod;
  }

  /// @inheritdoc IPriceReader
  function getPrice(
    bytes32 id
  ) external view checkReadAccess returns (AproStructs.Price memory price){
    return getPriceNoOlderThan(id, getValidTimePeriod());
  }

  /// @inheritdoc IPriceReader
  function getPriceUnsafe(
      bytes32 id
  ) public view  checkReadAccess returns (AproStructs.Price memory price){
    price = s_report_price[id];

    if (price.observeAt == 0) revert PriceFeedNotFound();

    if (price.expireAt < block.timestamp) revert PirceFeedExpire();

    return price;
  }

  /// @inheritdoc IPriceReader
  function getPriceNoOlderThan(
      bytes32 id,
      uint age
  ) public view  checkReadAccess returns (AproStructs.Price memory price){
    price = getPriceUnsafe(id);

    if (block.timestamp > price.observeAt && block.timestamp - price.observeAt > age) revert StalePrice();

    return price;
  }

}