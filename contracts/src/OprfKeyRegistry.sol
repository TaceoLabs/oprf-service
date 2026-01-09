// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Types} from "./Types.sol";
import {Ownable2StepUpgradeable} from "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

uint256 constant PUBLIC_INPUT_LENGTH_KEYGEN_13 = 24;
uint256 constant PUBLIC_INPUT_LENGTH_KEYGEN_25 = 36;
uint256 constant PUBLIC_INPUT_LENGTH_NULLIFIER = 13;
uint256 constant AUTHENTICATOR_MERKLE_TREE_DEPTH = 30;

interface IVerifierKeyGen13 {
    function verifyCompressedProof(
        uint256[4] calldata compressedProof,
        uint256[PUBLIC_INPUT_LENGTH_KEYGEN_13] calldata input
    ) external view;
}

interface IVerifierKeyGen25 {
    function verifyCompressedProof(
        uint256[4] calldata compressedProof,
        uint256[PUBLIC_INPUT_LENGTH_KEYGEN_25] calldata input
    ) external view;
}

interface IBabyJubJub {
    function add(uint256 x1, uint256 y1, uint256 x2, uint256 y2) external view returns (uint256 x3, uint256 y3);
    function isOnCurve(uint256 x, uint256 y) external pure returns (bool);
    function isInCorrectSubgroupAssumingOnCurve(uint256 x, uint256 y) external pure returns (bool);
    function computeLagrangeCoefficiants(uint256[] memory ids, uint256 threshold, uint256 numPeers)
        external
        pure
        returns (uint256[] memory coeffs);
    function scalarMul(uint256 scalar, uint256 x, uint256 y) external pure returns (uint256 x_res, uint256 y_res);
}

contract OprfKeyRegistry is Initializable, Ownable2StepUpgradeable, UUPSUpgradeable {
    using Types for Types.BabyJubJubElement;
    using Types for Types.Groth16Proof;
    using Types for Types.OprfPeer;
    using Types for Types.Round1Contribution;
    using Types for Types.OprfKeyGenState;
    // Gets set to ready state once OPRF participants are registered

    bool public isContractReady;

    // Admins to start KeyGens
    mapping(address => bool) public keygenAdmins;
    uint256 public amountKeygenAdmins;

    address public keyGenVerifier;
    IBabyJubJub public accumulator;
    uint256 public threshold;
    uint256 public numPeers;

    // The addresses of the currently participating peers.
    address[] public peerAddresses;
    // Maps the address of a peer to its party id.
    mapping(address => Types.OprfPeer) addressToPeer;

    // The keygen/reshare states for all OPRF key identifiers.
    mapping(uint160 => Types.OprfKeyGenState) internal runningKeyGens;

    // Mapping between each OPRF key identifier and the corresponding OPRF public-key.
    mapping(uint160 => Types.RegisteredOprfPublicKey) internal oprfKeyRegistry;

    // =============================================
    //                MODIFIERS
    // =============================================
    modifier isReady() {
        _isReady();
        _;
    }

    function _isReady() internal view {
        if (!isContractReady) revert NotReady();
    }

    modifier onlyAdmin() {
        _onlyAdmin();
        _;
    }

    function _onlyAdmin() internal view {
        if (!keygenAdmins[msg.sender]) revert OnlyAdmin();
    }

    modifier onlyInitialized() {
        _onlyInitialized();
        _;
    }

    function _onlyInitialized() internal view {
        if (_getInitializedVersion() == 0) {
            revert ImplementationNotInitialized();
        }
    }

    // =============================================
    //                Errors
    // =============================================
    error AlreadySubmitted();
    error BadContribution();
    error DeletedId(uint160 id);
    error ImplementationNotInitialized();
    error LastAdmin();
    error NotAParticipant();
    error NotAProducer();
    error NotReady();
    error OnlyAdmin();
    error OutdatedNullifier();
    error PartiesNotDistinct();
    error UnexpectedAmountPeers(uint256 expectedParties);
    error UnknownId(uint160 id);
    error UnsupportedNumPeersThreshold();
    error WrongRound();

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /// @notice Initializer function to set up the OprfKeyRegistry contract, this is not a constructor due to the use of upgradeable proxies.
    /// @param _keygenAdmin The address of the key generation administrator, only party that is allowed to start key generation processes.
    /// @param _keyGenVerifierAddress The address of the Groth16 verifier contract for key generation (needs to be compatible with threshold numPeers values).
    /// @param _accumulatorAddress The address of the BabyJubJub accumulator contract.
    /// @param _threshold The threshold number of peers required for key generation.
    /// @param _numPeers The number of peers participating in the key generation.
    function initialize(
        address _keygenAdmin,
        address _keyGenVerifierAddress,
        address _accumulatorAddress,
        uint256 _threshold,
        uint256 _numPeers
    ) public virtual initializer {
        __Ownable_init(msg.sender);
        __Ownable2Step_init();
        require(_numPeers < 1 << 16, "only supports party size up to 2^16");
        keygenAdmins[_keygenAdmin] = true;
        amountKeygenAdmins += 1;
        keyGenVerifier = _keyGenVerifierAddress;
        accumulator = IBabyJubJub(_accumulatorAddress);
        threshold = _threshold;
        numPeers = _numPeers;
        isContractReady = false;
    }

    // ==================================
    //         ADMIN FUNCTIONS
    // ==================================

    /// @notice Revokes the access of an admin (in case of key-loss or similar). In the long run we still want that this function is only callable with a threshold authentication, but for now we stick with admins being able to call this (this of course means one admin can block all others).
    //
    /// @param _keygenAdmin The admin address we want to revoke
    function revokeKeyGenAdmin(address _keygenAdmin) external virtual onlyProxy onlyInitialized onlyAdmin {
        // if the _keygenAdmin is an admin, we remove them
        if (keygenAdmins[_keygenAdmin]) {
            if (amountKeygenAdmins == 1) {
                // we don't allow the last admin to remove themselves
                revert LastAdmin();
            }
            delete keygenAdmins[_keygenAdmin];
            amountKeygenAdmins -= 1;
            emit Types.KeyGenAdminRevoked(_keygenAdmin);
        }
    }

    /// @notice Adds another admin address that is allowed to init/stop key-generations. In the long run we still want that this function is only callable with a threshold authentication, but for now we stick with admins being able to call this.
    /// @param _keygenAdmin The admin address we want to revoke
    function addKeyGenAdmin(address _keygenAdmin) external virtual onlyProxy onlyInitialized onlyAdmin {
        // if the _keygenAdmin is not yet an admin, we add them
        if (!keygenAdmins[_keygenAdmin]) {
            keygenAdmins[_keygenAdmin] = true;
            amountKeygenAdmins += 1;
            emit Types.KeyGenAdminRegistered(_keygenAdmin);
        }
    }

    /// @notice Registers the OPRF peers with their addresses and public keys. Only callable by the contract owner.
    // IMPORTANT: IF RE-REGISTERING, THE EXISTING PEERS NEED TO KEEP THEIR PARTY ID
    /// @param _peerAddresses An array of addresses of the OPRF peers.
    function registerOprfPeers(address[] calldata _peerAddresses) external virtual onlyProxy onlyInitialized onlyOwner {
        if (_peerAddresses.length != numPeers) revert UnexpectedAmountPeers(numPeers);
        // check that addresses are distinct
        for (uint256 i = 0; i < _peerAddresses.length; ++i) {
            for (uint256 j = i + 1; j < _peerAddresses.length; ++j) {
                if (_peerAddresses[i] == _peerAddresses[j]) {
                    revert PartiesNotDistinct();
                }
            }
        }
        // delete the old participants
        for (uint256 i = 0; i < peerAddresses.length; ++i) {
            delete addressToPeer[peerAddresses[i]];
        }
        // set the new ones
        for (uint16 i = 0; i < _peerAddresses.length; i++) {
            addressToPeer[_peerAddresses[i]] = Types.OprfPeer({isParticipant: true, partyId: i});
        }
        peerAddresses = _peerAddresses;
        isContractReady = true;
    }

    /// @notice Initializes the key generation process. Tries to use the provided oprfKeyId as identifier. If the identifier is already taken, reverts the transaction.
    /// @param oprfKeyId The unique identifier for the OPRF public-key.
    function initKeyGen(uint160 oprfKeyId) external virtual onlyProxy isReady onlyAdmin {
        // Check that this oprfKeyId was not used already
        Types.OprfKeyGenState storage st = runningKeyGens[oprfKeyId];
        if (st.exists) revert AlreadySubmitted();
        st.generatedEpoch = 0;
        st.round1 = new Types.Round1Contribution[](numPeers);
        st.round2 = new Types.SecretGenCiphertext[][](numPeers);
        for (uint256 i = 0; i < numPeers; i++) {
            st.round2[i] = new Types.SecretGenCiphertext[](numPeers);
        }
        st.shareCommitments = new Types.BabyJubJubElement[](numPeers);
        st.round2Done = new bool[](numPeers);
        st.round3Done = new bool[](numPeers);
        st.exists = true;

        // Emit Round1 event for everyone
        emit Types.SecretGenRound1(oprfKeyId, threshold);
    }

    /// @notice Initializes the reshare process for a given oprfKeyId. This method might either be used to re-randomize the shares of the MPC-nodes, switch out parties or regenerate the shares if one loses access to their shares.
    /// This method reuses the state from the last key-gen/re-share and deletes all old information.
    /// @param oprfKeyId The unique identifier for the OPRF public-key.
    function initReshare(uint160 oprfKeyId) external virtual onlyProxy isReady onlyAdmin {
        // Check that this oprfKeyId already exists
        Types.RegisteredOprfPublicKey storage oprfPublicKey = oprfKeyRegistry[oprfKeyId];
        if (_isEmpty(oprfPublicKey.key)) revert UnknownId(oprfKeyId);
        // Get the key-gen state for this key and reset everything
        Types.OprfKeyGenState storage st = runningKeyGens[oprfKeyId];
        // we need to leave the share commitments to check the peers are using the correct input
        delete st.lagrangeCoeffs;
        delete st.numProducers;
        delete st.round2Done;
        delete st.round3Done;
        delete st.round2EventEmitted;
        delete st.round3EventEmitted;
        delete st.finalizeEventEmitted;
        st.lagrangeCoeffs = new uint256[](threshold);
        st.round1 = new Types.Round1Contribution[](numPeers);
        st.round2 = new Types.SecretGenCiphertext[][](numPeers);
        for (uint256 i = 0; i < numPeers; i++) {
            delete st.nodeRoles[peerAddresses[i]];
            st.round2[i] = new Types.SecretGenCiphertext[](numPeers);
        }
        st.round2Done = new bool[](numPeers);
        st.round3Done = new bool[](numPeers);
        st.generatedEpoch = oprfPublicKey.epoch + 1;

        // Emit Round1 event for everyone
        emit Types.ReshareRound1(oprfKeyId, threshold, st.generatedEpoch);
    }

    /// @notice Deletes the OPRF public-key and its associated material. Works during key-gen or afterwards.
    /// @param oprfKeyId The unique identifier for the OPRF public-key.
    function deleteOprfPublicKey(uint160 oprfKeyId) external virtual onlyProxy isReady onlyAdmin {
        // try to delete the runningKeyGen data
        Types.OprfKeyGenState storage st = runningKeyGens[oprfKeyId];
        bool needToEmitEvent = false;
        if (st.exists) {
            // delete all the material and set to deleted
            for (uint256 i = 0; i < numPeers; ++i) {
                delete st.nodeRoles[peerAddresses[i]];
            }
            delete st.lagrangeCoeffs;
            delete st.round1;
            delete st.round2;
            delete st.shareCommitments;
            delete st.keyAggregate;
            delete st.numProducers;
            delete st.round2Done;
            delete st.round3Done;
            delete st.round2EventEmitted;
            delete st.round3EventEmitted;
            delete st.finalizeEventEmitted;
            // mark the key-gen as deleted
            // we need this to prevent race conditions during the key-gen
            st.deleted = true;
            needToEmitEvent = true;
        }

        Types.RegisteredOprfPublicKey memory oprfPublicKey = oprfKeyRegistry[oprfKeyId];
        if (!_isEmpty(oprfPublicKey.key)) {
            // delete the created key
            delete oprfPublicKey;
            needToEmitEvent = true;
        }

        if (needToEmitEvent) {
            emit Types.KeyDeletion(oprfKeyId);
        }
    }

    // ==================================
    //        OPRF Peer FUNCTIONS
    // ==================================

    /// @notice Adds a Round 1 contribution to the key generation process. Only callable by registered OPRF peers.
    /// @param oprfKeyId The unique identifier for the key-gen.
    /// @param data The Round 1 contribution data. See `Types.Round1Contribution` for details.
    function addRound1KeyGenContribution(uint160 oprfKeyId, Types.Round1Contribution calldata data)
        external
        virtual
        onlyProxy
        isReady
    {
        // return the partyId if sender is really a participant
        uint16 partyId = _internParticipantCheck();
        // for key-gen everyone is a producer, therefore we check that all values are set and valid points
        _curveChecks(data.commShare);
        if (data.commCoeffs == 0) revert BadContribution();
        Types.OprfKeyGenState storage st = _addRound1Contribution(oprfKeyId, partyId, data);
        // check that this is a key-gen
        if (st.generatedEpoch != 0) {
            revert BadContribution();
        }
        st.nodeRoles[msg.sender] = Types.KeyGenRole.PRODUCER;
        st.numProducers += 1;
        // Add BabyJubJub Elements together and keep running total
        _addToAggregate(st.keyAggregate, data.commShare.x, data.commShare.y);
        // everyone is a producer therefore we wait for numPeers amount producers
        _tryEmitRound2Event(oprfKeyId, numPeers, st);
        // Emit the transaction confirmation
        emit Types.KeyGenConfirmation(oprfKeyId, partyId, 1, st.generatedEpoch);
    }

    /// @notice Adds a Round 1 contribution to the re-sharing process. Only callable by registered OPRF peers. This method does some more work than the basic key-gen.
    /// We need threshold many PRODUCERS, meaning those will do the re-sharing. Nevertheless, all other parties need to participate as CONSUMERS and provide an ephemeral public-key so that the producers can create the new shares for them, so at least round 1 needs contributions by all nodes.
    ///
    /// @param oprfKeyId The unique identifier for the key-gen.
    /// @param data The Round 1 contribution data. See `Types.Round1Contribution` for details.
    function addRound1ReshareContribution(uint160 oprfKeyId, Types.Round1Contribution calldata data)
        external
        virtual
        onlyProxy
        isReady
    {
        // as we need contributions from everyone we check the
        // return the partyId if sender is really a participant
        uint16 partyId = _internParticipantCheck();
        // in reshare we can have producers and consumers, therefore we don't need to enforce that commitments are non-zero
        Types.OprfKeyGenState storage st = _addRound1Contribution(oprfKeyId, partyId, data);
        // check that this is in fact a reshare
        if (st.generatedEpoch == 0) {
            revert BadContribution();
        }
        // check if someone wants to be a consumer
        bool isEmptyCommShare = _isEmpty(data.commShare);
        bool isEmptyCommCoeffs = data.commCoeffs == 0;
        if ((isEmptyCommShare && isEmptyCommCoeffs) || st.numProducers >= threshold) {
            // both are empty or we already have enough producers
            st.nodeRoles[msg.sender] = Types.KeyGenRole.CONSUMER;
            // as a consolation prize we at least refund some storage costs
            delete st.round1[partyId].commShare;
            delete st.round1[partyId].commCoeffs;
        } else if (isEmptyCommShare != isEmptyCommCoeffs) {
            // sanity check that someone doesn't try to only commit to one value
            revert BadContribution();
        } else {
            // both commitments are set and we still need more producers
            _curveChecks(data.commShare);
            // in contrast to key-gen we don't compute the running total, but we can check whether the commitments are correct from the previous reshare/key-gen.
            Types.BabyJubJubElement memory shouldCommitment = st.shareCommitments[partyId];
            if (!_isEqual(shouldCommitment, data.commShare)) {
                revert BadContribution();
            }
            st.nodeRoles[msg.sender] = Types.KeyGenRole.PRODUCER;
            st.numProducers += 1;
            // check if we are the last producer, then we can compute the lagrange coefficients
            if (st.numProducers == threshold) {
                // first get all producer ids
                // iterating over the peers in that order always returns the ids in ascending order. This is important because the contributions in round 2 will also be in this order.
                uint256[] memory ids = new uint256[](threshold);
                uint256 counter = 0;
                for (uint256 i = 0; i < numPeers; ++i) {
                    address peerAddress = peerAddresses[i];
                    if (Types.KeyGenRole.PRODUCER == st.nodeRoles[peerAddress]) {
                        ids[counter++] = addressToPeer[peerAddress].partyId;
                    }
                }
                // then compute the coefficients
                st.lagrangeCoeffs = accumulator.computeLagrangeCoefficiants(ids, threshold, numPeers);
            }
        }
        // we need a contribution from everyone but only threshold many producers. If we don't manage to find enough producers, we will emit an event so that the admin can intervene.
        _tryEmitRound2Event(oprfKeyId, threshold, st);
        // Emit the transaction confirmation
        emit Types.KeyGenConfirmation(oprfKeyId, partyId, 1, st.generatedEpoch);
    }

    /// @notice Adds a Round 2 contribution to the key generation process. Only callable by registered OPRF peers. Is the same for key-gen and reshare, with the small difference with how the commitments for next reshare are computed and that we need less producers for reshare.
    ///
    /// @param oprfKeyId The unique identifier for the key-gen.
    /// @param data The Round 2 contribution data. See `Types.Round2Contribution` for details.
    /// @dev This internally verifies the Groth16 proof provided in the contribution data to ensure it is constructed correctly.
    function addRound2Contribution(uint160 oprfKeyId, Types.Round2Contribution calldata data)
        external
        virtual
        onlyProxy
        isReady
    {
        // check that the contribution is complete
        if (data.ciphers.length != numPeers) revert BadContribution();
        // check that we started the key-gen for this OPRF public-key.
        Types.OprfKeyGenState storage st = runningKeyGens[oprfKeyId];
        if (!st.exists) revert UnknownId(oprfKeyId);
        // check if the OPRF public-key was deleted in the meantime
        if (st.deleted) revert DeletedId(oprfKeyId);
        // check that we are actually in round2
        if (!st.round2EventEmitted || st.round3EventEmitted) revert WrongRound();
        // return the partyId if sender is really a participant
        uint16 partyId = _internParticipantCheck();
        // check that this peer did not submit anything for this round
        if (st.round2Done[partyId]) revert AlreadySubmitted();
        // check that this peer is a producer for this round
        if (Types.KeyGenRole.PRODUCER != st.nodeRoles[msg.sender]) revert BadContribution();

        // everything looks good - push the ciphertexts
        // additionally accumulate all commitments for the parties to have the correct commitment during the reshare process.
        //
        // this differs if this is the initial key-gen or one of the reshares
        if (st.generatedEpoch == 0) {
            // for the key-gen we simply accumulate all commitments as the resulting shamir-share should have contributions from all parties -> just add all together
            for (uint256 i = 0; i < numPeers; ++i) {
                _curveChecks(data.ciphers[i].commitment);
                _addToAggregate(st.shareCommitments[i], data.ciphers[i].commitment.x, data.ciphers[i].commitment.y);
                st.round2[i][partyId] = data.ciphers[i];
            }
        } else {
            // for the reshare we need to use the lagrange coefficients as here the resulting shamir-share is shared with shamir sharing
            uint256 lagrange = st.lagrangeCoeffs[partyId];
            require(lagrange > 0, "SAFETY CHECK: this should never happen. This means there is a bug");
            for (uint256 i = 0; i < numPeers; ++i) {
                _curveChecks(data.ciphers[i].commitment);
                (uint256 x, uint256 y) =
                    accumulator.scalarMul(lagrange, data.ciphers[i].commitment.x, data.ciphers[i].commitment.y);
                _addToAggregate(st.shareCommitments[i], x, y);
                st.round2[i][partyId] = data.ciphers[i];
            }
        }
        // set the contribution to done
        st.round2Done[partyId] = true;

        // depending on key-gen or reshare a different amount of producers
        uint256 necessaryContributions = st.generatedEpoch == 0 ? numPeers : threshold;
        _tryEmitRound3Event(oprfKeyId, necessaryContributions, st);

        // last step verify the proof and potentially revert if proof fails

        // build the public input:
        // 1) PublicKey from sender (Affine Point Babyjubjub)
        // 2) Commitment to share (Affine Point Babyjubjub)
        // 3) Commitment to coeffs (Basefield Babyjubjub)
        // 4) Ciphertexts for peers (in this case 3 Basefield BabyJubJub)
        // 5) Commitments to plaintexts (in this case 3 Affine Points BabyJubJub)
        // 6) Degree (Basefield BabyJubJub)
        // 7) Public Keys from peers (in this case 3 Affine Points BabyJubJub)
        // 8) Nonces (in this case 3 Basefield BabyJubJub)

        // TODO this is currently hardcoded for 13 and 25 need to make this more generic later
        if (numPeers == 3 && threshold == 2) {
            IVerifierKeyGen13 keyGenVerifier13 = IVerifierKeyGen13(keyGenVerifier);

            uint256[PUBLIC_INPUT_LENGTH_KEYGEN_13] memory publicInputs;

            Types.BabyJubJubElement[] memory pubKeyList = _loadPeerPublicKeys(st);
            publicInputs[0] = pubKeyList[partyId].x;
            publicInputs[1] = pubKeyList[partyId].y;
            publicInputs[2] = st.round1[partyId].commShare.x;
            publicInputs[3] = st.round1[partyId].commShare.y;
            publicInputs[4] = st.round1[partyId].commCoeffs;
            publicInputs[5 + (numPeers * 3)] = threshold - 1;
            // peer keys
            for (uint256 i = 0; i < numPeers; ++i) {
                publicInputs[5 + i] = data.ciphers[i].cipher;
                publicInputs[5 + numPeers + (i * 2) + 0] = data.ciphers[i].commitment.x;
                publicInputs[5 + numPeers + (i * 2) + 1] = data.ciphers[i].commitment.y;
                publicInputs[5 + (numPeers * 3) + 1 + (i * 2) + 0] = pubKeyList[i].x;
                publicInputs[5 + (numPeers * 3) + 1 + (i * 2) + 1] = pubKeyList[i].y;
                publicInputs[5 + (numPeers * 5) + 1 + i] = data.ciphers[i].nonce;
            }
            // As last step we call the foreign contract and revert the whole transaction in case anything is wrong.
            keyGenVerifier13.verifyCompressedProof(data.compressedProof, publicInputs);
        } else if (numPeers == 5 && threshold == 3) {
            IVerifierKeyGen25 keyGenVerifier25 = IVerifierKeyGen25(keyGenVerifier);

            uint256[PUBLIC_INPUT_LENGTH_KEYGEN_25] memory publicInputs;

            Types.BabyJubJubElement[] memory pubKeyList = _loadPeerPublicKeys(st);
            publicInputs[0] = pubKeyList[partyId].x;
            publicInputs[1] = pubKeyList[partyId].y;
            publicInputs[2] = st.round1[partyId].commShare.x;
            publicInputs[3] = st.round1[partyId].commShare.y;
            publicInputs[4] = st.round1[partyId].commCoeffs;
            publicInputs[5 + (numPeers * 3)] = threshold - 1;
            // peer keys
            for (uint256 i = 0; i < numPeers; ++i) {
                publicInputs[5 + i] = data.ciphers[i].cipher;
                publicInputs[5 + numPeers + (i * 2) + 0] = data.ciphers[i].commitment.x;
                publicInputs[5 + numPeers + (i * 2) + 1] = data.ciphers[i].commitment.y;
                publicInputs[5 + (numPeers * 3) + 1 + (i * 2) + 0] = pubKeyList[i].x;
                publicInputs[5 + (numPeers * 3) + 1 + (i * 2) + 1] = pubKeyList[i].y;
                publicInputs[5 + (numPeers * 5) + 1 + i] = data.ciphers[i].nonce;
            }
            // As last step we call the foreign contract and revert the whole transaction in case anything is wrong.
            keyGenVerifier25.verifyCompressedProof(data.compressedProof, publicInputs);
        } else {
            revert UnsupportedNumPeersThreshold();
        }
        // Emit the transaction confirmation
        emit Types.KeyGenConfirmation(oprfKeyId, partyId, 2, st.generatedEpoch);
    }

    /// @notice Adds a Round 3 contribution to the key generation process. Only callable by registered OPRF peers. This is exactly the same process for key-gen and reshare because nodes just acknowledge that they received their ciphertexts.
    ///
    /// @param oprfKeyId The unique identifier for the OPRF public-key.
    /// @dev This does not require any calldata, as it is simply an acknowledgment from the peer that is is done.
    function addRound3Contribution(uint160 oprfKeyId) external virtual onlyProxy isReady {
        // check that we started the key-gen for this OPRF public-key.
        Types.OprfKeyGenState storage st = runningKeyGens[oprfKeyId];
        if (!st.exists) revert UnknownId(oprfKeyId);
        // check if the OPRF public-key was deleted in the meantime
        if (st.deleted) revert DeletedId(oprfKeyId);
        // check that we are actually in round3
        if (!st.round3EventEmitted || st.finalizeEventEmitted) revert NotReady();
        // return the partyId if sender is really a participant
        uint16 partyId = _internParticipantCheck();
        // check that this peer did not submit anything for this round
        if (st.round3Done[partyId]) revert AlreadySubmitted();
        st.round3Done[partyId] = true;

        if (allRound3Submitted(st)) {
            // We are done! Register the OPRF public-key and emit event!
            if (st.generatedEpoch == 0) {
                oprfKeyRegistry[oprfKeyId] = Types.RegisteredOprfPublicKey({key: st.keyAggregate, epoch: 0});
            } else {
                // we simply increase the current epoch
                oprfKeyRegistry[oprfKeyId].epoch = st.generatedEpoch;
            }

            emit Types.SecretGenFinalize(oprfKeyId, st.generatedEpoch);
            // cleanup all old data - we need to keep shareCommitments though otherwise we can't do reshares
            delete st.lagrangeCoeffs;
            delete st.round1;
            delete st.round2;
            delete st.keyAggregate;
            delete st.numProducers;
            delete st.generatedEpoch;
            delete st.round2Done;
            delete st.round3Done;
            // we keep the eventsEmitted and exists to prevent participants to double submit
            st.finalizeEventEmitted = true;
        }
        // Emit the transaction confirmation
        emit Types.KeyGenConfirmation(oprfKeyId, partyId, 3, st.generatedEpoch);
    }

    // ==================================
    //           HELPER FUNCTIONS
    // ==================================

    /// @notice Checks if the caller is a registered OPRF participant and returns their party ID.
    /// @return The party ID of the given participant if they are a registered participant.
    function getPartyIdForParticipant(address participant) external view virtual isReady onlyProxy returns (uint256) {
        Types.OprfPeer memory peer = addressToPeer[participant];
        if (!peer.isParticipant) revert NotAParticipant();
        return peer.partyId;
    }

    function _internParticipantCheck() internal view virtual returns (uint16) {
        Types.OprfPeer memory peer = addressToPeer[msg.sender];
        if (!peer.isParticipant) revert NotAParticipant();
        return peer.partyId;
    }

    /// @notice Checks if the caller is a registered OPRF participant and returns ALL the ephemeral public keys created in round 1 of the key gen identified by the provided oprfKeyId. This method will be called by the nodes during round 2. The producers will receive all ephemeral public keys in order to encrypt the recreated shares (of the shares). The consumers will receive an empty array - this signals them that they don't need to participate in this round and just wait until the producers are done with this round.
    /// @param oprfKeyId The unique identifier for the OPRF public-key.
    /// @return The ephemeral public keys generated in round 1 iff a producer. An empty array iff a consumer.
    function loadPeerPublicKeysForProducers(uint160 oprfKeyId)
        external
        view
        virtual
        isReady
        onlyProxy
        returns (Types.BabyJubJubElement[] memory)
    {
        // check if a participant
        Types.OprfPeer memory peer = addressToPeer[msg.sender];
        if (!peer.isParticipant) revert NotAParticipant();

        // check if there exists this key-gen
        Types.OprfKeyGenState storage st = runningKeyGens[oprfKeyId];
        if (!st.exists) revert UnknownId(oprfKeyId);
        // check if the key-gen was deleted
        if (st.deleted) revert DeletedId(oprfKeyId);
        // check if we are a producer
        if (Types.KeyGenRole.PRODUCER != st.nodeRoles[msg.sender]) {
            // we are not a producer -> return empty array
            return new Types.BabyJubJubElement[](0);
        }
        return _loadPeerPublicKeys(st);
    }

    /// @notice Checks if the caller is a registered OPRF participant and returns only the ephemeral public OF THE PRODUCERS. The producers encrypted all shares in the previous round with DHE, therefore the recipients need the producer's public-key. For simplicity, the producers also call this method to receive the public-keys (including their own).
    /// @param oprfKeyId The unique identifier for the OPRF public-key.
    /// @return The ephemeral public keys OF THE PRODUCERS generated in round 1
    function loadPeerPublicKeysForConsumers(uint160 oprfKeyId)
        external
        view
        virtual
        isReady
        onlyProxy
        returns (Types.BabyJubJubElement[] memory)
    {
        // check if a participant
        Types.OprfPeer memory peer = addressToPeer[msg.sender];
        if (!peer.isParticipant) revert NotAParticipant();

        // check if there exists this key-gen
        Types.OprfKeyGenState storage st = runningKeyGens[oprfKeyId];
        if (!st.exists) revert UnknownId(oprfKeyId);
        // check if the key-gen was deleted
        if (st.deleted) revert DeletedId(oprfKeyId);
        // load the producer's keys for decryption
        return _loadProducerPeerPublicKeys(st);
    }

    /// @notice Checks if the caller is a registered OPRF participant and returns their Round 2 ciphertexts for the specified key-gen.
    /// @param oprfKeyId The unique identifier for the OPRF public-key.
    /// @return An array of Round 2 ciphertexts belonging to the caller.
    function checkIsParticipantAndReturnRound2Ciphers(uint160 oprfKeyId)
        external
        view
        virtual
        onlyProxy
        isReady
        returns (Types.SecretGenCiphertext[] memory)
    {
        // check if a participant
        Types.OprfPeer memory peer = addressToPeer[msg.sender];
        if (!peer.isParticipant) revert NotAParticipant();
        // check if there exists this a key-gen
        Types.OprfKeyGenState storage st = runningKeyGens[oprfKeyId];
        if (!st.exists) revert UnknownId(oprfKeyId);
        // check if the key-gen was deleted
        if (st.deleted) revert DeletedId(oprfKeyId);
        // check that round2 ciphers are finished
        if (!st.round2EventEmitted) revert NotReady();
        if (st.generatedEpoch == 0) {
            // this is a key-gen so just send all ciphers
            return st.round2[peer.partyId];
        } else {
            // this is a reshare -> find the contributions by the producers
            Types.SecretGenCiphertext[] memory ciphers = new Types.SecretGenCiphertext[](threshold);
            uint256 counter = 0;
            for (uint256 i = 0; i < numPeers; ++i) {
                if (Types.KeyGenRole.PRODUCER == st.nodeRoles[peerAddresses[i]]) {
                    ciphers[counter++] = st.round2[peer.partyId][i];
                }
            }
            return ciphers;
        }
    }

    /// @notice Retrieves the specified OPRF public-key.
    /// @param oprfKeyId The unique identifier for the OPRF public-key.
    /// @return The BabyJubJub element representing the nullifier public key.
    function getOprfPublicKey(uint160 oprfKeyId)
        public
        view
        virtual
        onlyProxy
        isReady
        returns (Types.BabyJubJubElement memory)
    {
        Types.RegisteredOprfPublicKey storage oprfPublicKey = oprfKeyRegistry[oprfKeyId];
        if (_isEmpty(oprfPublicKey.key)) revert UnknownId(oprfKeyId);
        return oprfPublicKey.key;
    }

    /// @notice Retrieves the specified OPRF public-key along with its current epoch.
    /// @param oprfKeyId The unique identifier for the OPRF public-key.
    /// @return The BabyJubJub element representing the nullifier public key and the current epoch.
    function getOprfPublicKeyAndEpoch(uint160 oprfKeyId)
        public
        view
        virtual
        onlyProxy
        isReady
        returns (Types.RegisteredOprfPublicKey memory)
    {
        Types.RegisteredOprfPublicKey storage oprfPublicKey = oprfKeyRegistry[oprfKeyId];
        if (_isEmpty(oprfPublicKey.key)) revert UnknownId(oprfKeyId);
        return oprfPublicKey;
    }

    function allRound1Submitted(Types.OprfKeyGenState storage st) internal view virtual returns (bool) {
        for (uint256 i = 0; i < numPeers; ++i) {
            if (Types.KeyGenRole.NOT_READY == st.nodeRoles[peerAddresses[i]]) {
                return false;
            }
        }
        return true;
    }

    function allProducersRound2Submitted(uint256 necessaryProducers, Types.OprfKeyGenState storage st)
        internal
        view
        virtual
        returns (bool)
    {
        uint256 submissions = 0;
        for (uint256 i = 0; i < numPeers; ++i) {
            if (st.round2Done[i]) submissions += 1;
        }
        return submissions == necessaryProducers;
    }

    function allRound3Submitted(Types.OprfKeyGenState storage st) internal view virtual returns (bool) {
        for (uint256 i = 0; i < numPeers; ++i) {
            if (!st.round3Done[i]) return false;
        }
        return true;
    }

    function _addRound1Contribution(uint160 oprfKeyId, uint256 partyId, Types.Round1Contribution calldata data)
        private
        returns (Types.OprfKeyGenState storage)
    {
        _curveChecks(data.ephPubKey);
        // check that we started the key-gen for this OPRF public-key
        Types.OprfKeyGenState storage st = runningKeyGens[oprfKeyId];
        if (!st.exists) revert UnknownId(oprfKeyId);
        // check if the OPRF public-key was deleted in the meantime
        if (st.deleted) revert DeletedId(oprfKeyId);
        if (st.round2EventEmitted) revert WrongRound();

        // check that we don't have double submission
        if (!_isEmpty(st.round1[partyId].commShare)) revert AlreadySubmitted();
        st.round1[partyId] = data;
        return st;
    }

    function _loadPeerPublicKeys(Types.OprfKeyGenState storage st)
        internal
        view
        returns (Types.BabyJubJubElement[] memory)
    {
        if (!st.round2EventEmitted) revert WrongRound();
        Types.BabyJubJubElement[] memory pubKeyList = new Types.BabyJubJubElement[](numPeers);
        for (uint256 i = 0; i < numPeers; ++i) {
            pubKeyList[i] = st.round1[i].ephPubKey;
        }
        return pubKeyList;
    }

    function _loadProducerPeerPublicKeys(Types.OprfKeyGenState storage st)
        internal
        view
        returns (Types.BabyJubJubElement[] memory)
    {
        if (!st.round2EventEmitted) revert WrongRound();
        Types.BabyJubJubElement[] memory pubKeyList = new Types.BabyJubJubElement[](st.numProducers);
        uint256 counter = 0;
        for (uint256 i = 0; i < numPeers; ++i) {
            if (Types.KeyGenRole.PRODUCER == st.nodeRoles[peerAddresses[i]]) {
                pubKeyList[counter++] = st.round1[i].ephPubKey;
            }
        }
        return pubKeyList;
    }

    function _tryEmitRound2Event(uint160 oprfKeyId, uint256 necessaryContributions, Types.OprfKeyGenState storage st)
        internal
        virtual
    {
        if (st.round2EventEmitted) return;
        if (!allRound1Submitted(st)) return;
        if (st.numProducers < necessaryContributions) {
            emit Types.NotEnoughProducers(oprfKeyId);
            st.round2EventEmitted = true;
        }

        st.round2EventEmitted = true;
        // delete the old commitments now
        delete st.shareCommitments;
        st.shareCommitments = new Types.BabyJubJubElement[](numPeers);
        emit Types.SecretGenRound2(oprfKeyId, st.generatedEpoch);
    }

    function _tryEmitRound3Event(uint160 oprfKeyId, uint256 necessaryContributions, Types.OprfKeyGenState storage st)
        internal
        virtual
    {
        if (st.round3EventEmitted) return;
        if (!allProducersRound2Submitted(necessaryContributions, st)) return;

        st.round3EventEmitted = true;
        if (st.generatedEpoch == 0) {
            emit Types.SecretGenRound3(oprfKeyId);
        } else {
            emit Types.ReshareRound3(oprfKeyId, st.lagrangeCoeffs, st.generatedEpoch);
        }
    }

    // Expects that callsite enforces that point is on the curve and in the correct sub-group (i.e. call _curveCheck).
    function _addToAggregate(Types.BabyJubJubElement storage keyAggregate, uint256 newPointX, uint256 newPointY)
        internal
        virtual
    {
        if (_isEmpty(keyAggregate)) {
            // We checked above that the point is on curve, so we can just set it
            keyAggregate.x = newPointX;
            keyAggregate.y = newPointY;
            return;
        }

        // we checked above that the new point is on curve
        // the initial aggregate is on curve as well, checked inside the if above
        // induction: sum of two on-curve points is on-curve, so the result is on-curve as well
        (uint256 resultX, uint256 resultY) = accumulator.add(keyAggregate.x, keyAggregate.y, newPointX, newPointY);

        keyAggregate.x = resultX;
        keyAggregate.y = resultY;
    }

    function _isEqual(Types.BabyJubJubElement memory lhs, Types.BabyJubJubElement memory rhs)
        internal
        pure
        virtual
        returns (bool)
    {
        return lhs.x == rhs.x && lhs.y == rhs.y;
    }

    function _isInfinity(Types.BabyJubJubElement memory element) internal pure virtual returns (bool) {
        return element.x == 0 && element.y == 1;
    }

    function _isEmpty(Types.BabyJubJubElement memory element) internal pure virtual returns (bool) {
        return element.x == 0 && element.y == 0;
    }

    /// Performs sanity checks on BabyJubJub elements. If either the point
    ///     * is the identity
    ///     * is not on the curve
    ///     * is not in the large sub-group
    ///
    /// this method will revert the call.
    function _curveChecks(Types.BabyJubJubElement memory element) internal view virtual {
        uint256 x = element.x;
        uint256 y = element.y;
        if (
            _isInfinity(element) || !accumulator.isOnCurve(x, y)
                || !accumulator.isInCorrectSubgroupAssumingOnCurve(x, y)
        ) {
            revert BadContribution();
        }
    }
    ////////////////////////////////////////////////////////////
    //                    Upgrade Authorization               //
    ////////////////////////////////////////////////////////////

    /**
     *
     *
     * @dev Authorize upgrade to a new implementation
     *
     *
     * @param newImplementation Address of the new implementation contract
     *
     *
     * @notice Only the contract owner can authorize upgrades
     *
     *
     */
    function _authorizeUpgrade(address newImplementation) internal virtual override onlyOwner {}

    ////////////////////////////////////////////////////////////
    //                    Storage Gap                         //
    ////////////////////////////////////////////////////////////

    /**
     *
     *
     * @dev Storage gap to allow for future upgrades without storage collisions
     *
     *
     * This is set to take a total of 50 storage slots for future state variables
     *
     *
     */
    uint256[40] private __gap;
}
