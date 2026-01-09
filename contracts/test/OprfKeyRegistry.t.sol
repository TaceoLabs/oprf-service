// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {OprfKeyRegistry} from "../src/OprfKeyRegistry.sol";
import {BabyJubJub} from "../src/BabyJubJub.sol";
import {Verifier as VerifierKeyGen13} from "../src/VerifierKeyGen13.sol";
import {Types} from "../src/Types.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

contract OprfKeyRegistryTest is Test {
    using Types for Types.BabyJubJubElement;

    uint256 public constant THRESHOLD = 2;
    uint256 public constant MAX_PEERS = 3;

    OprfKeyRegistry public oprfKeyRegistry;
    BabyJubJub public accumulator;
    VerifierKeyGen13 public verifierKeyGen;
    ERC1967Proxy public proxy;

    address alice = address(0x1);
    address bob = address(0x2);
    address carol = address(0x3);
    address taceoAdmin = address(0x4);

    uint256 privateKeyAlice = 0x3bc78294cae1fe9e441b3c6a97fc4f7844b016ec9deb28787b2ec8a63812834;
    uint256 privateKeyBob = 0xb5aaa322223b7015e0ab2690ddad24a3e553bbea711dcdd0f30e2ea2ca6fdc;
    uint256 privateKeyCarol = 0x379ca5cd47470da7bcefb954d86cf4d409d25dd2d65c4e2280aa2bcfc4f1f4d;

    Types.BabyJubJubElement publicKeyAlice = Types.BabyJubJubElement({
        x: 0x1583c671e97dd91df79d8c5b311d452a3eec14932c89d9cff0364d5b98ef215e,
        y: 0x3f5c610720cfa296066965732468ea34a8f7e3725899e1b4470c6b5a76321a3
    });

    Types.BabyJubJubElement publicKeyBob = Types.BabyJubJubElement({
        x: 0x35ed813d62de4efaec2090398ec8f221801a5d6937e71583455587971f82372,
        y: 0xa9764b67db417148efa93189bc63edecad9416e5923f985233f439fe53d4368
    });

    Types.BabyJubJubElement publicKeyCarol = Types.BabyJubJubElement({
        x: 0x3bb75e80a39e8afcee4f396477440968975a58b1a5f2222f48e7895bf4d5537,
        y: 0x2d21805332ed46c9a5b57834e87c0395bc07a7c4ded911184427cc0c1cae8e37
    });

    uint256 commCoeffsAlice = 0x6fc7aa21491e4b6878290f06958efa50de23e427d7b4f17b49b8da6191ad41f;

    uint256 commCoeffsBob = 0x84292791fef8a2de0d2617e877fe8769bf81df0848ac54c1a02ea84289a2d0c;

    uint256 commCoeffsCarol = 0x1cf1e6e4f9f4aa29430a9b08d51584f3194571178c0dde3f8d2edfef28cc2dac;

    Types.BabyJubJubElement commShareAlice = Types.BabyJubJubElement({
        x: 0x1713acbc11e0f0fdaebbcedceed52e57abf30f2b8c435f013ce0756e4377f097,
        y: 0x28145c47c630ed060a7f10ea3d727b9bc0d249796172c2bcb58b836d1e3d4bd4
    });

    Types.BabyJubJubElement commShareBob = Types.BabyJubJubElement({
        x: 0x23c80416edd379bde086351fc0169cfa69adff2c0f0ab04ca9622b099e597489,
        y: 0x130cf58590a10bdf2b75d0533cb5911d0fe86cfd27187eb77e42cc5719cb7124
    });

    Types.BabyJubJubElement commShareCarol = Types.BabyJubJubElement({
        x: 0x278da9b32323bf8afa691001d5d20e2c5f96db21b18a2e22f28e5d5742992232,
        y: 0x2cf9744859cdd3d29fd15057b7e3ebd2197a1af0bae650e5e40bfcd437dfd299
    });

    function setUp() public {
        accumulator = new BabyJubJub();
        verifierKeyGen = new VerifierKeyGen13();
        // Deploy implementation
        OprfKeyRegistry implementation = new OprfKeyRegistry();
        // Encode initializer call
        bytes memory initData = abi.encodeWithSelector(
            OprfKeyRegistry.initialize.selector, taceoAdmin, verifierKeyGen, accumulator, THRESHOLD, MAX_PEERS
        );
        // Deploy proxy
        proxy = new ERC1967Proxy(address(implementation), initData);
        oprfKeyRegistry = OprfKeyRegistry(address(proxy));

        // register participants for runs later
        address[] memory peerAddresses = new address[](3);
        peerAddresses[0] = alice;
        peerAddresses[1] = bob;
        peerAddresses[2] = carol;
        oprfKeyRegistry.registerOprfPeers(peerAddresses);
    }

    function testConstructedCorrectly() public {
        // Deploy implementation
        OprfKeyRegistry implementation = new OprfKeyRegistry();
        // Encode initializer call
        bytes memory initData = abi.encodeWithSelector(
            OprfKeyRegistry.initialize.selector, taceoAdmin, verifierKeyGen, accumulator, THRESHOLD, MAX_PEERS
        );
        // Deploy proxy
        ERC1967Proxy proxyTest = new ERC1967Proxy(address(implementation), initData);
        OprfKeyRegistry oprfKeyRegistryTest = OprfKeyRegistry(address(proxyTest));

        assert(oprfKeyRegistryTest.keygenAdmins(taceoAdmin));
        assertEq(address(oprfKeyRegistryTest.keyGenVerifier()), address(verifierKeyGen));
        assertEq(oprfKeyRegistryTest.threshold(), 2);
        assertEq(oprfKeyRegistryTest.numPeers(), 3);
        assert(!oprfKeyRegistryTest.isContractReady());

        // TODO call other functions to check that it reverts correctly
    }

    function testRegisterParticipants() public {
        // Deploy implementation
        OprfKeyRegistry implementation = new OprfKeyRegistry();
        // Encode initializer call
        bytes memory initData = abi.encodeWithSelector(
            OprfKeyRegistry.initialize.selector, taceoAdmin, verifierKeyGen, accumulator, THRESHOLD, MAX_PEERS
        );
        // Deploy proxy
        ERC1967Proxy proxyTest = new ERC1967Proxy(address(implementation), initData);
        OprfKeyRegistry oprfKeyRegistryTest = OprfKeyRegistry(address(proxyTest));

        address[] memory peerAddresses = new address[](3);
        peerAddresses[0] = alice;
        peerAddresses[1] = bob;
        peerAddresses[2] = carol;

        // check that not ready
        assert(!oprfKeyRegistryTest.isContractReady());
        oprfKeyRegistryTest.registerOprfPeers(peerAddresses);

        // check that ready after call
        assert(oprfKeyRegistryTest.isContractReady());

        // check that parties can read their partyID
        vm.prank(alice);
        uint256 aliceId = oprfKeyRegistryTest.getPartyIdForParticipant(alice);
        assertEq(aliceId, 0);
        vm.stopPrank();

        vm.prank(bob);
        uint256 bobId = oprfKeyRegistryTest.getPartyIdForParticipant(bob);
        assertEq(bobId, 1);
        vm.stopPrank();

        vm.prank(carol);
        uint256 carolId = oprfKeyRegistryTest.getPartyIdForParticipant(carol);
        assertEq(carolId, 2);
        vm.stopPrank();

        // check that taceo is not a participant
        vm.prank(taceoAdmin);
        vm.expectRevert(abi.encodeWithSelector(OprfKeyRegistry.NotAParticipant.selector));
        oprfKeyRegistryTest.getPartyIdForParticipant(taceoAdmin);
        vm.stopPrank();
    }

    function testRegisterParticipantsNotTACEO() public {
        // Deploy implementation
        OprfKeyRegistry implementation = new OprfKeyRegistry();
        // Encode initializer call
        bytes memory initData = abi.encodeWithSelector(
            OprfKeyRegistry.initialize.selector, taceoAdmin, verifierKeyGen, accumulator, THRESHOLD, MAX_PEERS
        );
        // Deploy proxy
        ERC1967Proxy proxyTest = new ERC1967Proxy(address(implementation), initData);
        OprfKeyRegistry oprfKeyRegistryTest = OprfKeyRegistry(address(proxyTest));

        address[] memory peerAddresses = new address[](3);
        peerAddresses[0] = alice;
        peerAddresses[1] = bob;
        peerAddresses[2] = carol;
        // check that not ready
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, alice));
        oprfKeyRegistryTest.registerOprfPeers(peerAddresses);
    }

    function testRegisterParticipantsNotDistinct() public {
        // Deploy implementation
        OprfKeyRegistry implementation = new OprfKeyRegistry();
        // Encode initializer call
        bytes memory initData = abi.encodeWithSelector(
            OprfKeyRegistry.initialize.selector, taceoAdmin, verifierKeyGen, accumulator, THRESHOLD, MAX_PEERS
        );
        // Deploy proxy
        ERC1967Proxy proxyTest = new ERC1967Proxy(address(implementation), initData);
        OprfKeyRegistry oprfKeyRegistryTest = OprfKeyRegistry(address(proxyTest));

        address[] memory peerAddresses = new address[](3);
        peerAddresses[0] = alice;
        peerAddresses[1] = bob;
        peerAddresses[2] = alice;

        // check that not ready
        assert(!oprfKeyRegistryTest.isContractReady());
        vm.expectRevert(abi.encodeWithSelector(OprfKeyRegistry.PartiesNotDistinct.selector));
        oprfKeyRegistryTest.registerOprfPeers(peerAddresses);
    }

    function testUpdateParticipants() public {
        // check the partyIDs
        vm.prank(alice);
        assertEq(oprfKeyRegistry.getPartyIdForParticipant(alice), 0);
        vm.stopPrank();

        vm.prank(bob);
        assertEq(oprfKeyRegistry.getPartyIdForParticipant(bob), 1);
        vm.stopPrank();

        vm.prank(carol);
        assertEq(oprfKeyRegistry.getPartyIdForParticipant(carol), 2);
        vm.stopPrank();

        address[] memory peerAddresses = new address[](3);
        peerAddresses[0] = bob;
        peerAddresses[1] = carol;
        peerAddresses[2] = taceoAdmin;

        // update
        oprfKeyRegistry.registerOprfPeers(peerAddresses);

        vm.prank(bob);
        assertEq(oprfKeyRegistry.getPartyIdForParticipant(bob), 0);
        vm.stopPrank();

        vm.prank(carol);
        assertEq(oprfKeyRegistry.getPartyIdForParticipant(carol), 1);
        vm.stopPrank();

        vm.prank(taceoAdmin);
        assertEq(oprfKeyRegistry.getPartyIdForParticipant(taceoAdmin), 2);
        vm.stopPrank();

        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(OprfKeyRegistry.NotAParticipant.selector));
        oprfKeyRegistry.getPartyIdForParticipant(alice);
        vm.stopPrank();
    }

    function testRegisterParticipantsWrongNumberKeys() public {
        // Deploy implementation
        OprfKeyRegistry implementation = new OprfKeyRegistry();
        // Encode initializer call
        bytes memory initData = abi.encodeWithSelector(
            OprfKeyRegistry.initialize.selector, taceoAdmin, verifierKeyGen, accumulator, THRESHOLD, MAX_PEERS
        );
        // Deploy proxy
        ERC1967Proxy proxyTest = new ERC1967Proxy(address(implementation), initData);
        OprfKeyRegistry oprfKeyRegistryTest = OprfKeyRegistry(address(proxyTest));

        address[] memory peerAddressesWrong = new address[](2);
        peerAddressesWrong[0] = alice;
        peerAddressesWrong[1] = bob;

        vm.expectRevert(abi.encodeWithSelector(OprfKeyRegistry.UnexpectedAmountPeers.selector, 3));
        oprfKeyRegistryTest.registerOprfPeers(peerAddressesWrong);
    }

    function testInitKeyGenRevokeRegisterAdmin() public {
        vm.startPrank(taceoAdmin);
        // register another admin
        vm.expectEmit(true, true, true, true);
        emit Types.KeyGenAdminRegistered(alice);
        oprfKeyRegistry.addKeyGenAdmin(alice);
        assertEq(2, oprfKeyRegistry.amountKeygenAdmins());

        // revoke taceo
        vm.expectEmit(true, true, true, true);
        emit Types.KeyGenAdminRevoked(taceoAdmin);
        oprfKeyRegistry.revokeKeyGenAdmin(taceoAdmin);
        assertEq(1, oprfKeyRegistry.amountKeygenAdmins());

        // try start key-gen as taceo
        vm.expectRevert(abi.encodeWithSelector(OprfKeyRegistry.OnlyAdmin.selector));
        oprfKeyRegistry.initKeyGen(0);
        vm.stopPrank();

        // start key-gen as alice
        vm.prank(alice);
        oprfKeyRegistry.initKeyGen(0);
        vm.stopPrank();
    }

    function testRevokeLastAdmin() public {
        vm.startPrank(taceoAdmin);
        // register another admin
        vm.expectRevert(abi.encodeWithSelector(OprfKeyRegistry.LastAdmin.selector));
        oprfKeyRegistry.revokeKeyGenAdmin(taceoAdmin);
        assertEq(1, oprfKeyRegistry.amountKeygenAdmins());
        vm.stopPrank();
    }

    function testRevokeAdminThatIsNoAdmin() public {
        vm.startPrank(taceoAdmin);
        vm.recordLogs();
        oprfKeyRegistry.revokeKeyGenAdmin(alice);
        assertEq(1, oprfKeyRegistry.amountKeygenAdmins());
        vm.stopPrank();
        assertEq(0, vm.getRecordedLogs().length);
    }

    function testRegisterAdminTwice() public {
        vm.startPrank(taceoAdmin);
        vm.recordLogs();
        oprfKeyRegistry.addKeyGenAdmin(taceoAdmin);
        assertEq(1, oprfKeyRegistry.amountKeygenAdmins());
        vm.stopPrank();
        assertEq(0, vm.getRecordedLogs().length);
    }

    function testInitKeyGenResubmit() public {
        vm.prank(taceoAdmin);
        oprfKeyRegistry.initKeyGen(0);
        vm.expectRevert(abi.encodeWithSelector(OprfKeyRegistry.AlreadySubmitted.selector));
        vm.prank(taceoAdmin);
        oprfKeyRegistry.initKeyGen(0);
    }

    function testDeleteBeforeRound1() public {
        uint160 oprfKeyId = 42;
        vm.prank(taceoAdmin);
        vm.expectEmit(true, true, true, true);
        emit Types.SecretGenRound1(oprfKeyId, THRESHOLD);
        oprfKeyRegistry.initKeyGen(oprfKeyId);
        vm.stopPrank();
        vm.prank(taceoAdmin);
        // now delete
        vm.expectEmit(true, true, true, true);
        emit Types.KeyDeletion(oprfKeyId);
        oprfKeyRegistry.deleteOprfPublicKey(oprfKeyId);
        vm.stopPrank();

        // check that we can add round1 but nothing happens
        // do round 1 contributions
        vm.prank(bob);
        vm.expectRevert(abi.encodeWithSelector(OprfKeyRegistry.DeletedId.selector, oprfKeyId));
        oprfKeyRegistry.addRound1KeyGenContribution(
            oprfKeyId,
            Types.Round1Contribution({commShare: commShareBob, commCoeffs: commCoeffsBob, ephPubKey: publicKeyBob})
        );
        vm.stopPrank();

        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(OprfKeyRegistry.DeletedId.selector, oprfKeyId));
        oprfKeyRegistry.loadPeerPublicKeysForProducers(oprfKeyId);
        vm.stopPrank();

        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(OprfKeyRegistry.DeletedId.selector, oprfKeyId));
        oprfKeyRegistry.checkIsParticipantAndReturnRound2Ciphers(oprfKeyId);
        vm.stopPrank();
    }

    function testDeleteDuringRound1() public {
        uint160 oprfKeyId = 42;
        vm.prank(taceoAdmin);
        vm.expectEmit(true, true, true, true);
        emit Types.SecretGenRound1(oprfKeyId, THRESHOLD);
        oprfKeyRegistry.initKeyGen(oprfKeyId);
        vm.stopPrank();

        // check that we can add round1 but nothing happens
        // do round 1 contributions
        vm.prank(bob);
        vm.expectEmit(true, true, true, true);
        emit Types.KeyGenConfirmation(oprfKeyId, 1, 1, 0);
        oprfKeyRegistry.addRound1KeyGenContribution(
            oprfKeyId,
            Types.Round1Contribution({commShare: commShareBob, commCoeffs: commCoeffsBob, ephPubKey: publicKeyBob})
        );
        vm.stopPrank();

        vm.prank(taceoAdmin);
        // now delete
        vm.expectEmit(true, true, true, true);
        emit Types.KeyDeletion(oprfKeyId);
        oprfKeyRegistry.deleteOprfPublicKey(oprfKeyId);
        vm.stopPrank();

        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(OprfKeyRegistry.DeletedId.selector, oprfKeyId));
        oprfKeyRegistry.addRound1KeyGenContribution(
            oprfKeyId,
            Types.Round1Contribution({
                commShare: commShareAlice, commCoeffs: commCoeffsAlice, ephPubKey: publicKeyAlice
            })
        );
        vm.stopPrank();

        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(OprfKeyRegistry.DeletedId.selector, oprfKeyId));
        oprfKeyRegistry.loadPeerPublicKeysForProducers(oprfKeyId);
        vm.stopPrank();

        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(OprfKeyRegistry.DeletedId.selector, oprfKeyId));
        oprfKeyRegistry.checkIsParticipantAndReturnRound2Ciphers(oprfKeyId);
        vm.stopPrank();
    }

    function testDeleteDuringRound2() public {
        uint160 oprfKeyId = 42;
        vm.prank(taceoAdmin);
        vm.expectEmit(true, true, true, true);
        emit Types.SecretGenRound1(oprfKeyId, THRESHOLD);
        oprfKeyRegistry.initKeyGen(oprfKeyId);
        vm.stopPrank();

        // do round 1 contributions
        vm.prank(bob);
        vm.expectEmit(true, true, true, true);
        emit Types.KeyGenConfirmation(oprfKeyId, 1, 1, 0);
        oprfKeyRegistry.addRound1KeyGenContribution(
            oprfKeyId,
            Types.Round1Contribution({commShare: commShareBob, commCoeffs: commCoeffsBob, ephPubKey: publicKeyBob})
        );
        vm.stopPrank();

        vm.prank(alice);
        vm.expectEmit(true, true, true, true);
        emit Types.KeyGenConfirmation(oprfKeyId, 0, 1, 0);
        oprfKeyRegistry.addRound1KeyGenContribution(
            oprfKeyId,
            Types.Round1Contribution({
                commShare: commShareAlice, commCoeffs: commCoeffsAlice, ephPubKey: publicKeyAlice
            })
        );
        vm.stopPrank();

        vm.prank(carol);
        vm.expectEmit(true, true, true, true);
        emit Types.KeyGenConfirmation(oprfKeyId, 2, 1, 0);
        oprfKeyRegistry.addRound1KeyGenContribution(
            oprfKeyId,
            Types.Round1Contribution({
                commShare: commShareCarol, commCoeffs: commCoeffsCarol, ephPubKey: publicKeyCarol
            })
        );
        vm.stopPrank();

        vm.prank(bob);
        vm.expectEmit(true, true, true, true);
        emit Types.KeyGenConfirmation(oprfKeyId, 1, 2, 0);
        oprfKeyRegistry.addRound2Contribution(oprfKeyId, bobRound2Contribution());
        vm.stopPrank();

        vm.prank(taceoAdmin);
        // now delete
        vm.expectEmit(true, true, true, true);
        emit Types.KeyDeletion(oprfKeyId);
        oprfKeyRegistry.deleteOprfPublicKey(oprfKeyId);
        vm.stopPrank();

        vm.recordLogs();
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(OprfKeyRegistry.DeletedId.selector, oprfKeyId));
        oprfKeyRegistry.addRound2Contribution(oprfKeyId, aliceRound2Contribution());
        vm.stopPrank();

        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(OprfKeyRegistry.DeletedId.selector, oprfKeyId));
        oprfKeyRegistry.loadPeerPublicKeysForProducers(oprfKeyId);
        vm.stopPrank();

        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(OprfKeyRegistry.DeletedId.selector, oprfKeyId));
        oprfKeyRegistry.checkIsParticipantAndReturnRound2Ciphers(oprfKeyId);
        vm.stopPrank();
    }

    function testDeleteDuringRound3() public {
        uint160 oprfKeyId = 42;
        vm.prank(taceoAdmin);
        vm.expectEmit(true, true, true, true);
        emit Types.SecretGenRound1(oprfKeyId, THRESHOLD);
        oprfKeyRegistry.initKeyGen(oprfKeyId);
        vm.stopPrank();

        // do round 1 contributions
        vm.prank(bob);
        vm.expectEmit(true, true, true, true);
        emit Types.KeyGenConfirmation(oprfKeyId, 1, 1, 0);
        oprfKeyRegistry.addRound1KeyGenContribution(
            oprfKeyId,
            Types.Round1Contribution({commShare: commShareBob, commCoeffs: commCoeffsBob, ephPubKey: publicKeyBob})
        );
        vm.stopPrank();

        vm.prank(alice);
        vm.expectEmit(true, true, true, true);
        emit Types.KeyGenConfirmation(oprfKeyId, 0, 1, 0);
        oprfKeyRegistry.addRound1KeyGenContribution(
            oprfKeyId,
            Types.Round1Contribution({
                commShare: commShareAlice, commCoeffs: commCoeffsAlice, ephPubKey: publicKeyAlice
            })
        );
        vm.stopPrank();

        vm.prank(carol);
        vm.expectEmit(true, true, true, true);
        emit Types.KeyGenConfirmation(oprfKeyId, 2, 1, 0);
        oprfKeyRegistry.addRound1KeyGenContribution(
            oprfKeyId,
            Types.Round1Contribution({
                commShare: commShareCarol, commCoeffs: commCoeffsCarol, ephPubKey: publicKeyCarol
            })
        );
        vm.stopPrank();

        vm.prank(bob);
        vm.expectEmit(true, true, true, true);
        emit Types.KeyGenConfirmation(oprfKeyId, 1, 2, 0);
        oprfKeyRegistry.addRound2Contribution(oprfKeyId, bobRound2Contribution());
        vm.stopPrank();

        vm.prank(alice);
        vm.expectEmit(true, true, true, true);
        emit Types.KeyGenConfirmation(oprfKeyId, 0, 2, 0);
        oprfKeyRegistry.addRound2Contribution(oprfKeyId, aliceRound2Contribution());
        vm.stopPrank();

        vm.prank(carol);
        vm.expectEmit(true, true, true, true);
        emit Types.KeyGenConfirmation(oprfKeyId, 2, 2, 0);
        oprfKeyRegistry.addRound2Contribution(oprfKeyId, carolRound2Contribution());
        vm.stopPrank();

        // do round 3 contributions
        vm.prank(alice);
        vm.expectEmit(true, true, true, true);
        emit Types.KeyGenConfirmation(oprfKeyId, 0, 3, 0);
        oprfKeyRegistry.addRound3Contribution(oprfKeyId);
        vm.stopPrank();

        vm.prank(taceoAdmin);
        // now delete
        vm.expectEmit(true, true, true, true);
        emit Types.KeyDeletion(oprfKeyId);
        oprfKeyRegistry.deleteOprfPublicKey(oprfKeyId);
        vm.stopPrank();

        vm.recordLogs();
        vm.prank(bob);
        vm.expectRevert(abi.encodeWithSelector(OprfKeyRegistry.DeletedId.selector, oprfKeyId));
        oprfKeyRegistry.addRound3Contribution(oprfKeyId);
        vm.stopPrank();

        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(OprfKeyRegistry.UnknownId.selector, oprfKeyId));
        oprfKeyRegistry.getOprfPublicKey(oprfKeyId);
        vm.stopPrank();

        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(OprfKeyRegistry.DeletedId.selector, oprfKeyId));
        oprfKeyRegistry.loadPeerPublicKeysForProducers(oprfKeyId);
        vm.stopPrank();

        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(OprfKeyRegistry.DeletedId.selector, oprfKeyId));
        oprfKeyRegistry.checkIsParticipantAndReturnRound2Ciphers(oprfKeyId);
        vm.stopPrank();
    }

    function testE2E() public {
        uint160 oprfKeyId = 42;
        vm.prank(taceoAdmin);
        vm.expectEmit(true, true, true, true);
        emit Types.SecretGenRound1(oprfKeyId, THRESHOLD);
        oprfKeyRegistry.initKeyGen(oprfKeyId);
        vm.stopPrank();

        // do round 1 contributions
        vm.prank(bob);
        vm.expectEmit(true, true, true, true);
        emit Types.KeyGenConfirmation(oprfKeyId, 1, 1, 0);
        oprfKeyRegistry.addRound1KeyGenContribution(
            oprfKeyId,
            Types.Round1Contribution({commShare: commShareBob, commCoeffs: commCoeffsBob, ephPubKey: publicKeyBob})
        );
        vm.stopPrank();

        vm.prank(alice);
        vm.expectEmit(true, true, true, true);
        emit Types.KeyGenConfirmation(oprfKeyId, 0, 1, 0);
        oprfKeyRegistry.addRound1KeyGenContribution(
            oprfKeyId,
            Types.Round1Contribution({
                commShare: commShareAlice, commCoeffs: commCoeffsAlice, ephPubKey: publicKeyAlice
            })
        );
        vm.stopPrank();

        vm.prank(carol);
        vm.expectEmit(true, true, true, true);
        emit Types.SecretGenRound2(oprfKeyId);
        vm.expectEmit(true, true, true, true);
        emit Types.KeyGenConfirmation(oprfKeyId, 2, 1, 0);
        oprfKeyRegistry.addRound1KeyGenContribution(
            oprfKeyId,
            Types.Round1Contribution({
                commShare: commShareCarol, commCoeffs: commCoeffsCarol, ephPubKey: publicKeyCarol
            })
        );
        vm.stopPrank();

        // do round 2 contributions
        vm.prank(bob);
        vm.expectEmit(true, true, true, true);
        emit Types.KeyGenConfirmation(oprfKeyId, 1, 2, 0);
        oprfKeyRegistry.addRound2Contribution(oprfKeyId, bobRound2Contribution());
        vm.stopPrank();

        vm.prank(alice);
        vm.expectEmit(true, true, true, true);
        emit Types.KeyGenConfirmation(oprfKeyId, 0, 2, 0);
        oprfKeyRegistry.addRound2Contribution(oprfKeyId, aliceRound2Contribution());
        vm.stopPrank();

        vm.expectEmit(true, true, true, true);
        emit Types.SecretGenRound3(oprfKeyId);
        vm.prank(carol);
        vm.expectEmit(true, true, true, true);
        emit Types.KeyGenConfirmation(oprfKeyId, 2, 2, 0);
        oprfKeyRegistry.addRound2Contribution(oprfKeyId, carolRound2Contribution());
        vm.stopPrank();

        // do round 3 contributions
        vm.prank(alice);
        vm.expectEmit(true, true, true, true);
        emit Types.KeyGenConfirmation(oprfKeyId, 0, 3, 0);
        oprfKeyRegistry.addRound3Contribution(oprfKeyId);
        vm.stopPrank();

        vm.prank(bob);
        vm.expectEmit(true, true, true, true);
        emit Types.KeyGenConfirmation(oprfKeyId, 1, 3, 0);
        oprfKeyRegistry.addRound3Contribution(oprfKeyId);
        vm.stopPrank();

        vm.expectEmit(true, true, true, true);
        emit Types.SecretGenFinalize(oprfKeyId, 0);
        vm.prank(carol);
        vm.expectEmit(true, true, true, true);
        emit Types.KeyGenConfirmation(oprfKeyId, 2, 3, 0);
        oprfKeyRegistry.addRound3Contribution(oprfKeyId);
        vm.stopPrank();

        // check that the computed nullifier is correct
        Types.BabyJubJubElement memory oprfKey = oprfKeyRegistry.getOprfPublicKey(oprfKeyId);
        assertEq(oprfKey.x, 2197751895809799734146001567623507872025142095924791991243994059456432106738);
        assertEq(oprfKey.y, 17752307105958841504133705104840128793511849993452913074787269028121192628329);
    }

    // function testE2EReshare() public {
    //     testE2E();
    //     uint160 oprfKeyId = 42;
    //     vm.prank(taceoAdmin);
    //     vm.expectEmit(true, true, true, true);
    //     emit Types.ReshareRound1(oprfKeyId, THRESHOLD);
    //     oprfKeyRegistry.initReshare(oprfKeyId);
    //     vm.stopPrank();

    //     // do round 1 contributions
    //     vm.prank(bob);
    //     oprfKeyRegistry.addRound1ReshareContribution(
    //         oprfKeyId,
    //         Types.Round1Contribution({commShare: commShareBob, commCoeffs: commCoeffsBob, ephPubKey: publicKeyBob})
    //     );
    //     vm.stopPrank();

    //     vm.prank(alice);
    //     oprfKeyRegistry.addRound1ReshareContribution(
    //         oprfKeyId,
    //         Types.Round1Contribution({
    //             commShare: commShareAlice, commCoeffs: commCoeffsAlice, ephPubKey: publicKeyAlice
    //         })
    //     );
    //     vm.stopPrank();

    //     vm.prank(carol);
    //     vm.expectEmit(true, true, true, true);
    //     emit Types.SecretGenRound2(oprfKeyId);
    //     oprfKeyRegistry.addRound1ReshareContribution(
    //         oprfKeyId,
    //         Types.Round1Contribution({
    //             commShare: commShareCarol, commCoeffs: commCoeffsCarol, ephPubKey: publicKeyCarol
    //         })
    //     );
    //     vm.stopPrank();
    //     // do round 2 contributions
    //     // check that carol is not a producer
    //     vm.prank(carol);
    //     Types.BabyJubJubElement[] memory ephKeys = oprfKeyRegistry.loadPeerPublicKeysForProducers(oprfKeyId);
    //     assert(ephKeys.length == 0);
    //     vm.stopPrank();

    //     // only alice and bob need to contribute now
    //     vm.prank(bob);
    //     oprfKeyRegistry.addRound2Contribution(oprfKeyId, bobRound2Contribution());
    //     vm.stopPrank();

    //     vm.expectEmit(true, true, true, true);
    //     uint256[] memory shouldLagrange = new uint256[](3);
    //     shouldLagrange[0] = 2;
    //     shouldLagrange[1] = 2736030358979909402780800718157159386076813972158567259200215660948447373040;
    //     shouldLagrange[2] = 0;
    //     emit Types.ReshareRound3(oprfKeyId, shouldLagrange);
    //     vm.prank(alice);
    //     oprfKeyRegistry.addRound2Contribution(oprfKeyId, aliceRound2Contribution());
    //     vm.stopPrank();
    // }
}

function aliceProof() pure returns (uint256[4] memory) {
    return [
        7599036951350496938509228185070999974645951806785190687964555491994104973638,
        2919495355306661769244723111688503346563095730808672017901039244298659151074,
        62406865356414663459054313885605812633979168283245204691957640350968902107927,
        2390821710080109228602752477366472772918784232589294042986920772263546028753
    ];
}

function bobProof() pure returns (uint256[4] memory) {
    return [
        4844428075446874424059258695529135628240933165617260457392759267441916033334,
        17070729547872382485980726106788227357700306686859531375221963107454887413147,
        80641342548823339886682425796518069524588816755280364751661170041672976076008,
        6586906492367060256061951295741416499476961970659009966143515589680908362955
    ];
}

function carolProof() pure returns (uint256[4] memory) {
    return [
        40970297886722395198386824377135721567428789376755589636937634767900617421816,
        16326389773756886685330477456453664957476596047968775267578686693995815444769,
        68194252363814646796167112014251640330110065189251787080541819374741444677737,
        27274938290776373352801027902607424960225645698805250884721544881102180964729
    ];
}

function aliceRound2Contribution() pure returns (Types.Round2Contribution memory) {
    Types.SecretGenCiphertext[] memory ciphers = new Types.SecretGenCiphertext[](3);
    ciphers[0].cipher = 0x28bb5603f454ca0e93975292a64b5e2627508939c34f75110b1f564b5c573700;
    ciphers[0].nonce = 0x2e0e33932fed970f0a6502ccdbd31d9f53d869dd97047e8163b61b64ea184893;
    ciphers[0].commitment = Types.BabyJubJubElement({
        x: 0x1d0c22e0b65e28a2dda5d1f7963f17576bb6e1ac6fda44d1f64688c9f4fd10d3,
        y: 0x2918af65f63e3619ac5cbcc3771e124f8fdaa06b73e45a84472999dbf2115e8e
    });

    ciphers[1].cipher = 0x12297ee0bfbd08ff417e17f98ceb6fd1fd0ebf7591dfc240cf863ee809f0fd74;
    ciphers[1].nonce = 0x046dc1740048f99098f97b9a74f725bc21ae5248eeb9e6385dbdc0b5e128c558;
    ciphers[1].commitment = Types.BabyJubJubElement({
        x: 0x25f159ef60c19fa55bdeeac713eab1bc69e41f7e9079f7bffdd0ef7d7381166a,
        y: 0x1a53af8466e5d476a6183f57ccfd6f1ed98729b972a40459c317547a390ad20d
    });

    ciphers[2].cipher = 0x11465b22b395b507b15fd06b33eb1074f067f9ba6638aca490cdfceef16fc3c0;
    ciphers[2].nonce = 0x15819576a5b57223acfbc67cc5af75400ebefa3a418e76d13de46e259e363171;
    ciphers[2].commitment = Types.BabyJubJubElement({
        x: 0x0e20e6c71ff0732a2cc47e78e55e1dca63dadf085b756a12e8cf384097cbdab2,
        y: 0x20bb39169676c06bd11bc45475ca73499e5e1bd6ef5934908be9b1e7ed261f93
    });

    return Types.Round2Contribution({compressedProof: aliceProof(), ciphers: ciphers});
}

function bobRound2Contribution() pure returns (Types.Round2Contribution memory) {
    Types.SecretGenCiphertext[] memory ciphers = new Types.SecretGenCiphertext[](3);
    ciphers[0].cipher = 0x164f495708ce5e668303f5369920c7b223346f54ddce81dd65e29b28035352c8;
    ciphers[0].nonce = 0x018809491ccdf374352e3bc89f8cd1bb7e767653a46d5a7984e76a3ecc845a60;
    ciphers[0].commitment = Types.BabyJubJubElement({
        x: 0x21140ebf4a3a8fd06d22f440b05337fd47f9ef50ea48cbd101b038c3500aeb5b,
        y: 0x287dc67a967ffe4925215678e4ee240fdc1eeeb3d5cca0dc2dcd421d61c63497
    });

    ciphers[1].cipher = 0x24f8970af58f92f1edba22f8fa950de3f423307dc69c7e1ca026ac64d9155ad7;
    ciphers[1].nonce = 0x07c1dd5ff232cba92025ada9a706a4aa589f7835af8a8258ab0ae8ebd92969bd;
    ciphers[1].commitment = Types.BabyJubJubElement({
        x: 0x08bf1f8f96d3fdd9dc7f770a75c4f7971742ed0c1ef8bd676f59e3f034bbede2,
        y: 0x0f1d886b93ffd7308b07791b0be78067a165f63556512d0e83d98a538c2bd0fd
    });

    ciphers[2].cipher = 0x0c9ef83c1484d8fe1d0bff491d7dd24237f04df949be9e78f7b1c9baaf157e1b;
    ciphers[2].nonce = 0x0e22fda32802ba5b8e2c27a2a2a10964e1a9399c16540e2939545047c2d77c62;
    ciphers[2].commitment = Types.BabyJubJubElement({
        x: 0x1a17bf8d2e05b2f9722f6a6acc73efc384e3aeac7c1d1e68f92dad30bdccdce0,
        y: 0x29647d1fd7116608b00a5b1aca74e3183fe9dff0d4dead1bae563a571a4be06f
    });

    return Types.Round2Contribution({compressedProof: bobProof(), ciphers: ciphers});
}

function carolRound2Contribution() pure returns (Types.Round2Contribution memory) {
    Types.SecretGenCiphertext[] memory ciphers = new Types.SecretGenCiphertext[](3);
    ciphers[0].cipher = 0x26f532e67dc0880ff05b88fbe206ac8cccc7279c8ff6608070611e1feba80d34;
    ciphers[0].nonce = 0x201e86bdaa637b185b47b18ba21aa4bf8ab1b52379a8f78fc7566277e73e225c;
    ciphers[0].commitment = Types.BabyJubJubElement({
        x: 0x1d84598a953f9a03e7683c81e3320d91cc7876ff7ed66698c7b5ad0e2d510f23,
        y: 0x1b3340c7e2186338d97e8ecc5541067327a7ef1f5bd2f78d948f40ff8579a2f7
    });

    ciphers[1].cipher = 0x2d86cbb6cb1e2c9fea0aa2e954c050a576a6389ff2a3ba5fb56c955acf5e7dd7;
    ciphers[1].nonce = 0x00094c8c56a206d2294fa3987b2a4f34fcea8675aacf8bb993775d8856065c63;
    ciphers[1].commitment = Types.BabyJubJubElement({
        x: 0x1432b7063b0637bb63abd4a09ca48e54124fa499463e1704a42ea1c19c69ee38,
        y: 0x1c8fa3c18b2192bfb729a40931491b23f66d0ed5979123c5442bd5380757f83b
    });

    ciphers[2].cipher = 0x2baff49b2c25533429030682feba2055f0559010a353a305f477315cff26f857;
    ciphers[2].nonce = 0x22bd22f26744b94655b17c01b74968b3f186a620413d3213c27db9b92fe192d0;
    ciphers[2].commitment = Types.BabyJubJubElement({
        x: 0x190fb1fccfbf63a4c683e6caf945cd90991bafd6eaa65b9192ed94bb44533176,
        y: 0x1ecdc7e068d459804aee2bfe03654947ca95c740095904b90f97519df06179f7
    });

    return Types.Round2Contribution({compressedProof: carolProof(), ciphers: ciphers});
}
