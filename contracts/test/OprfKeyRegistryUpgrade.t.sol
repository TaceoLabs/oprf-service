// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {OprfKeyRegistry} from "../src/OprfKeyRegistry.sol";
import {BabyJubJub} from "../src/BabyJubJub.sol";
import {Verifier as VerifierKeyGen13} from "../src/VerifierKeyGen13.sol";
import {Types} from "../src/Types.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {aliceRound2Contribution, bobRound2Contribution, carolRound2Contribution} from "./OprfKeyRegistry.t.sol";

/**
 *
 *
 * @title OprfKeyRegistryV2Mock
 *
 *
 * @notice Mock V2 implementation for testing upgrades
 *
 *
 */
contract OprfKeyRegistryV2Mock is OprfKeyRegistry {
    // Add a new state variable to test storage layout preservation

    uint256 public newFeature;

    function version() public pure returns (string memory) {
        return "V2";
    }

    function setNewFeature(uint256 _value) public {
        newFeature = _value;
    }
}

contract OprfKeyRegistryUpgradeTest is Test {
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

    function testUpgrade() public {
        // start key generation process for oprfKeyId 42
        // see testE2E in OprfKeyRegistry.t.sol for the full process
        uint160 oprfKeyId = 42;
        vm.prank(taceoAdmin);
        vm.expectEmit(true, true, true, true);
        emit Types.SecretGenRound1(oprfKeyId, THRESHOLD);
        oprfKeyRegistry.initKeyGen(oprfKeyId);
        vm.stopPrank();

        // do round 1 contributions
        vm.prank(bob);
        vm.expectEmit(true, true, true, true);
        emit Types.TransactionNonce(0);
        oprfKeyRegistry.addRound1KeyGenContribution(
        0,
            oprfKeyId,
            Types.Round1Contribution({commShare: commShareBob, commCoeffs: commCoeffsBob, ephPubKey: publicKeyBob})
        );
        vm.stopPrank();

        vm.prank(alice);
        vm.expectEmit(true, true, true, true);
        emit Types.TransactionNonce(1);
        oprfKeyRegistry.addRound1KeyGenContribution(
        1,
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
        emit Types.TransactionNonce(2);
        oprfKeyRegistry.addRound1KeyGenContribution(
        2,
            oprfKeyId,
            Types.Round1Contribution({
                commShare: commShareCarol, commCoeffs: commCoeffsCarol, ephPubKey: publicKeyCarol
            })
        );
        vm.stopPrank();

        // do round 2 contributions
        vm.prank(bob);
        vm.expectEmit(true, true, true, true);
        emit Types.TransactionNonce(3);
        oprfKeyRegistry.addRound2Contribution(3,oprfKeyId, bobRound2Contribution());
        vm.stopPrank();

        vm.prank(alice);
        vm.expectEmit(true, true, true, true);
        emit Types.TransactionNonce(4);
        oprfKeyRegistry.addRound2Contribution(4,oprfKeyId, aliceRound2Contribution());
        vm.stopPrank();

        vm.expectEmit(true, true, true, true);
        emit Types.SecretGenRound3(oprfKeyId);
        vm.prank(carol);
        vm.expectEmit(true, true, true, true);
        emit Types.TransactionNonce(5);
        oprfKeyRegistry.addRound2Contribution(5,oprfKeyId, carolRound2Contribution());
        vm.stopPrank();

        // do round 3 contributions
        vm.prank(alice);
        vm.expectEmit(true, true, true, true);
        emit Types.TransactionNonce(6);
        oprfKeyRegistry.addRound3Contribution(6,oprfKeyId);
        vm.stopPrank();

        vm.prank(bob);
        vm.expectEmit(true, true, true, true);
        emit Types.TransactionNonce(7);
        oprfKeyRegistry.addRound3Contribution(7,oprfKeyId);
        vm.stopPrank();

        vm.expectEmit(true, true, true, true);
        emit Types.SecretGenFinalize(oprfKeyId, 0);
        vm.prank(carol);
        vm.expectEmit(true, true, true, true);
        emit Types.TransactionNonce(8);
        oprfKeyRegistry.addRound3Contribution(8,oprfKeyId);
        vm.stopPrank();

        // check that the computed nullifier is correct
        Types.BabyJubJubElement memory oprfKey = oprfKeyRegistry.getOprfPublicKey(oprfKeyId);
        assertEq(oprfKey.x, 2197751895809799734146001567623507872025142095924791991243994059456432106738);
        assertEq(oprfKey.y, 17752307105958841504133705104840128793511849993452913074787269028121192628329);

        // Now perform upgrade
        OprfKeyRegistryV2Mock implementationV2 = new OprfKeyRegistryV2Mock();
        // upgrade as owner
        OprfKeyRegistry(address(proxy)).upgradeToAndCall(address(implementationV2), "");
        // Wrap proxy with V2 interface
        OprfKeyRegistryV2Mock oprfKeyRegistryV2 = OprfKeyRegistryV2Mock(address(proxy));

        // Verify storage was preserved
        Types.BabyJubJubElement memory oprfKeyV2 = oprfKeyRegistryV2.getOprfPublicKey(oprfKeyId);
        assertEq(oprfKeyV2.x, 2197751895809799734146001567623507872025142095924791991243994059456432106738);
        assertEq(oprfKeyV2.y, 17752307105958841504133705104840128793511849993452913074787269028121192628329);

        // Verify new functionality works
        assertEq(oprfKeyRegistryV2.version(), "V2");
        oprfKeyRegistryV2.setNewFeature(42);
        assertEq(oprfKeyRegistryV2.newFeature(), 42);

        // Verify old functionality still works
        uint160 newOprfKeyId = 43;
        vm.prank(taceoAdmin);
        vm.expectEmit(true, true, true, true);
        emit Types.SecretGenRound1(newOprfKeyId, 2);
        oprfKeyRegistry.initKeyGen(newOprfKeyId);
        vm.stopPrank();

        // do round 1 contributions
        vm.prank(bob);
        vm.expectEmit(true, true, true, true);
        emit Types.TransactionNonce(10);
        oprfKeyRegistry.addRound1KeyGenContribution(
        10,
            newOprfKeyId,
            Types.Round1Contribution({commShare: commShareBob, commCoeffs: commCoeffsBob, ephPubKey: publicKeyBob})
        );
        vm.stopPrank();

        vm.prank(alice);
        vm.expectEmit(true, true, true, true);
        emit Types.TransactionNonce(11);
        oprfKeyRegistry.addRound1KeyGenContribution(
        11,
            newOprfKeyId,
            Types.Round1Contribution({
                commShare: commShareAlice, commCoeffs: commCoeffsAlice, ephPubKey: publicKeyAlice
            })
        );
        vm.stopPrank();

        vm.prank(carol);
        vm.expectEmit(true, true, true, true);
        emit Types.SecretGenRound2(newOprfKeyId);
        vm.expectEmit(true, true, true, true);
        emit Types.TransactionNonce(12);
        oprfKeyRegistry.addRound1KeyGenContribution(
        12,
            newOprfKeyId,
            Types.Round1Contribution({
                commShare: commShareCarol, commCoeffs: commCoeffsCarol, ephPubKey: publicKeyCarol
            })
        );
        vm.stopPrank();

        // do round 2 contributions
        vm.prank(bob);
        vm.expectEmit(true, true, true, true);
        emit Types.TransactionNonce(13);
        oprfKeyRegistry.addRound2Contribution(13,newOprfKeyId, bobRound2Contribution());
        vm.stopPrank();

        vm.prank(alice);
        vm.expectEmit(true, true, true, true);
        emit Types.TransactionNonce(14);
        oprfKeyRegistry.addRound2Contribution(14,newOprfKeyId, aliceRound2Contribution());
        vm.stopPrank();

        vm.expectEmit(true, true, true, true);
        emit Types.SecretGenRound3(newOprfKeyId);
        vm.prank(carol);
        vm.expectEmit(true, true, true, true);
        emit Types.TransactionNonce(15);
        oprfKeyRegistry.addRound2Contribution(15,newOprfKeyId, carolRound2Contribution());
        vm.stopPrank();

        // do round 3 contributions
        vm.prank(alice);
        vm.expectEmit(true, true, true, true);
        emit Types.TransactionNonce(16);
        oprfKeyRegistry.addRound3Contribution(16,newOprfKeyId);
        vm.stopPrank();

        vm.prank(bob);
        vm.expectEmit(true, true, true, true);
        emit Types.TransactionNonce(17);
        oprfKeyRegistry.addRound3Contribution(17,newOprfKeyId);
        vm.stopPrank();

        vm.expectEmit(true, true, true, true);
        emit Types.SecretGenFinalize(newOprfKeyId, 0);
        vm.prank(carol);
        vm.expectEmit(true, true, true, true);
        emit Types.TransactionNonce(18);
        oprfKeyRegistry.addRound3Contribution(18,newOprfKeyId);
        vm.stopPrank();

        // check that the computed nullifier is correct
        Types.BabyJubJubElement memory oprfKeyNew = oprfKeyRegistry.getOprfPublicKey(newOprfKeyId);
        assertEq(oprfKeyNew.x, 2197751895809799734146001567623507872025142095924791991243994059456432106738);
        assertEq(oprfKeyNew.y, 17752307105958841504133705104840128793511849993452913074787269028121192628329);
    }
}

