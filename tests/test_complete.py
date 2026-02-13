# Complete Test Suite
# Tests for crypto, protocol, replay detection, tampering detection

import pytest
from crypto import CryptoEngine, KeyDerivation, X25519KeyExchange
from protocol import (
    ProtocolMessage, MessageType, ReplayProtector, SequenceTracker
)
import os


class TestCryptoEngine:
    """Test AES-256-GCM and ChaCha20-Poly1305 encryption."""
    
    def test_aes_encrypt_decrypt(self):
        """AES-256-GCM round-trip encryption."""
        engine = CryptoEngine("aes-256-gcm")
        key = engine.generate_key()
        plaintext = b"Hello, World! This is a secret message."
        
        # Encrypt
        ciphertext, nonce, tag = engine.encrypt(plaintext, key)
        
        # Verify it's actually encrypted (not equal to plaintext)
        assert ciphertext != plaintext
        assert len(ciphertext) == len(plaintext)
        
        # Decrypt
        decrypted = engine.decrypt(ciphertext, key, nonce, tag)
        assert decrypted == plaintext
    
    def test_chacha_encrypt_decrypt(self):
        """ChaCha20-Poly1305 round-trip encryption."""
        engine = CryptoEngine("chacha20-poly1305")
        key = engine.generate_key()
        plaintext = b"Test message for ChaCha20"
        
        ciphertext, nonce, tag = engine.encrypt(plaintext, key)
        decrypted = engine.decrypt(ciphertext, key, nonce, tag)
        assert decrypted == plaintext
    
    def test_tampering_detection_aes(self):
        """Tampering with AES-GCM ciphertext causes decryption failure."""
        engine = CryptoEngine("aes-256-gcm")
        key = engine.generate_key()
        plaintext = b"Original message"
        
        ciphertext, nonce, tag = engine.encrypt(plaintext, key)
        
        # Tamper with ciphertext
        tampered = bytearray(ciphertext)
        tampered[0] ^= 0xFF  # Flip bits in first byte
        tampered = bytes(tampered)
        
        # Decryption should fail
        from cryptography.exceptions import InvalidTag
        with pytest.raises(InvalidTag):
            engine.decrypt(tampered, key, nonce, tag)
    
    def test_tampering_detection_tag(self):
        """Tampering with auth tag causes decryption failure."""
        engine = CryptoEngine("aes-256-gcm")
        key = engine.generate_key()
        plaintext = b"Test"
        
        ciphertext, nonce, tag = engine.encrypt(plaintext, key)
        
        # Tamper with tag
        tampered_tag = bytearray(tag)
        tampered_tag[-1] ^= 0xFF
        tampered_tag = bytes(tampered_tag)
        
        from cryptography.exceptions import InvalidTag
        with pytest.raises(InvalidTag):
            engine.decrypt(ciphertext, key, nonce, tampered_tag)
    
    def test_wrong_key_detection(self):
        """Decryption with wrong key fails."""
        engine = CryptoEngine("aes-256-gcm")
        key1 = engine.generate_key()
        key2 = engine.generate_key()
        plaintext = b"Secret"
        
        ciphertext, nonce, tag = engine.encrypt(plaintext, key1)
        
        from cryptography.exceptions import InvalidTag
        with pytest.raises(InvalidTag):
            engine.decrypt(ciphertext, key2, nonce, tag)
    
    def test_aad_protection(self):
        """Associated Authenticated Data verification."""
        engine = CryptoEngine("aes-256-gcm")
        key = engine.generate_key()
        plaintext = b"Message"
        aad = b"user_id:alice|room:lobby"
        
        ciphertext, nonce, tag = engine.encrypt(plaintext, key, aad=aad)
        
        # Correct AAD: decryption succeeds
        decrypted = engine.decrypt(ciphertext, key, nonce, tag, aad=aad)
        assert decrypted == plaintext
        
        # Wrong AAD: decryption fails
        wrong_aad = b"user_id:bob|room:lobby"
        from cryptography.exceptions import InvalidTag
        with pytest.raises(InvalidTag):
            engine.decrypt(ciphertext, key, nonce, tag, aad=wrong_aad)
    
    def test_key_generation_randomness(self):
        """Generated keys are random and different."""
        engine = CryptoEngine()
        keys = [engine.generate_key() for _ in range(10)]
        
        # All keys should be unique
        assert len(set(keys)) == 10
        
        # All keys should be correct size
        assert all(len(k) == 32 for k in keys)
    
    def test_nonce_generation_randomness(self):
        """Generated nonces are random and different."""
        engine = CryptoEngine()
        nonces = [engine.generate_nonce() for _ in range(10)]
        
        # All nonces should be unique
        assert len(set(nonces)) == 10
        
        # All nonces should be correct size
        assert all(len(n) == 12 for n in nonces)


class TestKeyDerivation:
    """Test HKDF key derivation."""
    
    def test_hkdf_deterministic(self):
        """HKDF with same inputs produces same output."""
        shared_secret = os.urandom(32)
        info = b'test-info'
        salt = os.urandom(16)
        
        key1 = KeyDerivation.hkdf_expand(shared_secret, info, salt)
        key2 = KeyDerivation.hkdf_expand(shared_secret, info, salt)
        
        assert key1 == key2
    
    def test_hkdf_different_info(self):
        """Different info produces different keys."""
        shared_secret = os.urandom(32)
        salt = os.urandom(16)
        
        key1 = KeyDerivation.hkdf_expand(shared_secret, b'key-1', salt)
        key2 = KeyDerivation.hkdf_expand(shared_secret, b'key-2', salt)
        
        assert key1 != key2
    
    def test_hkdf_different_salt(self):
        """Different salt produces different keys."""
        shared_secret = os.urandom(32)
        info = b'test-info'
        
        key1 = KeyDerivation.hkdf_expand(shared_secret, info, os.urandom(16))
        key2 = KeyDerivation.hkdf_expand(shared_secret, info, os.urandom(16))
        
        assert key1 != key2
    
    def test_multi_party_group_key(self):
        """3-party group key derivation produces same key for all."""
        # 3 participants
        alice = X25519KeyExchange()
        bob = X25519KeyExchange()
        charlie = X25519KeyExchange()
        
        # Exchange public keys
        alice_pub = alice.get_public_bytes()
        bob_pub = bob.get_public_bytes()
        charlie_pub = charlie.get_public_bytes()
        
        # Each computes pairwise shared secrets
        ss_ab = alice.exchange(bob_pub)
        ss_ac = alice.exchange(charlie_pub)
        alice_key = KeyDerivation.derive_room_key(ss_ab, ss_ac)
        
        ss_ba = bob.exchange(alice_pub)
        ss_bc = bob.exchange(charlie_pub)
        bob_key = KeyDerivation.derive_room_key(ss_ba, ss_bc)
        
        ss_ca = charlie.exchange(alice_pub)
        ss_cb = charlie.exchange(bob_pub)
        charlie_key = KeyDerivation.derive_room_key(ss_ca, ss_cb)
        
        # All should be equal
        assert alice_key == bob_key == charlie_key


class TestX25519Exchange:
    """Test X25519 key exchange."""
    
    def test_key_exchange(self):
        """Two parties derive same shared secret."""
        alice = X25519KeyExchange()
        bob = X25519KeyExchange()
        
        # Exchange public keys
        alice_pub = alice.get_public_bytes()
        bob_pub = bob.get_public_bytes()
        
        # Compute shared secrets
        ss_alice = alice.exchange(bob_pub)
        ss_bob = bob.exchange(alice_pub)
        
        # Should be identical
        assert ss_alice == ss_bob
        assert len(ss_alice) == 32
    
    def test_different_pairs_different_secrets(self):
        """Different key pairs produce different shared secrets."""
        alice = X25519KeyExchange()
        bob1 = X25519KeyExchange()
        bob2 = X25519KeyExchange()
        
        alice_pub = alice.get_public_bytes()
        
        ss1 = bob1.exchange(alice_pub)
        ss2 = bob2.exchange(alice_pub)
        
        # Different pairs should give different secrets
        assert ss1 != ss2


class TestProtocolMessage:
    """Test message serialization and deserialization."""
    
    def test_message_roundtrip(self):
        """Message serializes and deserializes correctly."""
        msg = ProtocolMessage(
            message_type=MessageType.CHAT,
            sender_id="alice",
            room_id="lobby",
            sequence_number=42,
            nonce=os.urandom(12),
            ciphertext=b"encrypted payload",
            auth_tag=os.urandom(16)
        )
        
        serialized = msg.to_bytes()
        deserialized = ProtocolMessage.from_bytes(serialized)
        
        assert deserialized.sender_id == msg.sender_id
        assert deserialized.room_id == msg.room_id
        assert deserialized.sequence_number == msg.sequence_number
        assert deserialized.nonce == msg.nonce
        assert deserialized.ciphertext == msg.ciphertext
        assert deserialized.auth_tag == msg.auth_tag
    
    def test_message_types(self):
        """Different message types serialize correctly."""
        for msg_type in [MessageType.CHAT, MessageType.HANDSHAKE, MessageType.HEARTBEAT]:
            msg = ProtocolMessage(
                message_type=msg_type,
                sender_id="bob",
                room_id="test",
                sequence_number=1,
                nonce=os.urandom(12),
                ciphertext=b"test",
                auth_tag=os.urandom(16)
            )
            
            serialized = msg.to_bytes()
            deserialized = ProtocolMessage.from_bytes(serialized)
            assert deserialized.message_type == msg_type
    
    def test_message_too_short(self):
        """Malformed message raises error."""
        with pytest.raises(ValueError):
            ProtocolMessage.from_bytes(b"too_short")
    
    def test_malformed_message(self):
        """Incomplete message raises error."""
        # Create incomplete message (missing auth tag)
        msg = ProtocolMessage(
            sender_id="alice",
            room_id="test",
            sequence_number=1,
            nonce=os.urandom(12),
            ciphertext=b"data",
            auth_tag=os.urandom(16)
        )
        serialized = msg.to_bytes()[:-8]  # Remove last 8 bytes
        
        with pytest.raises(ValueError):
            ProtocolMessage.from_bytes(serialized)


class TestReplayProtection:
    """Test replay attack detection."""
    
    def test_no_replay_valid_sequence(self):
        """Valid increasing sequence is accepted."""
        protector = ReplayProtector(window_size=100)
        
        # Send messages 1, 2, 3 from alice
        assert protector.check_and_update("alice", 1) is True
        assert protector.check_and_update("alice", 2) is True
        assert protector.check_and_update("alice", 3) is True
    
    def test_duplicate_rejected(self):
        """Duplicate sequence number is rejected."""
        protector = ReplayProtector(window_size=100)
        
        assert protector.check_and_update("alice", 1) is True
        assert protector.check_and_update("alice", 2) is True
        assert protector.check_and_update("alice", 1) is False  # Replay
        assert protector.check_and_update("alice", 2) is False  # Replay
    
    def test_out_of_window_rejected(self):
        """Messages below window floor are rejected."""
        protector = ReplayProtector(window_size=10)
        
        # Fill window: 1-50
        for i in range(1, 51):
            protector.check_and_update("alice", i)
        
        # Message 30 is below window floor (50 - 10 = 40)
        assert protector.check_and_update("alice", 30) is False
    
    def test_out_of_order_within_window(self):
        """Out-of-order messages within window are accepted."""
        protector = ReplayProtector(window_size=100)
        
        # Accept 1, 3, 2 (out of order but all in window)
        assert protector.check_and_update("alice", 1) is True
        assert protector.check_and_update("alice", 3) is True
        assert protector.check_and_update("alice", 2) is True  # Still valid
    
    def test_multiple_senders(self):
        """Different senders have independent sequences."""
        protector = ReplayProtector(window_size=100)
        
        # Alice: 1, 2
        assert protector.check_and_update("alice", 1) is True
        assert protector.check_and_update("alice", 2) is True
        
        # Bob: 1, 2 (same numbers, different sender - valid)
        assert protector.check_and_update("bob", 1) is True
        assert protector.check_and_update("bob", 2) is True
        
        # Alice: 1 (replay from Alice)
        assert protector.check_and_update("alice", 1) is False
    
    def test_highest_sequence_tracking(self):
        """Highest sequence number is tracked correctly."""
        protector = ReplayProtector()
        
        assert protector.get_highest_sequence("alice") == -1
        
        protector.check_and_update("alice", 5)
        assert protector.get_highest_sequence("alice") == 5
        
        protector.check_and_update("alice", 3)
        assert protector.get_highest_sequence("alice") == 5  # Still 5


class TestSequenceTracker:
    """Test outgoing message sequence numbering."""
    
    def test_sequence_increments(self):
        """Sequence numbers increment correctly."""
        tracker = SequenceTracker()
        
        assert tracker.next_sequence("room1") == 0
        assert tracker.next_sequence("room1") == 1
        assert tracker.next_sequence("room1") == 2
    
    def test_independent_per_room(self):
        """Different rooms have independent sequences."""
        tracker = SequenceTracker()
        
        assert tracker.next_sequence("room1") == 0
        assert tracker.next_sequence("room2") == 0
        assert tracker.next_sequence("room1") == 1
        assert tracker.next_sequence("room2") == 1
    
    def test_current_sequence(self):
        """Current sequence is returned without incrementing."""
        tracker = SequenceTracker()
        
        assert tracker.current_sequence("room1") == -1
        tracker.next_sequence("room1")
        assert tracker.current_sequence("room1") == 0
        assert tracker.current_sequence("room1") == 0  # Still 0


class TestEndToEnd:
    """Integration tests: crypto + protocol + replay detection."""
    
    def test_full_message_flow(self):
        """Complete encryption, serialization, deserialization, decryption."""
        # Setup
        crypto = CryptoEngine("aes-256-gcm")
        key = crypto.generate_key()
        plaintext = b"Secret message from Alice"
        
        # Alice sends
        nonce = crypto.generate_nonce()
        ciphertext, _, tag = crypto.encrypt(plaintext, key, nonce)
        
        msg = ProtocolMessage(
            sender_id="alice",
            room_id="lobby",
            sequence_number=1,
            nonce=nonce,
            ciphertext=ciphertext,
            auth_tag=tag
        )
        
        # Serialize for network
        serialized = msg.to_bytes()
        
        # Network transfer (could be modified by adversary)
        # ...
        
        # Deserialize on Bob's end
        received_msg = ProtocolMessage.from_bytes(serialized)
        
        # Check replay
        replay_checker = ReplayProtector()
        if not replay_checker.check_and_update(received_msg.sender_id, received_msg.sequence_number):
            pytest.fail("Message flagged as replay")
        
        # Decrypt
        decrypted = crypto.decrypt(
            received_msg.ciphertext,
            key,
            received_msg.nonce,
            received_msg.auth_tag
        )
        
        assert decrypted == plaintext
    
    def test_adversary_modification_detected(self):
        """Adversary modifying ciphertext is detected."""
        crypto = CryptoEngine("aes-256-gcm")
        key = crypto.generate_key()
        plaintext = b"Private message"
        
        ciphertext, nonce, tag = crypto.encrypt(plaintext, key)
        
        msg = ProtocolMessage(
            sender_id="alice",
            room_id="lobby",
            sequence_number=1,
            nonce=nonce,
            ciphertext=ciphertext,
            auth_tag=tag
        )
        
        serialized = msg.to_bytes()
        
        # Adversary modifies ciphertext
        modified = bytearray(serialized)
        modified[30] ^= 0xFF
        modified = bytes(modified)
        
        # Deserialize
        received_msg = ProtocolMessage.from_bytes(modified)
        
        # Decryption should fail
        from cryptography.exceptions import InvalidTag
        with pytest.raises(InvalidTag):
            crypto.decrypt(
                received_msg.ciphertext,
                key,
                received_msg.nonce,
                received_msg.auth_tag
            )


if __name__ == "__main__":
    # Run tests
    pytest.main([__file__, "-v"])
