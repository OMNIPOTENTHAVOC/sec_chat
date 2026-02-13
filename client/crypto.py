# Cryptographic Operations Module
# All AEAD encryption, key generation, nonce generation

import os
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from typing import Literal, Tuple

class CryptoEngine:
    """
    Handles all cryptographic operations: AEAD encryption, key derivation.
    
    Supports:
    - AES-256-GCM (default)
    - ChaCha20-Poly1305 (alternative)
    
    All operations are deterministic except nonce/salt generation.
    """
    
    # Cipher constants
    CIPHER_AES = "aes-256-gcm"
    CIPHER_CHACHA = "chacha20-poly1305"
    
    # Key sizes (bytes)
    KEY_SIZE = 32          # 256-bit keys
    NONCE_SIZE_GCM = 12    # 96-bit nonce for GCM
    NONCE_SIZE_CHACHA = 12 # 96-bit nonce for ChaCha20-Poly1305
    AUTH_TAG_SIZE = 16     # 128-bit authentication tag
    
    def __init__(self, cipher: Literal["aes-256-gcm", "chacha20-poly1305"] = "aes-256-gcm"):
        """
        Initialize crypto engine with selected cipher.
        
        Args:
            cipher: Either "aes-256-gcm" (default) or "chacha20-poly1305"
        """
        self.cipher = cipher
        if cipher not in [self.CIPHER_AES, self.CIPHER_CHACHA]:
            raise ValueError(f"Unsupported cipher: {cipher}")
    
    def encrypt(
        self,
        plaintext: bytes,
        key: bytes,
        nonce: bytes = None,
        aad: bytes = None
    ) -> Tuple[bytes, bytes, bytes]:
        """
        Encrypt plaintext with AEAD.
        
        Args:
            plaintext: Data to encrypt
            key: 32-byte encryption key
            nonce: 12-byte nonce (randomly generated if None)
            aad: Associated authenticated data (optional)
        
        Returns:
            Tuple of (ciphertext, nonce, auth_tag)
        
        Raises:
            ValueError: If key size is incorrect
        """
        if len(key) != self.KEY_SIZE:
            raise ValueError(f"Key must be {self.KEY_SIZE} bytes, got {len(key)}")
        
        # Generate random nonce if not provided
        if nonce is None:
            nonce = os.urandom(self.NONCE_SIZE_GCM)
        
        if self.cipher == self.CIPHER_AES:
            cipher_obj = AESGCM(key)
            # AESGCM.encrypt() returns ciphertext + tag concatenated
            ct_with_tag = cipher_obj.encrypt(nonce, plaintext, aad)
            # Split ciphertext and authentication tag
            ciphertext = ct_with_tag[:-self.AUTH_TAG_SIZE]
            auth_tag = ct_with_tag[-self.AUTH_TAG_SIZE:]
        else:  # ChaCha20-Poly1305
            cipher_obj = ChaCha20Poly1305(key)
            ciphertext, auth_tag = cipher_obj.encrypt_and_digest(nonce, plaintext, aad)
        
        return ciphertext, nonce, auth_tag
    
    def decrypt(
        self,
        ciphertext: bytes,
        key: bytes,
        nonce: bytes,
        auth_tag: bytes,
        aad: bytes = None
    ) -> bytes:
        """
        Decrypt ciphertext with AEAD authentication.
        
        Args:
            ciphertext: Encrypted data
            key: 32-byte decryption key (must match encryption key)
            nonce: 12-byte nonce (must match encryption nonce)
            auth_tag: 16-byte authentication tag from encryption
            aad: Associated authenticated data (must match encryption AAD)
        
        Returns:
            Decrypted plaintext
        
        Raises:
            cryptography.exceptions.InvalidTag: If authentication fails (tampering detected)
            ValueError: If key/nonce/tag sizes are incorrect
        """
        if len(key) != self.KEY_SIZE:
            raise ValueError(f"Key must be {self.KEY_SIZE} bytes, got {len(key)}")
        if len(auth_tag) != self.AUTH_TAG_SIZE:
            raise ValueError(f"Auth tag must be {self.AUTH_TAG_SIZE} bytes, got {len(auth_tag)}")
        
        if self.cipher == self.CIPHER_AES:
            cipher_obj = AESGCM(key)
            # Reconstruct ct_with_tag for AESGCM
            ct_with_tag = ciphertext + auth_tag
            plaintext = cipher_obj.decrypt(nonce, ct_with_tag, aad)
        else:  # ChaCha20-Poly1305
            cipher_obj = ChaCha20Poly1305(key)
            plaintext = cipher_obj.decrypt_and_verify(nonce, ciphertext, auth_tag, aad)
        
        return plaintext
    
    def generate_nonce(self) -> bytes:
        """
        Generate cryptographically random nonce.
        
        Returns:
            12-byte random nonce
        """
        return os.urandom(self.NONCE_SIZE_GCM)
    
    def generate_key(self) -> bytes:
        """
        Generate cryptographically random 256-bit key.
        
        Returns:
            32-byte random key
        """
        return os.urandom(self.KEY_SIZE)


class KeyDerivation:
    """
    HKDF-SHA256 based key derivation for group key establishment.
    
    Follows RFC 5869 and RFC 7748 best practices.
    """
    
    HASH_ALGORITHM = hashes.SHA256()
    DERIVED_KEY_SIZE = 32  # 256-bit keys
    
    @staticmethod
    def hkdf_expand(
        shared_secret: bytes,
        info: bytes,
        salt: bytes = None,
        output_length: int = 32
    ) -> bytes:
        """
        Perform HKDF key derivation.
        
        Follows: HKDF-Expand(Extract(salt, IKM), info, L)
        
        Args:
            shared_secret: Raw shared secret from X25519 exchange (32 bytes)
            info: Context label (e.g., b'room-key' or b'handshake-data')
            salt: Optional salt (random or context-specific)
            output_length: Number of bytes to derive (typically 32)
        
        Returns:
            Derived key of specified length
        
        Note:
            - salt=None is valid but uses zero bytes; consider random salt
            - info distinguishes different key purposes (binding)
            - Multiple DH pairs → multiple room keys all independently derived
        """
        hkdf = HKDF(
            algorithm=KeyDerivation.HASH_ALGORITHM,
            length=output_length,
            salt=salt,
            info=info,
        )
        return hkdf.derive(shared_secret)
    
    @staticmethod
    def derive_room_key(
        *shared_secrets: bytes,
        info: bytes = b'secure-chatroom-group-key'
    ) -> bytes:
        """
        Derive group room key from multiple X25519 exchanges.
        
        In multi-party DH:
        - Each participant performs DH with every other participant
        - All shared secrets are concatenated (or hashed together)
        - Final HKDF produces room key
        
        Args:
            *shared_secrets: One or more X25519 shared secrets (32 bytes each)
            info: Context label for room key
        
        Returns:
            256-bit room key
        
        Example:
            # 3-party group: Alice, Bob, Charlie
            # Each has: (A_priv, A_pub), (B_priv, B_pub), (C_priv, C_pub)
            
            # Alice computes:
            ss_ab = A_priv.exchange(B_pub)
            ss_ac = A_priv.exchange(C_pub)
            room_key = KeyDerivation.derive_room_key(ss_ab, ss_ac)
            
            # Bob computes (same result):
            ss_ba = B_priv.exchange(A_pub)
            ss_bc = B_priv.exchange(C_pub)
            room_key = KeyDerivation.derive_room_key(ss_ba, ss_bc)
            
            # Charlie computes (same result):
            ss_ca = C_priv.exchange(A_pub)
            ss_cb = C_priv.exchange(B_pub)
            room_key = KeyDerivation.derive_room_key(ss_ca, ss_cb)
        """
        if not shared_secrets:
            raise ValueError("At least one shared secret required")
        
        # Concatenate all shared secrets
        combined = b''.join(shared_secrets)
        
        # Derive single room key
        return KeyDerivation.hkdf_expand(combined, info)


class X25519KeyExchange:
    """
    X25519 elliptic curve Diffie-Hellman key exchange.
    
    Each party generates ephemeral keypair, exchanges public keys,
    performs DH to get shared secret (never transmitted).
    """
    
    KEY_SIZE = 32  # X25519 keys are always 32 bytes
    
    def __init__(self):
        """Initialize with new X25519 private key."""
        self.private_key = x25519.X25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()
    
    def get_public_bytes(self) -> bytes:
        """
        Get public key as raw bytes for transmission.
        
        Returns:
            32-byte public key (safe to transmit over untrusted network)
        """
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
    
    def get_private_bytes(self) -> bytes:
        """
        Get private key as raw bytes (for storage/debugging only).
        
        Returns:
            32-byte private key (KEEP SECRET)
        
        WARNING: Only call this for test/debug. Private keys should stay in memory.
        """
        return self.private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )
    
    def exchange(self, peer_public_bytes: bytes) -> bytes:
        """
        Perform X25519 key exchange with peer's public key.
        
        Args:
            peer_public_bytes: 32-byte public key from peer
        
        Returns:
            32-byte shared secret (never transmitted, used only for KDF)
        
        Raises:
            ValueError: If peer_public_bytes is not 32 bytes
        
        Security:
            - Shared secret is deterministic: same private + peer public always → same secret
            - Multiple DH pairs with same peer produce different secrets
            - Shared secret is NOT directly usable as encryption key - must run through HKDF
        """
        if len(peer_public_bytes) != self.KEY_SIZE:
            raise ValueError(f"Public key must be {self.KEY_SIZE} bytes, got {len(peer_public_bytes)}")
        
        peer_public_key = x25519.X25519PublicKey.from_public_bytes(peer_public_bytes)
        return self.private_key.exchange(peer_public_key)
    
    @staticmethod
    def load_public_key(public_bytes: bytes) -> x25519.X25519PublicKey:
        """
        Load X25519 public key from bytes (for peer public key).
        
        Args:
            public_bytes: 32-byte public key
        
        Returns:
            X25519PublicKey object
        """
        if len(public_bytes) != X25519KeyExchange.KEY_SIZE:
            raise ValueError(f"Public key must be {X25519KeyExchange.KEY_SIZE} bytes")
        return x25519.X25519PublicKey.from_public_bytes(public_bytes)


# Example usage (for documentation)
if __name__ == "__main__":
    # Example 1: Simple encryption
    print("=== Example 1: AES-256-GCM Encryption ===")
    engine = CryptoEngine("aes-256-gcm")
    key = engine.generate_key()
    plaintext = b"Secret message"
    
    ciphertext, nonce, tag = engine.encrypt(plaintext, key)
    print(f"Plaintext: {plaintext}")
    print(f"Ciphertext (hex): {ciphertext.hex()}")
    
    decrypted = engine.decrypt(ciphertext, key, nonce, tag)
    print(f"Decrypted: {decrypted}")
    assert decrypted == plaintext
    
    # Example 2: 3-party group key establishment
    print("\n=== Example 2: 3-Party X25519 Group Key ===")
    alice = X25519KeyExchange()
    bob = X25519KeyExchange()
    charlie = X25519KeyExchange()
    
    # Exchange public keys (via server)
    alice_pub = alice.get_public_bytes()
    bob_pub = bob.get_public_bytes()
    charlie_pub = charlie.get_public_bytes()
    
    # Each party computes shared secrets with others
    ss_ab = alice.exchange(bob_pub)
    ss_ac = alice.exchange(charlie_pub)
    alice_room_key = KeyDerivation.derive_room_key(ss_ab, ss_ac)
    
    ss_ba = bob.exchange(alice_pub)
    ss_bc = bob.exchange(charlie_pub)
    bob_room_key = KeyDerivation.derive_room_key(ss_ba, ss_bc)
    
    ss_ca = charlie.exchange(alice_pub)
    ss_cb = charlie.exchange(bob_pub)
    charlie_room_key = KeyDerivation.derive_room_key(ss_ca, ss_cb)
    
    print(f"Alice key:   {alice_room_key.hex()}")
    print(f"Bob key:     {bob_room_key.hex()}")
    print(f"Charlie key: {charlie_room_key.hex()}")
    print(f"Keys match: {alice_room_key == bob_room_key == charlie_room_key}")
