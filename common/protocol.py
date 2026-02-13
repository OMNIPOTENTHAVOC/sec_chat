# Protocol Message Formats and Validation
# Handles message serialization, replay protection, integrity checking

import struct
from dataclasses import dataclass
from typing import Dict, Set
from enum import IntEnum

class MessageType(IntEnum):
    """Message type constants for protocol."""
    HANDSHAKE = 1
    CHAT = 2
    HEARTBEAT = 3
    ERROR = 4


@dataclass
class ProtocolMessage:
    """
    Encrypted message in the protocol.
    
    Fields match design spec:
    - sender_id: Who sent this message
    - sequence_number: Monotonically increasing per sender (replay detection)
    - nonce: Random nonce for encryption
    - ciphertext: Encrypted payload
    - auth_tag: AEAD authentication tag
    - room_id: Which chatroom (for routing)
    """
    sender_id: str
    sequence_number: int
    room_id: str
    nonce: bytes
    ciphertext: bytes
    auth_tag: bytes
    message_type: MessageType = MessageType.CHAT
    
    def to_bytes(self) -> bytes:
        """
        Serialize message to bytes for transmission.
        
        Format (binary):
        [message_type:1][sender_id_len:1][sender_id:N][room_id_len:1][room_id:N]
        [sequence_number:8][nonce:12][ciphertext_len:4][ciphertext:N][auth_tag:16]
        
        Returns:
            Serialized message bytes
        """
        sender_id_bytes = self.sender_id.encode('utf-8')
        room_id_bytes = self.room_id.encode('utf-8')
        
        if len(sender_id_bytes) > 255:
            raise ValueError("sender_id too long (max 255 bytes)")
        if len(room_id_bytes) > 255:
            raise ValueError("room_id too long (max 255 bytes)")
        if len(self.nonce) != 12:
            raise ValueError(f"nonce must be 12 bytes, got {len(self.nonce)}")
        if len(self.auth_tag) != 16:
            raise ValueError(f"auth_tag must be 16 bytes, got {len(self.auth_tag)}")
        
        # Build packet
        packet = bytearray()
        packet.append(self.message_type)
        packet.append(len(sender_id_bytes))
        packet.extend(sender_id_bytes)
        packet.append(len(room_id_bytes))
        packet.extend(room_id_bytes)
        packet.extend(struct.pack('>Q', self.sequence_number))  # Big-endian 64-bit
        packet.extend(self.nonce)
        packet.extend(struct.pack('>I', len(self.ciphertext)))  # Big-endian 32-bit
        packet.extend(self.ciphertext)
        packet.extend(self.auth_tag)
        
        return bytes(packet)
    
    @staticmethod
    def from_bytes(data: bytes) -> 'ProtocolMessage':
        """
        Deserialize message from bytes.
        
        Args:
            data: Raw bytes from network
        
        Returns:
            Parsed ProtocolMessage
        
        Raises:
            ValueError: If message is malformed
        """
        if len(data) < 1 + 1 + 1 + 8 + 12 + 4 + 16:
            raise ValueError("Message too short")
        
        offset = 0
        
        # Parse message type
        message_type = MessageType(data[offset])
        offset += 1
        
        # Parse sender_id
        sender_id_len = data[offset]
        offset += 1
        sender_id = data[offset:offset + sender_id_len].decode('utf-8')
        offset += sender_id_len
        
        # Parse room_id
        room_id_len = data[offset]
        offset += 1
        room_id = data[offset:offset + room_id_len].decode('utf-8')
        offset += room_id_len
        
        # Parse sequence number
        sequence_number = struct.unpack('>Q', data[offset:offset + 8])[0]
        offset += 8
        
        # Parse nonce
        nonce = data[offset:offset + 12]
        offset += 12
        
        # Parse ciphertext length and ciphertext
        ciphertext_len = struct.unpack('>I', data[offset:offset + 4])[0]
        offset += 4
        ciphertext = data[offset:offset + ciphertext_len]
        offset += ciphertext_len
        
        # Parse auth tag (should be exactly 16 bytes)
        if offset + 16 != len(data):
            raise ValueError(f"Malformed message: expected {offset + 16} bytes, got {len(data)}")
        auth_tag = data[offset:offset + 16]
        
        return ProtocolMessage(
            message_type=message_type,
            sender_id=sender_id,
            room_id=room_id,
            sequence_number=sequence_number,
            nonce=nonce,
            ciphertext=ciphertext,
            auth_tag=auth_tag
        )


class ReplayProtector:
    """
    Sliding window replay detection per sender.
    
    Prevents replay attacks:
    - Duplicate sequence numbers rejected
    - Out-of-order messages (within window) accepted
    - Messages below window rejected
    
    Design:
    - Per-sender sequence number tracker
    - Sliding acceptance window (e.g., last 1000 messages)
    - Set of seen sequence numbers in current window
    """
    
    def __init__(self, window_size: int = 1000):
        """
        Initialize replay protector.
        
        Args:
            window_size: Maximum message numbers to track per sender
        """
        self.window_size = window_size
        # Map: sender_id -> (highest_seen, set of recent sequence numbers)
        self.state: Dict[str, tuple[int, Set[int]]] = {}
    
    def check_and_update(self, sender_id: str, sequence_number: int) -> bool:
        """
        Check if message is replay attack, update state if valid.
        
        Returns:
            True if message is valid (not a replay), False if replay detected
        
        Security:
            - First message from sender must have seq=0 or any initial value
            - Duplicate sequences rejected
            - Sequences below (highest - window) rejected
        """
        if sender_id not in self.state:
            # First message from this sender
            self.state[sender_id] = (sequence_number, {sequence_number})
            return True
        
        highest_seen, seen_set = self.state[sender_id]
        
        # Check if duplicate
        if sequence_number in seen_set:
            return False  # Replay detected
        
        # Check if below window
        window_floor = highest_seen - self.window_size
        if sequence_number < window_floor:
            return False  # Out of window (potential old replay)
        
        # Message is valid - update state
        if sequence_number > highest_seen:
            highest_seen = sequence_number
        
        # Add to seen set, remove old entries if window exceeded
        seen_set.add(sequence_number)
        if len(seen_set) > self.window_size:
            # Remove oldest entries
            to_remove = sorted(seen_set)[: len(seen_set) - self.window_size]
            for seq in to_remove:
                seen_set.discard(seq)
        
        self.state[sender_id] = (highest_seen, seen_set)
        return True
    
    def get_highest_sequence(self, sender_id: str) -> int:
        """Get highest sequence number seen from sender (-1 if none)."""
        if sender_id not in self.state:
            return -1
        return self.state[sender_id][0]


class SequenceTracker:
    """
    Outgoing message sequence numbers (per room for sender).
    
    Each sender maintains independent counter per room.
    """
    
    def __init__(self):
        """Initialize tracker."""
        # Map: room_id -> current sequence number
        self.counters: Dict[str, int] = {}
    
    def next_sequence(self, room_id: str) -> int:
        """
        Get next sequence number for message in room.
        
        Returns:
            Sequence number (incremented from last)
        """
        if room_id not in self.counters:
            self.counters[room_id] = 0
        else:
            self.counters[room_id] += 1
        
        return self.counters[room_id]
    
    def current_sequence(self, room_id: str) -> int:
        """Get current sequence number (without incrementing)."""
        return self.counters.get(room_id, -1)


# Example usage
if __name__ == "__main__":
    print("=== Protocol Message Example ===")
    
    # Create a message
    msg = ProtocolMessage(
        message_type=MessageType.CHAT,
        sender_id="alice",
        room_id="lobby",
        sequence_number=42,
        nonce=b'\x00' * 12,
        ciphertext=b'encrypted_data_here',
        auth_tag=b'\xFF' * 16
    )
    
    # Serialize
    serialized = msg.to_bytes()
    print(f"Serialized length: {len(serialized)} bytes")
    print(f"Serialized (hex): {serialized.hex()}")
    
    # Deserialize
    deserialized = ProtocolMessage.from_bytes(serialized)
    print(f"Deserialized sender: {deserialized.sender_id}")
    print(f"Deserialized seq: {deserialized.sequence_number}")
    assert deserialized.sender_id == msg.sender_id
    assert deserialized.sequence_number == msg.sequence_number
    
    print("\n=== Replay Detection Example ===")
    
    protector = ReplayProtector(window_size=100)
    
    # Valid sequence
    print(f"Sequence 1: {protector.check_and_update('alice', 1)}")  # True
    print(f"Sequence 2: {protector.check_and_update('alice', 2)}")  # True
    print(f"Sequence 3: {protector.check_and_update('alice', 3)}")  # True
    
    # Replay attempt
    print(f"Sequence 2 (replay): {protector.check_and_update('alice', 2)}")  # False
    print(f"Sequence 1 (replay): {protector.check_and_update('alice', 1)}")  # False
    
    # Out-of-order but in window
    print(f"Sequence 2.5 (OOO): {protector.check_and_update('bob', 5)}")  # True
    print(f"Sequence 4 (OOO): {protector.check_and_update('bob', 4)}")  # True (still valid, < 5)
    
    print("\n=== Sequence Tracker Example ===")
    
    tracker = SequenceTracker()
    print(f"Room1, msg 1: {tracker.next_sequence('room1')}")  # 0
    print(f"Room1, msg 2: {tracker.next_sequence('room1')}")  # 1
    print(f"Room2, msg 1: {tracker.next_sequence('room2')}")  # 0
    print(f"Room1, msg 3: {tracker.next_sequence('room1')}")  # 2
