# Client Session State Management
# Tracks encryption keys, sequence numbers, room membership

from dataclasses import dataclass, field
from typing import Dict, Optional
from protocol import SequenceTracker, ReplayProtector
import os


@dataclass
class RoomState:
    """State for a single chatroom session."""
    room_id: str
    room_key: bytes  # Derived from group key establishment (32 bytes)
    members: Dict[str, bytes] = field(default_factory=dict)  # member_id -> public_key
    
    # Sequence tracking
    outgoing_sequence: SequenceTracker = field(default_factory=SequenceTracker)
    incoming_replay_check: ReplayProtector = field(default_factory=lambda: ReplayProtector(window_size=1000))
    
    # Metadata
    created_at: float = field(default_factory=lambda: __import__('time').time())
    
    def get_member_public_key(self, member_id: str) -> Optional[bytes]:
        """Get member's public key for DH exchange."""
        return self.members.get(member_id)
    
    def add_member(self, member_id: str, public_key: bytes) -> None:
        """Register new member public key."""
        if len(public_key) != 32:
            raise ValueError(f"Public key must be 32 bytes, got {len(public_key)}")
        self.members[member_id] = public_key
    
    def next_sequence(self) -> int:
        """Get next outgoing message sequence number."""
        return self.outgoing_sequence.next_sequence(self.room_id)
    
    def check_incoming_replay(self, sender_id: str, sequence_number: int) -> bool:
        """Check if incoming message is a replay attack."""
        return self.incoming_replay_check.check_and_update(sender_id, sequence_number)


@dataclass
class ClientSessionState:
    """Complete client session state."""
    client_id: str
    
    # Current room (can join/leave)
    current_room: Optional[RoomState] = None
    
    # All room states (for multi-room support)
    rooms: Dict[str, RoomState] = field(default_factory=dict)
    
    # Transport security
    tls_established: bool = False
    
    # Credentials
    private_key_bytes: Optional[bytes] = None  # X25519 private key
    
    def create_room(self, room_id: str, room_key: bytes) -> RoomState:
        """Create new room state."""
        if room_id in self.rooms:
            raise ValueError(f"Room {room_id} already exists")
        
        room = RoomState(room_id=room_id, room_key=room_key)
        self.rooms[room_id] = room
        return room
    
    def join_room(self, room_id: str) -> RoomState:
        """Switch to existing room."""
        if room_id not in self.rooms:
            raise ValueError(f"Room {room_id} not found")
        self.current_room = self.rooms[room_id]
        return self.current_room
    
    def leave_room(self) -> None:
        """Leave current room."""
        self.current_room = None
    
    def get_current_room_key(self) -> Optional[bytes]:
        """Get encryption key for current room."""
        if self.current_room is None:
            return None
        return self.current_room.room_key
    
    def mark_tls_established(self) -> None:
        """Mark transport security as established."""
        self.tls_established = True


# Example usage
if __name__ == "__main__":
    import os
    from crypto import CryptoEngine
    
    print("=== Client Session State Example ===")
    
    # Initialize client
    client = ClientSessionState(client_id="alice")
    print(f"Client ID: {client.client_id}")
    
    # Create a room
    room_key = os.urandom(32)
    room1 = client.create_room("lobby", room_key)
    print(f"Created room: {room1.room_id}")
    
    # Add members
    room1.add_member("bob", os.urandom(32))
    room1.add_member("charlie", os.urandom(32))
    print(f"Members: {list(room1.members.keys())}")
    
    # Join room and get sequence numbers
    client.join_room("lobby")
    seq1 = client.current_room.next_sequence()
    seq2 = client.current_room.next_sequence()
    print(f"Outgoing sequences: {seq1}, {seq2}")
    
    # Check for replay attacks (test)
    is_valid = client.current_room.check_incoming_replay("bob", 1)
    print(f"Message from bob seq=1: valid={is_valid}")
    
    is_replay = client.current_room.check_incoming_replay("bob", 1)
    print(f"Message from bob seq=1 (replay): valid={is_replay}")
    
    print("\n=== Multi-Room Support ===")
    room2 = client.create_room("dev", os.urandom(32))
    
    client.join_room("lobby")
    print(f"Current room: {client.current_room.room_id}")
    
    client.join_room("dev")
    print(f"Current room: {client.current_room.room_id}")
    
    # Each room has independent sequence counters
    lobby_seq = client.rooms["lobby"].next_sequence()
    dev_seq = client.rooms["dev"].next_sequence()
    print(f"Lobby sequence: {lobby_seq}, Dev sequence: {dev_seq}")
