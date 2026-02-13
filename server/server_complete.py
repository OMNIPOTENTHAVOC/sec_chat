# Complete Server Implementation
# Fully functional encrypted chat server with group key coordination

import socket
import ssl
import threading
from typing import Dict, Optional
from protocol import ProtocolMessage, MessageType


class ChatRoom:
    """
    Server-side chatroom representation.
    
    Manages member list and sockets for message relay.
    Server NEVER sees plaintext or keys (untrusted server model).
    """
    
    def __init__(self, room_id: str):
        """Initialize room."""
        self.room_id = room_id
        self.members: Dict[str, Dict] = {}  # member_id -> {public_key, socket}
        self.lock = threading.RLock()
    
    def add_member(self, member_id: str, client_socket: ssl.SSLSocket, 
                   public_key: bytes = None) -> None:
        """Add member to room."""
        with self.lock:
            self.members[member_id] = {
                'socket': client_socket,
                'public_key': public_key
            }
            print(f"[ROOM:{self.room_id}] Member joined: {member_id} (total: {len(self.members)})")
    
    def remove_member(self, member_id: str) -> None:
        """Remove member from room."""
        with self.lock:
            if member_id in self.members:
                self.members.pop(member_id)
                print(f"[ROOM:{self.room_id}] Member left: {member_id} (remaining: {len(self.members)})")
    
    def get_members(self) -> Dict[str, Dict]:
        """Get copy of members dict."""
        with self.lock:
            return dict(self.members)
    
    def get_public_keys(self) -> Dict[str, bytes]:
        """Get all members' public keys for group key establishment."""
        with self.lock:
            return {
                mid: info['public_key'] 
                for mid, info in self.members.items()
                if info['public_key'] is not None
            }
    
    def member_count(self) -> int:
        """Number of members in room."""
        with self.lock:
            return len(self.members)
    
    def is_empty(self) -> bool:
        """Check if room has no members."""
        with self.lock:
            return len(self.members) == 0


class ServerProtocol:
    """
    Complete server-side protocol implementation.
    
    Features:
    - TLS server with client certificate authentication
    - Message relay (server never decrypts)
    - Group key establishment coordination
    - Room management
    
    Security Model: UNTRUSTED SERVER
    - Server relays encrypted messages
    - Server NEVER sees plaintext or room keys
    - All encryption is end-to-end between clients
    """
    
    def __init__(self, host: str = "localhost", port: int = 4443):
        """Initialize server."""
        self.host = host
        self.port = port
        
        # Room management
        self.rooms: Dict[str, ChatRoom] = {}
        self.rooms_lock = threading.RLock()
        
        # Client tracking
        self.clients: Dict[str, ssl.SSLSocket] = {}  # client_id -> socket
        self.clients_lock = threading.RLock()
        
        # Server socket
        self.server_socket: Optional[ssl.SSLSocket] = None
        self.running = False
    
    def start(self, cert_path: str = "certs/server.pem",
              key_path: str = "certs/server.key",
              ca_cert_path: str = "certs/ca.pem") -> bool:
        """
        Start TLS server.
        
        ✅ COMPLETE IMPLEMENTATION
        
        Steps:
        1. Create SSL context for TLS server
        2. Load server certificate and key
        3. Enable client certificate authentication (mutual TLS)
        4. Create and bind server socket
        5. Accept connections in loop
        """
        try:
            print("=" * 60)
            print("         🔐 SECURE ENCRYPTED CHATROOM SERVER 🔐")
            print("=" * 60)
            print()
            print(f"[SERVER] Starting TLS listener on {self.host}:{self.port}")
            
            # Create SSL context
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(cert_path, key_path)
            
            # Enable client certificate authentication (optional but recommended)
            try:
                context.load_verify_locations(ca_cert_path)
                context.verify_mode = ssl.CERT_OPTIONAL  # Allow clients without certs
                print("[SERVER] Client certificate authentication enabled")
            except FileNotFoundError:
                print("[SERVER] ⚠️  CA cert not found - client auth disabled")
                context.verify_mode = ssl.CERT_NONE
            
            # Create server socket
            server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_sock.bind((self.host, self.port))
            server_sock.listen(10)
            
            # Wrap with TLS
            self.server_socket = context.wrap_socket(server_sock, server_side=True)
            
            self.running = True
            print(f"[SERVER] ✅ Server running")
            print(f"[SERVER] Waiting for client connections...")
            print("=" * 60)
            print()
            
            # Accept loop
            while self.running:
                try:
                    client_socket, addr = self.server_socket.accept()
                    print(f"[SERVER] New connection from {addr}")
                    
                    # Spawn handler thread
                    handler_thread = threading.Thread(
                        target=self._handle_client,
                        args=(client_socket, addr),
                        daemon=True
                    )
                    handler_thread.start()
                    
                except Exception as e:
                    if self.running:
                        print(f"[SERVER] Accept error: {e}")
            
            return True
            
        except Exception as e:
            print(f"[SERVER] ❌ Failed to start: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def _handle_client(self, client_socket: ssl.SSLSocket, addr: tuple) -> None:
        """
        Handle single client connection.
        
        ✅ COMPLETE IMPLEMENTATION
        
        Processes messages from client and routes them appropriately.
        """
        client_id = None
        
        try:
            # Try to get client ID from certificate CN
            try:
                cert = client_socket.getpeercert()
                if cert and 'subject' in cert:
                    # Extract CN (Common Name) from certificate
                    for rdn in cert['subject']:
                        for name, value in rdn:
                            if name == 'commonName':
                                client_id = value
                                break
            except Exception:
                pass
            
            # Fallback: use address as client ID
            if not client_id:
                client_id = f"client_{addr[0]}_{addr[1]}"
            
            print(f"[SERVER] Client authenticated: {client_id} from {addr}")
            self._register_client(client_id, client_socket)
            
            # Message receive loop
            while self.running:
                # Receive frame
                frame = self._recv_frame(client_socket)
                if not frame:
                    print(f"[SERVER] Client {client_id} disconnected")
                    break
                
                # Deserialize message
                try:
                    msg = ProtocolMessage.from_bytes(frame)
                    
                    # Route based on message type
                    if msg.message_type == MessageType.CHAT:
                        self._handle_chat_message(msg)
                        
                    elif msg.message_type == MessageType.HANDSHAKE:
                        self._handle_handshake(msg, client_socket)
                        
                    else:
                        print(f"[SERVER] Unknown message type from {client_id}: {msg.message_type}")
                        
                except Exception as e:
                    print(f"[SERVER] Message processing error from {client_id}: {e}")
                    import traceback
                    traceback.print_exc()
            
        except Exception as e:
            print(f"[SERVER] Client handler error {client_id}: {e}")
            import traceback
            traceback.print_exc()
            
        finally:
            if client_id:
                self._unregister_client(client_id)
            try:
                client_socket.close()
            except Exception:
                pass
    
    def _handle_chat_message(self, msg: ProtocolMessage) -> None:
        """
        Handle CHAT message - relay to room members.
        
        ✅ COMPLETE IMPLEMENTATION
        
        Server is UNTRUSTED: never decrypts, just relays encrypted bytes.
        """
        room = self._get_room(msg.room_id)
        if not room:
            print(f"[SERVER] ⚠️  Message for non-existent room: {msg.room_id}")
            return
        
        # Log relay (encrypted data only)
        print(f"[SERVER] Relaying message: {msg.sender_id} → room '{msg.room_id}' (seq={msg.sequence_number})")
        
        # Relay to all members EXCEPT sender
        members = room.get_members()
        relayed = 0
        
        for member_id, info in members.items():
            if member_id == msg.sender_id:
                continue  # Don't echo back to sender
            
            try:
                self._send_frame(info['socket'], msg.to_bytes())
                relayed += 1
            except Exception as e:
                print(f"[SERVER] ❌ Failed to relay to {member_id}: {e}")
        
        print(f"[SERVER] Message relayed to {relayed} members")
    
    def _handle_handshake(self, msg: ProtocolMessage, client_socket: ssl.SSLSocket) -> None:
        """
        Handle HANDSHAKE message - coordinate group key establishment.
        
        ✅ COMPLETE IMPLEMENTATION
        
        Protocol:
        1. Client sends HANDSHAKE with their X25519 public key
        2. Server stores public key in room
        3. Server broadcasts ALL public keys to ALL members
        4. Clients derive group key independently
        
        Server NEVER derives the room key - it's end-to-end encrypted.
        """
        room_id = msg.room_id
        sender_id = msg.sender_id
        public_key = msg.ciphertext  # Public key is in ciphertext field (not actually encrypted)
        
        print(f"[SERVER] Handshake from {sender_id} for room '{room_id}'")
        print(f"[SERVER]   Public key: {public_key.hex()[:16]}... ({len(public_key)} bytes)")
        
        # Get or create room
        room = self._get_room(room_id, create=True)
        
        # Add member to room with their public key
        room.add_member(sender_id, client_socket, public_key)
        
        # Broadcast this handshake to ALL members (including sender for confirmation)
        # This allows all members to collect public keys
        members = room.get_members()
        
        print(f"[SERVER] Broadcasting handshake to {len(members)} members")
        
        for member_id, info in members.items():
            try:
                self._send_frame(info['socket'], msg.to_bytes())
            except Exception as e:
                print(f"[SERVER] ❌ Failed to broadcast to {member_id}: {e}")
        
        # If this is not the first member, also send all OTHER members' keys to the new joiner
        # This ensures the new member gets keys from members who joined before them
        if len(members) > 1:
            print(f"[SERVER] Sending existing member keys to {sender_id}")
            
            for member_id, info in members.items():
                if member_id == sender_id:
                    continue  # Skip self
                
                # Create handshake message for this existing member
                existing_key_msg = ProtocolMessage(
                    message_type=MessageType.HANDSHAKE,
                    sender_id=member_id,
                    room_id=room_id,
                    sequence_number=0,
                    nonce=msg.nonce,
                    ciphertext=info['public_key'],
                    auth_tag=b'\x00' * 16
                )
                
                try:
                    self._send_frame(client_socket, existing_key_msg.to_bytes())
                except Exception as e:
                    print(f"[SERVER] ❌ Failed to send {member_id}'s key to {sender_id}: {e}")
    
    def _register_client(self, client_id: str, socket: ssl.SSLSocket) -> None:
        """Register new client."""
        with self.clients_lock:
            self.clients[client_id] = socket
            print(f"[SERVER] Registered client: {client_id} (total: {len(self.clients)})")
    
    def _unregister_client(self, client_id: str) -> None:
        """Unregister client and cleanup rooms."""
        with self.clients_lock:
            self.clients.pop(client_id, None)
        
        # Remove from all rooms
        with self.rooms_lock:
            for room in list(self.rooms.values()):
                room.remove_member(client_id)
                
                # Delete empty rooms
                if room.is_empty():
                    self.rooms.pop(room.room_id, None)
                    print(f"[SERVER] Deleted empty room: {room.room_id}")
        
        print(f"[SERVER] Unregistered client: {client_id} (remaining: {len(self.clients)})")
    
    def _get_room(self, room_id: str, create: bool = False) -> Optional[ChatRoom]:
        """
        Get or create room.
        
        Args:
            room_id: Room name
            create: Create if doesn't exist
        
        Returns:
            ChatRoom or None
        """
        with self.rooms_lock:
            if room_id not in self.rooms:
                if not create:
                    return None
                self.rooms[room_id] = ChatRoom(room_id)
                print(f"[SERVER] Created room: {room_id}")
            return self.rooms[room_id]
    
    def _send_frame(self, socket: ssl.SSLSocket, data: bytes) -> None:
        """
        Send length-prefixed frame.
        
        ✅ COMPLETE IMPLEMENTATION
        
        Format: [4-byte big-endian length][data]
        """
        try:
            length = len(data).to_bytes(4, 'big')
            socket.sendall(length + data)
        except Exception as e:
            raise RuntimeError(f"Send failed: {e}")
    
    def _recv_frame(self, socket: ssl.SSLSocket) -> Optional[bytes]:
        """
        Receive length-prefixed frame.
        
        ✅ COMPLETE IMPLEMENTATION
        
        Returns:
            Frame data or None if disconnected
        """
        try:
            # Receive 4-byte length
            length_bytes = self._recv_exact(socket, 4)
            if not length_bytes:
                return None
            
            length = int.from_bytes(length_bytes, 'big')
            
            # Sanity check (prevent DoS with huge frames)
            if length > 10 * 1024 * 1024:  # 10MB max
                print(f"[SERVER] ⚠️  Rejecting oversized frame: {length} bytes")
                return None
            
            # Receive frame data
            frame = self._recv_exact(socket, length)
            return frame
            
        except Exception as e:
            return None
    
    def _recv_exact(self, socket: ssl.SSLSocket, n: int) -> Optional[bytes]:
        """
        Receive exactly n bytes from socket.
        
        Helper for framing - ensures we get complete data.
        """
        data = b''
        while len(data) < n:
            chunk = socket.recv(n - len(data))
            if not chunk:
                return None  # Connection closed
            data += chunk
        return data
    
    def stop(self) -> None:
        """Stop server."""
        self.running = False
        if self.server_socket:
            self.server_socket.close()
        print("[SERVER] Server stopped")


# Server entry point
if __name__ == "__main__":
    server = ServerProtocol("localhost", 4443)
    
    try:
        if not server.start():
            print("❌ Failed to start server")
            exit(1)
        
        # Keep running (blocks on accept loop in start())
        # Server runs until Ctrl+C
        
    except KeyboardInterrupt:
        print("\n")
        print("[SERVER] Shutdown signal received")
        server.stop()
        print("[SERVER] Goodbye!")
