#!/usr/bin/env python3
"""
Generate self-signed certificates for secure chat demo.

Creates:
- CA certificate (ca.pem)
- Server certificate (server.pem, server.key)
- Client certificate (client.pem, client.key)
"""

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import datetime
import os


def generate_certificates():
    """Generate all required certificates."""
    
    print("=" * 60)
    print("  🔐 Generating TLS Certificates for Secure Chat")
    print("=" * 60)
    print()
    
    # Create certs directory if it doesn't exist
    if not os.path.exists('certs'):
        os.makedirs('certs')
        print("✅ Created certs/ directory")
    
    os.chdir('certs')
    
    # 1. Generate CA (Certificate Authority)
    print("📜 Generating CA certificate...")
    ca_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    
    ca_subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureChat Demo"),
        x509.NameAttribute(NameOID.COMMON_NAME, "SecureChat CA"),
    ])
    
    ca_cert = x509.CertificateBuilder().subject_name(
        ca_subject
    ).issuer_name(
        ca_subject
    ).public_key(
        ca_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=3650)  # 10 years
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=None), critical=True,
    ).sign(ca_key, hashes.SHA256())
    
    # Save CA certificate
    with open("ca.pem", "wb") as f:
        f.write(ca_cert.public_bytes(serialization.Encoding.PEM))
    
    print("   ✅ ca.pem")
    
    # 2. Generate Server Certificate
    print("🖥️  Generating server certificate...")
    server_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    
    server_subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureChat Demo"),
        x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
    ])
    
    server_cert = x509.CertificateBuilder().subject_name(
        server_subject
    ).issuer_name(
        ca_cert.subject
    ).public_key(
        server_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=365)
    ).add_extension(
        x509.SubjectAlternativeName([
            x509.DNSName("localhost"),
            x509.IPAddress(__import__('ipaddress').IPv4Address("127.0.0.1")),
        ]),
        critical=False,
    ).sign(ca_key, hashes.SHA256())
    
    # Save server certificate and key
    with open("server.pem", "wb") as f:
        f.write(server_cert.public_bytes(serialization.Encoding.PEM))
    
    with open("server.key", "wb") as f:
        f.write(server_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    print("   ✅ server.pem")
    print("   ✅ server.key")
    
    # 3. Generate Client Certificate
    print("💻 Generating client certificate...")
    client_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    
    client_subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureChat Demo"),
        x509.NameAttribute(NameOID.COMMON_NAME, "SecureChat Client"),
    ])
    
    client_cert = x509.CertificateBuilder().subject_name(
        client_subject
    ).issuer_name(
        ca_cert.subject
    ).public_key(
        client_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=365)
    ).sign(ca_key, hashes.SHA256())
    
    # Save client certificate and key
    with open("client.pem", "wb") as f:
        f.write(client_cert.public_bytes(serialization.Encoding.PEM))
    
    with open("client.key", "wb") as f:
        f.write(client_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    print("   ✅ client.pem")
    print("   ✅ client.key")
    
    os.chdir('..')
    
    print()
    print("=" * 60)
    print("  ✅ Certificate generation complete!")
    print("=" * 60)
    print()
    print("Files created in certs/ directory:")
    print("  - ca.pem         (Certificate Authority)")
    print("  - server.pem     (Server certificate)")
    print("  - server.key     (Server private key)")
    print("  - client.pem     (Client certificate)")
    print("  - client.key     (Client private key)")
    print()
    print("You can now run:")
    print("  python server_complete.py   (in one terminal)")
    print("  python client_complete.py   (in another terminal)")
    print()


if __name__ == "__main__":
    try:
        generate_certificates()
    except Exception as e:
        print(f"\n❌ Error generating certificates: {e}")
        import traceback
        traceback.print_exc()
