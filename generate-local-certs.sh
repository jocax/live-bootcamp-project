#!/bin/bash

# Generate self-signed certificates for local TLS testing
# This script creates a complete PKI infrastructure for local development

set -e

# Configuration
CERT_DIR="certs/local"
CA_DIR="$CERT_DIR/ca"
DAYS_VALID=365

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Clean up existing certificates
if [ -d "$CERT_DIR" ]; then
    warn "Removing existing local certificates directory..."
    rm -rf "$CERT_DIR"
fi

# Create directory structure
log "Creating certificate directory structure..."
mkdir -p "$CA_DIR"
mkdir -p "$CERT_DIR/app-service"
mkdir -p "$CERT_DIR/auth-service"  
mkdir -p "$CERT_DIR/nginx"

# Generate CA certificate
log "Generating Certificate Authority (CA)..."

cat > "$CA_DIR/ca.conf" << EOF
[req]
default_bits = 2048
prompt = no
distinguished_name = req_distinguished_name
x509_extensions = v3_ca

[req_distinguished_name]
C = US
ST = Local
L = Development
O = Live Bootcamp Local CA
CN = Live Bootcamp Local Root CA

[v3_ca]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical,CA:true
keyUsage = critical, digitalSignature, cRLSign, keyCertSign
EOF

# Generate CA private key
openssl genrsa -out "$CA_DIR/ca.key" 2048

# Generate CA certificate
openssl req -new -x509 -days $DAYS_VALID -key "$CA_DIR/ca.key" -out "$CA_DIR/ca.crt" -config "$CA_DIR/ca.conf"

log "CA certificate generated successfully"

# Function to generate service certificate
generate_service_cert() {
    local service_name="$1"
    local service_dir="$CERT_DIR/$service_name"
    shift
    local hostnames=("$@")
    
    log "Generating certificate for $service_name..."
    
    # Create hostnames string for SAN
    local san_list=""
    local dns_count=1
    for hostname in "${hostnames[@]}"; do
        if [ $dns_count -eq 1 ]; then
            san_list="DNS:$hostname"
        else
            san_list="$san_list,DNS:$hostname"
        fi
        ((dns_count++))
    done
    
    # Create certificate configuration
    cat > "$service_dir/cert.conf" << EOF
[req]
default_bits = 2048
prompt = no
distinguished_name = req_distinguished_name
req_extensions = v3_req

[req_distinguished_name]
C = US
ST = Local
L = Development
O = Live Bootcamp Local
CN = $service_name

[v3_req]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
subjectAltName = $san_list
EOF

    # Generate private key
    openssl genrsa -out "$service_dir/key.pem" 2048
    
    # Generate certificate signing request
    openssl req -new -key "$service_dir/key.pem" -out "$service_dir/cert.csr" -config "$service_dir/cert.conf"
    
    # Generate certificate signed by our CA
    openssl x509 -req -days $DAYS_VALID \
        -in "$service_dir/cert.csr" \
        -CA "$CA_DIR/ca.crt" \
        -CAkey "$CA_DIR/ca.key" \
        -CAcreateserial \
        -out "$service_dir/cert.pem" \
        -extensions v3_req \
        -extfile "$service_dir/cert.conf"
    
    # Clean up CSR file
    rm "$service_dir/cert.csr"
    
    log "Certificate for $service_name generated with hostnames: ${hostnames[*]}"
}

# Generate certificates for each service
generate_service_cert "app-service" "app-service" "localhost" "127.0.0.1" "live-bootcamp.local"
generate_service_cert "auth-service" "auth-service" "localhost" "127.0.0.1" "live-bootcamp.local"  
generate_service_cert "nginx" "live-bootcamp.local" "localhost" "127.0.0.1"

# Set appropriate permissions
log "Setting certificate file permissions..."
chmod 644 "$CA_DIR/ca.crt"
chmod 600 "$CA_DIR/ca.key"

for service in app-service auth-service nginx; do
    chmod 644 "$CERT_DIR/$service/cert.pem"
    chmod 600 "$CERT_DIR/$service/key.pem"
done

# Display certificate information
log "Certificate generation complete!"
echo
log "Generated certificates:"
echo "  CA Certificate: $CA_DIR/ca.crt"
echo "  App Service: $CERT_DIR/app-service/cert.pem"
echo "  Auth Service: $CERT_DIR/auth-service/cert.pem"  
echo "  Nginx: $CERT_DIR/nginx/cert.pem"
echo
log "Certificate validity: $DAYS_VALID days"
echo
warn "To trust these certificates in your browser:"
echo "  1. Import $CA_DIR/ca.crt as a trusted root certificate"
echo "  2. Or accept security warnings when accessing https://live-bootcamp.local"
echo
log "Certificates are ready for use with Docker Compose!"