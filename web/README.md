# RealGibber WebAssembly Demo

This directory contains a browser-based demonstration of RealGibber's WebAssembly capabilities, showcasing secure directional communication directly in web browsers.

## Features

- **Secure Protocol Handshake**: Complete ECDH key exchange and AES-GCM encryption in the browser
- **Real-time Messaging**: Send and receive encrypted messages with automatic state management
- **Cryptographic Utilities**: Generate nonces, compute HMAC, verify signatures
- **QR Code Generation**: Create and decode QR codes for visual communication
- **WebAssembly Performance**: Native-speed cryptography and protocol handling

## Quick Start

### Prerequisites

- Node.js 16+ and npm
- Rust 1.70+ with wasm-pack
- A modern web browser with WebAssembly support

### Installation

1. Install wasm-pack globally:
```bash
cargo install wasm-pack
```

2. Install npm dependencies:
```bash
cd web
npm install
```

### Building and Running

1. Build the WebAssembly module:
```bash
npm run build
```

2. Start the development server:
```bash
npm run serve
```

3. Open your browser to `http://localhost:8000`

## Demo Features

### 🔗 Secure Communication Protocol

- **Initiate Handshake**: Generate QR codes for secure pairing
- **Process QR Codes**: Scan and validate peer credentials
- **Real-time Status**: Monitor connection state and security status

### 💬 Secure Messaging

- **Encrypted Messages**: Send AES-GCM encrypted messages
- **Message Queue**: View pending messages with automatic processing
- **Priority Levels**: Support for different message priorities

### 🔐 Cryptographic Operations

- **Random Generation**: Generate cryptographically secure nonces and random bytes
- **HMAC Operations**: Compute and verify HMAC-SHA256 signatures
- **Key Management**: Handle public/private key operations

### 📱 QR Code Utilities

- **QR Generation**: Create QR codes with embedded cryptographic payloads
- **QR Decoding**: Parse and validate QR code data
- **Visual Communication**: Support for camera-based QR scanning

## Architecture

The WebAssembly demo consists of:

- **Rust Core**: `rgibberlink-core` compiled to WebAssembly
- **JavaScript Interface**: ES6 modules with async/await support
- **HTML/CSS UI**: Modern responsive design with real-time updates
- **Protocol Bridge**: Seamless communication between JS and WASM

## Security Considerations

- All cryptographic operations run in WebAssembly (native speed)
- No sensitive data leaves the browser
- Perfect forward secrecy with ECDH key exchange
- Anti-replay protection with timestamps and nonces

## Browser Compatibility

- Chrome 57+
- Firefox 52+
- Safari 11+
- Edge 16+

## Development

### Building for Development

```bash
npm run build:dev  # Faster builds with debug symbols
```

### Testing

The WebAssembly module includes comprehensive tests:

```bash
cd ../rgibberlink-core
cargo test --features wasm
```

### API Documentation

The WebAssembly API is automatically generated. Key classes:

- `WasmRgibberLink`: Main communication interface
- `WasmCryptoEngine`: Cryptographic utilities
- `WasmVisualEngine`: QR code operations

## Deployment

### Production Build

```bash
npm run build
```

This creates optimized WebAssembly binaries in `web/pkg/`.

### Static Hosting

The demo can be deployed to any static web host:

```bash
# Copy built files to your web server
cp -r web/* /path/to/web/server/
```

## Contributing

1. Make changes to the Rust code in `../rgibberlink-core/src/wasm.rs`
2. Rebuild: `npm run build`
3. Test in browser: `npm run serve`

## License

GPL-3.0 - See LICENSE file for details.