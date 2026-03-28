# PrivMITLab Privacy Toolkit

**Block Everything. Trust Nothing. Control Everything.**

A complete offline privacy utility dashboard that runs 100% in your browser. No data is ever sent to any server.

![PrivMITLab](https://via.placeholder.com/800x400/111827/22d3ee?text=PrivMITLab+Privacy+Toolkit)

## Features

### 🛡️ Password Generator
- Cryptographically secure random passwords using `crypto.getRandomValues()`
- Adjustable length (6-64)
- Character type toggles (Upper, Lower, Numbers, Symbols)
- Real-time strength meter

### 🔐 Hash Generator
- Supports: **MD5**, **SHA-1**, **SHA-256**, **SHA-512**
- Text input or file upload
- Pure JavaScript MD5 implementation + Web Crypto API

### 🧹 Metadata Remover
- Removes EXIF, GPS, camera info from JPG, PNG
- Works on PDF files too
- Clean file download

### 🔒 File Encryptor / Decryptor
- AES-256-GCM encryption using Web Crypto API
- Password-based key derivation (PBKDF2)
- Secure IV generation
- Encrypt or decrypt files locally

### 📡 Privacy Score Scanner
- Mock privacy analysis for any website
- Shows estimated tracker count and risk level
- Educational demonstration of what privacy analysis looks like

## Privacy Principles

- **Zero telemetry**
- **Zero analytics**
- **Zero external APIs**
- **Zero tracking**
- **Everything runs locally**

> "This toolkit runs entirely inside your browser. No data is uploaded or stored anywhere."

## Tech Stack

- React 19 + TypeScript
- Vite
- Tailwind CSS
- Web Crypto API
- Lucide Icons

## Development

```bash
npm install
npm run dev
```

## Deployment

This project is optimized for Vercel. Just connect your GitHub repository.

```bash
npm run build
```

The build includes a single-file optimized output with all assets inlined.

## Project Structure

```
privmitlab-privacy-toolkit/
├── src/
│   ├── App.tsx          # Main dashboard + all tools
│   ├── main.tsx
│   └── index.css
├── public/
│   └── favicon.svg
├── index.html
├── vite.config.ts
├── package.json
└── README.md
```

## Security

- Uses `crypto.subtle` for all encryption
- Passwords never leave the browser
- No file is uploaded to any server
- All operations are sandboxed

---

Made with ❤️ for privacy-conscious users.

**PrivMITLab** — Taking back control of your digital privacy.
