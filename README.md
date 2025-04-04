# Phoenix Security Utilities

This repository contains a collection of utilities for interacting with Phoenix Security's APIs and services.

## Available Utilities

### Gating
Location: `/Gating`
- **Posture Gating**: Query and analyze vulnerability posture for applications and components
  - URL: `https://api.poc1.appsecphx.io/v1/components/posture`
  - URL: `https://api.poc1.appsecphx.io/v1/applications/posture`

### Client Container
Location: `/Client`
- **Vulnerability Upload**: Tools for uploading vulnerability data to Phoenix Security
  - URL: `https://api.poc1.appsecphx.io/v1/vulnerabilities/import`

## Environment Setup

### Prerequisites
- Python 3.x
- Docker (for container-based utilities)
- Phoenix Security API credentials
  - Client ID
  - Client Secret

### Authentication
All utilities use Phoenix Security's authentication endpoint:
```
https://api.poc1.appsecphx.io/v1/auth/access_token
```

### Base URLs
- Demo Environment: `https://api.demo.appsecphx.io`
- PoC Environment: `https://api.poc1.appsecphx.io`
- Production Environment: `https://api.securityphoenix.cloud`

## Getting Started

1. Clone this repository:
```bash
git clone <repository-url>
```

2. Set up your environment variables:
```bash
export CLIENT_ID="your-client-id"
export CLIENT_SECRET="your-client-secret"
```

3. Navigate to the desired utility directory and follow its specific README for detailed usage instructions.

## Directory Structure
```
.
├── README.md
├── Gating/
│   ├── README.md
│   └── phoenix_posture_gating.py
└── Client/
    └── ... (vulnerability upload utilities)
```

## Contributing

Please read our contributing guidelines before submitting pull requests.

## License

This project is licensed under the MIT License - see the LICENSE file for details. 