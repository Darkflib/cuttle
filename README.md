# Cuttle

![Cuttle Logo](https://raw.githubusercontent.com/Darkflib/cuttle/main/cuttle-800.png)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python Version](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.95.2-blue.svg)](https://fastapi.tiangolo.com/)
[![Uvicorn](https://img.shields.io/badge/Uvicorn-0.22.0-blue.svg)](https://www.uvicorn.org/)

A certificate lifecycle management system with a finite state machine approach.

## Overview

Cuttle is a FastAPI-based service that manages SSL/TLS certificates through their entire lifecycle using a finite state machine (FSM) approach. It tracks certificate states such as unissued, requesting, validating, issued, and handles transitions between states.

The API provides a dashboard and endpoints to manage domains and their certificates, with a special focus on automating the certificate lifecycle.

## Features

- **FSM-based Certificate Management**: Manage certificates through a defined lifecycle with clear state transitions
- **RESTful API**: Complete API for certificate management operations
- **Certificate Operations**: Issue, renew, and revoke certificates
- **Status Monitoring**: Check certificate status and expiration
- **Mock Testing**: Test with a certbot mock without making actual API calls

## State Machine

The certificate lifecycle is managed through the following states:

- `unissued`: Initial state for new domains
- `requesting`: Certificate issuance in progress
- `validating`: Domain validation in progress
- `issued`: Certificate successfully issued and active
- `renewing`: Certificate renewal in progress
- `renewed`: Certificate successfully renewed
- `failed`: Certificate operation failed
- `expired`: Certificate has expired
- `revoked`: Certificate has been revoked
- `invalid`: Certificate is invalid

## API Endpoints

### Core Endpoints

- `GET /`: Root endpoint with API information
- `GET /health`: Health check endpoint
- `GET /fsm/states`: Get all possible certificate states
- `GET /fsm/transitions`: Get all possible state transitions
- `GET /fsm/transitions/{state}`: Get transitions available from a specific state

### Domain Management

- `POST /domains/`: Create a new domain entry
- `GET /domains/`: List all domains
- `POST /domains/{domain}/transition/{event}`: Trigger a state transition

### Certificate Operations

- `POST /certbot/issue/{domain}`: Trigger certificate issuance
- `POST /certbot/renew/{domain}`: Trigger certificate renewal
- `POST /certbot/revoke/{domain}`: Trigger certificate revocation
- `GET /certbot/status/{domain}`: Check certificate status

## Installation

### Prerequisites

- Python 3.11+
- SQLite (for development) or PostgreSQL (for production)

### Setup

1. Clone the repository:

```bash
git clone https://github.com/Darkflib/cuttle.git
cd cuttle
```

2. Set up a virtual environment:

```bash
uv venv .venv
. .venv/bin/activate  # On Unix/Linux
# or
.\.venv\Scripts\activate  # On Windows
```

3. Install dependencies:

```bash
uv pip install -r requirements.txt
```

4. Run the application:

```bash
python app.py
```

The API will be available at http://localhost:8000.

## Usage

### Adding a New Domain

```bash
curl -X POST "http://localhost:8000/domains/?domain=example.com"
```

### Issuing a Certificate

```bash
curl -X POST "http://localhost:8000/certbot/issue/example.com"
```

### Checking Certificate Status

```bash
curl "http://localhost:8000/certbot/status/example.com"
```

### Renewing a Certificate

```bash
curl -X POST "http://localhost:8000/certbot/renew/example.com"
```

### Revoking a Certificate

```bash
curl -X POST "http://localhost:8000/certbot/revoke/example.com"
```

## Development

### Database

The application uses SQLite for development:

```python
engine = create_engine("sqlite:///certfsm.db")
```

For production, consider using PostgreSQL.

### Testing

Test the API using the certbot mock which simulates certificate operations without making actual calls to certificate authorities.

## License

MIT

## Author

Mike (Darkflib) - darkflib@gmail.com
