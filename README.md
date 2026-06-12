# SplitKey

**Recording Without Surveillance**

SplitKey is an open-source system that enables communities to maintain security camera recordings while preventing surveillance abuse. Using threshold cryptography (Shamir's Secret Sharing), footage is encrypted so that no single person can access it—a quorum of trusted community custodians must agree before any recording can be released.

---

## The Problem

Traditional surveillance systems create dangerous power imbalances:

- **Stalking & abuse**: Landlords, property managers, or bad actors with camera access can monitor individuals
- **Authoritarian overreach**: Centralized access enables mass surveillance
- **Single points of failure**: One compromised account exposes all footage
- **Breach liability**: Cloud-stored footage is a target for hackers
- **No accountability**: Who watches the watchers?

## The Solution

SplitKey implements **"custody, not control"**—footage exists for accountability, but access requires community consensus.

- Cameras record and immediately encrypt footage locally
- Encryption keys are split using Shamir's Secret Sharing
- Multiple trusted custodians each hold one key share
- A quorum (e.g., 3-of-5 custodians) must agree to release footage
- All releases are logged and the community is notified

**No single person—not the property manager, not a custodian, not law enforcement—can access footage alone.**

---

## Core Concepts & Terminology

### Roles

| Term | Definition |
|------|------------|
| **Custodian** | A trusted community member who holds a key share and participates in release decisions |
| **Witness** | A custodian who has participated in a release (they've now "witnessed" the footage access) |
| **Petitioner** | A person requesting access to footage (resident, victim, management, law enforcement) |

### System Components

| Term | Definition |
|------|------------|
| **Storage** | The local server/application that encrypts and stores footage from cameras |
| **Custodian App** | Desktop application for custodians to manage keys and respond to release requests |
| **Portal** | Optional web interface for submitting and managing release requests |

### Cryptographic Terms

| Term | Definition |
|------|------------|
| **Custodian Keys** | The key shares distributed to custodians, derived from Shamir's Secret Sharing |
| **Window Key** | The specific encryption key for a rolling time period (epoch) |
| **Threshold** | The minimum number of custodians required to reconstruct a key (e.g., 3-of-5) |

### Records & Data

| Term | Definition |
|------|------------|
| **Secured Records** | Encrypted footage that cannot be accessed without quorum approval |
| **Released Records** | Footage that has been decrypted following a successful release |
| **Security Boundary** | The time-based encryption epoch; limits how much footage can be released at once |

### Release Process Terms

| Term | Definition |
|------|------------|
| **Release** | The act of decrypting secured records after quorum approval |
| **Release Request** | A formal petition to access footage, including justification and time window |
| **Release Window** | The specific time range being requested (e.g., 12:00-14:00 on a given date) |
| **Summons** | Notification sent to custodians when a release request is submitted |
| **Attestation** | A custodian's submission of their key share in response to a request |
| **Threshold Met** | When enough custodians have submitted attestations to reconstruct the key |
| **Disclosure Notice** | Public notification to the community that a release has occurred |

### Setup Terms

| Term | Definition |
|------|------------|
| **Key Ceremony** | The initial process of generating and distributing custodian keys |
| **Key Acceptance** | A custodian formally accepting responsibility for their key share |
| **Enrollment** | The process of onboarding a new custodian |

---

## Principles

1. **Privacy by default**: Footage is encrypted immediately; no one can view it without consensus
2. **Distributed trust**: No single point of control or failure
3. **Transparency**: All releases are logged and disclosed to the community
4. **Accountability**: Custodians are known; their participation is recorded
5. **Bounded access**: Security boundaries limit how much footage can be released at once
6. **Community governance**: The community chooses its own custodians and threshold

---

## Project Components

### 1. Information Website (`website/`)
Educational site explaining the concept, providing implementation guides, and hosting documentation.

### 2. SplitKey Sealer (sealer/)
Server application that integrates with cameras to encrypt footage as it's created.

### 3. SplitKey Custodian (future)
Desktop application for custodians to securely store keys and participate in releases.

### 4. Model Legislation (future)
Template bylaws and policies for communities to adopt SplitKey governance.

---

## Development

### Website

The information website is built with [Hugo](https://gohugo.io/) using the [Hextra](https://github.com/imfing/hextra) theme.

```bash
cd website
hugo server
```

See `/website/README.md` for detailed development instructions.

---

## Taglines

- "Recording without surveillance"
- "Custody, not control"
- "Privacy through consensus"

---

## License

[TBD - recommend Apache 2.0 or MIT for maximum adoption]

---

## Contributing

[TBD]

---

## Contact

[TBD]
