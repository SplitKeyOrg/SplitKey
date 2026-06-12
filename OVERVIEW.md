# SplitKey

**Recording Without Surveillance**

SplitKey is an open-source system that enables communities to maintain security camera recordings while preventing surveillance abuse. Using threshold cryptography (Shamir's Secret Sharing), footage is encrypted so that no single person can access it—a quorum of trusted community keyholders must agree before any recording can be released.

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
- Multiple trusted keyholders each hold one key share
- A quorum (e.g., 3-of-5 keyholders) must agree to release footage
- All releases are logged and the community is notified

**No single person—not the property manager, not a keyholder, not law enforcement—can access footage alone.**

---

## Core Concepts & Terminology

### Roles

| Term | Definition |
|------|------------|
| **Keyholder** | A trusted community member who holds a key share and participates in release decisions |
| **Approver** | A keyholder who has approved and participated in a release of footage
| **Requester** | A person requesting access to footage (resident, victim, management, law enforcement) |

### System Components

| Term | Definition |
|------|------------|
| **Storage** | The local server/application that encrypts and stores footage from cameras |
| **Keyholder App** | Desktop application for keyholders to manage keys and respond to release requests |
| **Portal** | Optional web interface for submitting and managing release requests |

### Cryptographic Terms

| Term | Definition |
|------|------------|
| **Keyholder Keys** | The key shares distributed to keyholders, derived from Shamir's Secret Sharing |
| **Window Key** | The specific encryption key for a rolling time period (epoch) |
| **Threshold** | The minimum number of keyholders required to reconstruct a key (e.g., 3-of-5) |

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
| **Summons** | Notification sent to keyholders when a release request is submitted |
| **Attestation** | A keyholder's submission of their key share in response to a request |
| **Threshold Met** | When enough keyholders have submitted attestations to reconstruct the key |
| **Disclosure Notice** | Public notification to the community that a release has occurred |

### Setup Terms

| Term | Definition |
|------|------------|
| **Key Ceremony** | The initial process of generating and distributing keyholder keys |
| **Key Acceptance** | A keyholder formally accepting responsibility for their key share |
| **Enrollment** | The process of onboarding a new keyholder |

---

## Principles

1. **Privacy by default**: Footage is encrypted immediately; no one can view it without consensus
2. **Distributed trust**: No single point of control or failure
3. **Transparency**: All releases are logged and disclosed to the community
4. **Accountability**: Keyholders are known; their participation is recorded
5. **Bounded access**: Security boundaries limit how much footage can be released at once
6. **Community governance**: The community chooses its own keyholders and threshold

---

## Project Components

### 1. Information Website (`website/`)
Educational site explaining the concept, providing implementation guides, and hosting documentation.

### 2. SplitKey Sealer (Sealer/)
Server application that integrates with cameras to encrypt footage as it's created.

### 3. SplitKey Keyholder (future)
Desktop application for keyholders to securely store keys and participate in releases.
