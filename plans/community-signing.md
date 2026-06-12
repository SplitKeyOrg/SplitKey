
# Need to design a key signing process


* offline pc with printer

Rough Process:
  * community meeting
  * one controller who does the PC stuff, thinking like a projector
  * prints out a set of keys, they key holdler goes and picks them up, no one else sees them

When incident occures, you can call in the key codes for that window.
Preferably the keys are words, SLIP-0039.   Note, need multi-lingual in the future.


Key Concepts
Daily keys — one unique keys per day.  Unlocking one day reveals nothing about any other day.
Keyholders — trusted community members who hold SSS shares. A quorum of any 2-of-N can unlock a specific day.
Annual ceremony — public meeting where that year's daily private keys are split into shares and distributed to keyholders on paper.

Requirements
Camera

Encrypts footage using that day's public key
Public keys loaded at installation via QR code shown to camera lens
Camera is write-only after installation
Cannot decrypt its own footage
Destroys any ephemeral key material after use

Key Generation

One keypair generated per camera per day
Generated on air-gapped machine at annual ceremony
Daily private key immediately SSS split after generation
Daily private key never stored anywhere after splitting
Daily public keys loaded onto camera at installation or via annual QR update

Annual Ceremony

Held publicly, town hall or similar
Air-gapped machine, thermal or laser printer
Each keyholder receives printed cards with share secret words
Keyholders sign public verification sheet
Machine and media destroyed after ceremony

Keyholders

Represent adversarial community interests
Each holds one SSS share per day
Shares stored on paper in personal safe
Any 2-of-N can reconstruct a daily private key
Personal keypairs used to sign unlock approvals

Unlock Procedure

Requestor files public unlock request specifying camera, date, reason
Two keyholders locate that day's card
Read BIP39 words over secure phone or in person
Air-gapped machine reconstructs daily private key
Decrypts only that day's footage
Daily private key destroyed immediately after
Unlock event published to public transparency log including who, when, why

Transparency Log

Append only, publicly readable
Every unlock event recorded with keyholder signatures
Cannot be modified or deleted
Citizens can audit all access

Key Update (annual)

New year's daily public keys delivered to camera via signed QR code
QR verified by camera against stored keyholder public keys
Requires signatures from quorum of keyholders to be valid
18 month key validity allows ceremony delays up to 6 months
