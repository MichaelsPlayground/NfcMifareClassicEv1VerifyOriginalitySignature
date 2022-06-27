# NFC NFCA Verify signature of NXP's NTAG21x

This app is verifying the ("originality") signature of a NTAG21x. 

Kindly note that the code for verification of the signature is taken from the application note  
AN11350, provided by NXP.

The Public Key is taken from the same document.

These are the specifications of the signature:
- Key type: Elliptic Curve
- Curve: SECP128R1
- Signature Scheme: ECDSA with NONE hashing
- Signature encoding: IEE P1363 (32 bytes R value, 32 bytes S value)

