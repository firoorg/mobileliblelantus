# lelantus

Lelantus is Firo’s next generation privacy protocol which improves on Sigma by removing the requirement of fixed denominations
 allowing people to burn arbitrary amounts and redeem partial amounts without revealing values or the source.
 Lelantus doesn’t require any trusted setup and uses only DDH assumptions.
 It also supports untraceable direct anonymous payments by allowing people to pass the right to redeem to someone else.
 Lelantus is Firo’s own innovation described in [https://lelantus.io/].

### Directory layout

````
   .
   ├── src              # Source code for the protocol & schema
   ├── bitcoin          # Slightly modified source code from bitcoin
   ├── secp256k1        # Slightly modified source code from secp256k1
   ├── tests            # Test executables
   ├── build            # Script to build executables in tests (Linux & MacOS)
   ├── run_all_tests    # Script to run all tests together
   └── README.mdℤ
````


The code can be compiled using the following command from the root directory of the repository.

``./build <directory>``

For example, ``build ~/macos`` will put the executables ``protocol_tests``, ``challenge_generator_tests``, ``coin_tests``, ``inner_product_test``, ``joinsplit_tests``, ``lelantus_primitives_tests``, ``range_proof_test``, ``serialize_test``, ``sigma_extended_test`` and ``schnorr_test`` in the directory ``~/macos``.


### Group

 The elliptic curve group ``secp256k1`` used in Bitcoin.

### Executables

### ``protocol_tests``

The executable protocol_tests runs Lelantus proof generation and verification tests. It creates random anonymity sets, puts there there coins, generates proofs and tries to verify

### ``challenge_generator_tests``

The executable challenge_generator_tests creates various types of challenges, used in Lelantus protocol, and checks correctness of challenges

### ``coin_tests``

The executable coin_tests creates coins and runes several checks on them

### ``inner_product_test``

The executable inner_product_test creates inner profuct proofs and tries to verify running InnerProductProofVerifier

### ``joinsplit_tests``

The executable joinsplit_tests runs tests for whole schema.

### ``lelantus_primitives_tests``

The executable lelantus_primitives_tests runs tests for primitives used in Lelantus protocol

### ``schnorr_test``

The executable schnorr_test creates Schnorr proofs and tires to verify them for checking the correctness of creation and verification of the proof.

### ``range_proof_test``

The executable range_proof_test creates Bulletproofs Range proofs and tires to verify them for checking the correctness of creation and verification of the proof.

### ``sigma_extended_test``

The executable sigma_extended_test creates Sigma proofs and tires to verify them for checking the correctness of creation and verification of the proof.

### ``serialize_test``

The executable serialization_test runs tests for EC Group element, Scalar, InnerProduct proof, Range proof, Schnorr proof, Sigma  and Sigma proofs. It serializes the object, deserializes it to another object and compares them.


````
