Keyless Entry System Security Enhancement Project
Overview
This project focuses on enhancing the security of keyless entry systems against relay attacks. Using Decawave's MDEK1001 module, we implemented a solution that employs Diffie-Hellman encryption and Two-Way Ranging (TWR) methods to secure communication between the key fob and the vehicle.
Project Description
Keyless entry systems are vulnerable to relay attacks, where attackers intercept and relay signals between a key fob and a vehicle, allowing unauthorized access. This project aims to mitigate such vulnerabilities by integrating UWB signals.
Software Implementation
The software utilizes:
Diffie-Hellman Encryption: To establish a secure communication channel.
Two-Way Ranging (TWR): To measure the distance between devices accurately, ensuring proximity verification.
Code Structure
Encryption: Implementing Diffie-Hellman.
Ranging: Using TWR for distance measurement.
GPIO Control: Managing interactions with the keyless entry system.
