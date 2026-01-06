- ADCS Introduction PREVIEW
- Introduction to ADCS Misconfigurations
- ADCS Enumeration
- ESC1
- ESC2
- ESC3
- Certificate Mapping
- ESC9
- ESC10
- ESC6
- ESC4
- ESC7
- ESC5
- ESC8
- ESC11
- Certifried (CVE-2022-26923)
- PKINIT
- Using BloodHound with Certipy
- Skills Assessment
Organizations utilizing Active Directory rely on Active Directory Certificate Services (ADCS) to build and maintain their internal Public Key Infrastructure (PKI), enabling them to issue and manage digital certificates. Digital certificates are essential for establishing secure communication channels, enabling encryption, and serving as cryptographic credentials that authenticate the identities of users, devices, and services, among other functionalities.

However, despite its many benefits, ADCS is a vast and complex system, making it prone to various misconfigurations that can open the door to attacks, particularly domain escalation. Not only do system administrators neglect to ensure a robust ADCS security posture, but they often misunderstand its workings.

In this module, we will learn about the various domain escalation scenarios caused by ADCS misconfigurations, covering all of the ones released by SpecterOps and those discovered later. After thoroughly comprehending each domain escalation scenario, we will learn how to abuse these misconfigurations from Windows and Linux systems, allowing us to escalate privileges horizontally and vertically and move laterally across a domain.

This module is broken into sections with accompanying hands-on exercises to practice each of the tactics and techniques we cover. The module ends with a practical hands-on skills assessment to gauge your understanding of the various topic areas.

You can start and stop the module at any time and pick up where you left off. There is no time limit or "grading," but you must complete all of the exercises and the skills assessment to receive the maximum number of cubes and have this module marked as complete in any paths you have chosen.

As you work through the module, you will see example commands and command output for the various topics introduced. It is worth reproducing as many of these examples as possible to reinforce further the concepts presented in each section. You can do this in the PwnBox provided in the interactive sections or your virtual machine.

A firm grasp of the following modules can be considered a prerequisite for the successful completion of this module:

- Active Directory Enumeration & Attacks
- Kerberos Attacks
# ADCS Introduction

In the dynamic landscape of digital security, `Active Directory Certificate Services (ADCS)` stands as a cornerstone technology. ADCS empowers organizations to establish and manage their own `Public Key Infrastructure (PKI)`, a foundation for secure communication, user authentication, and data protection. This introduction serves as a gateway to the world of ADCS, encompassing key elements such as `Certificate Authority (CA)`, `digital certificates`, `PKI architecture`, and their role in fortifying the bedrock of modern network security.

In the initial three sections, our attention will be on exploring the fundamental concepts and terminology related to ADCS. Following this, we'll delve into how to enumerate and attack misconfigured ADCS services.

---

## Public Key Infrastructure (PKI)

`Public Key Infrastructure (PKI)` is a system that uses digital certificates and public key cryptography to provide secure communication over unsecured networks, such as the Internet. PKI enables digital signatures, encryption, and authentication of electronic documents, email messages, and other forms of online communication.

A digital certificate is an electronic document that binds a public key to a person, organization, device, or service. It is issued and signed by a trusted `Certificate Authority (CA)`, which verifies the identity of the certificate holder and the integrity of the public key. The certificate includes the public key, the name of the subject, the name of the issuer, the validity period, and other attributes.

Benefits of PKI:

- Confidentiality: The PKI allows you to encrypt data is that is stored or transmitted.
- Integrity: A digital signature identifies whether the data is modified while the data is transmitted.
- Authenticity: A message digest is digitally signed using the sender’s private key. Because the digest can be decrypted only with the sender’s corresponding public key, it proves that the message can come only from the sending user (non-repudiation).

Advantages of ADCS over PKI:

- Tight integration with AD DS, which simplifies certificate management and authentication within enterprise organizations that use Active Directory
- Built-in support for certificate revocation using the Certificate Revocation List (CRL) and the Online Certificate Status Protocol (OCSP).
- Support for custom certificate templates, which allows administrators to define the attributes, extensions, and policies of the certificates issued by AD CS.
- Scalability and redundancy, which allows multiple CAs to be deployed in a hierarchy or a load-balanced cluster.

---

## What is ADCS?

`Active Directory Certificate Services (AD CS)` is a Windows server role that enables organizations to establish and manage their own Public Key Infrastructure (PKI).

AD CS integrates with Active Directory Domain Services (AD DS), which is a centralized database of users, computers, groups, and other objects in a Windows network.

AD CS can be used to secure various network services, such as Secure Socket Layer/Transport Layer Security (SSL/TLS), Virtual Private Network (VPN), Remote Desktop Services (RDS), and Wireless LAN (WLAN). It can also issue certificates for smart cards and other physical tokens, which can be used to authenticate users to network resources. The private key stored on the smart card or token is then used to authenticate the user to the network.

Active Directory Certificate Services includes:

1. Digital Certificates
2. Certificate Authority
    1. Stand-alone CA or Enterprise CA
    2. Root CA or Subordinate CA
3. Certificate Templates
4. Key Pair Generation
5. Certificate Revocation
6. Secure Communication
7. Digital Signatures
8. Encryption and Decryption
9. Enhanced Security and Identity Management

---

## Essential ADCS Terminology

Active Directory Certificate Services (ADCS) orchestrates a symphony of cryptographic intricacies that underpin modern security. This technology empowers organizations to establish and manage their Public Key Infrastructure (PKI), facilitating secure communication, data integrity, and user authentication.

In the dynamic landscape of digital security, ADCS serves as a pivotal player, seamlessly weaving together the threads of trust and encryption. At its core lies the concept of `Certificate Authority (CA)`, a sentinel that issues and manages digital certificates. These certificates play the role of digital passports, vouching for the authenticity of users, devices, or services within a network.

ADCS orchestrates a complex process of protection, where digital certificates and private keys work together like partners to keep data safe and unaltered. This technology creates a network of trust, allowing different parties to communicate with confidence, knowing that their identities are confirmed, and their conversations are kept private from unauthorized observers.

Navigating the landscape of digital security necessitates a firm grasp of `Active Directory Certificate Services (ADCS)` fundamentals. This exploration aims to demystify ADCS concepts. Delving into these core terms will illuminate the essential components to assimilate better how we will abuse ADCS.

## Key Terminologies in ADCS:

- `Certificate Templates`: These predefined configurations dictate the properties and usage of certificates issued by AD CS. They encompass settings like certificate purpose, key size, validity period, and issuance policies. AD CS offers standard templates (e.g., Web Server, Code Signing) while empowering administrators to craft custom templates catering to specific business requisites.
    
- `Public Key Infrastructure (PKI)`: A comprehensive system integrating hardware, software, policies, and procedures for creating, managing, distributing, and revoking digital certificates. It houses Certification Authorities (CAs) and registration authorities validating entities involved in electronic transactions via public key cryptography.
    
- `Certificate Authority (CA)`: This component issues certificates to users, computers, and services while overseeing certificate validity management.
    
- `Certificate Enrollment`: Entities request certificates from CAs, where verification of the requester's identity precedes certificate issuance.
    
- `Certificate Manager`: Responsible for certificate issuance, management, and authorization of enrollment and revocation requests.
    
- `Digital Certificate`: An electronic document housing identity details, such as user or organizational names, and a corresponding public key. These certificates serve for authentication, proving a person's or device's identity.
    
- `Certificate Revocation`: ADCS supports revoking certificates if they are compromised or no longer valid. Revocation can be managed through Certificate Revocation Lists (CRLs) or Online Certificate Status Protocol (OCSP).
    
- `Key Management`: ADCS provides mechanisms to manage private keys, ensuring their security and proper usage.
    
- `Backup Operator`: The backup operator backs up and restores files and directories. Backup operators are assigned using Active Directory Users and Computers or Computer Management. They can back up and restore the system state, including CA information, Start and stop the AD CS service, Possess the system backup user right, and Read records and configuration information in the CA database.
    
- `Standalone CA & Enterprise CA`: `Standalone CAs` operate autonomously without Active Directory, allowing manual or web-based certificate requests. In contrast, `Enterprise CAs`, reliant on Active Directory, issue certificates for users, devices, and servers within an organization, automating processes using Group Policy or Certificate Enrollment Web Services.
    
- `Certificate Signing Requests`: `Certificate Signing Requests (CSRs)` are requests submitted by users or devices to an ADCS CA to obtain a certificate. A CSR contains the user or device's public key and other identifying information, such as the certificate's subject name and intended usage. When a CSR is submitted to a CA, the CA verifies the requester's identity and performs various checks to ensure the integrity and validity of the CSR. If the CSR is approved, the CA issues a digital certificate that binds the requester's public key to their identity and intended usage.
    
- `Certificate Revocation List`: A digitally signed inventory issued by a CA cataloging revoked certificates. The CRL includes details of certificates invalidated by the CA, ensuring entities can verify the revoked status of specific certificates.
    
- `Extended/Enhanced Key Usages`: Certificate extensions delineating authorized uses for a certificate. EKUs allow administrators to restrict certificate usage to defined applications or scenarios, such as code signing, email encryption, or smart card logon. AD CS furnishes prebuilt EKUs like Server Authentication, Client Authentication, and Code Signing, empowering administrators to craft custom EKUs aligning with specific business requisites.
    

---

## ADCS Attack Scenario Examples:

In a corporate environment, AD CS is a vital component for secure communication. Attackers could exploit vulnerabilities in AD CS to gain unauthorized access and compromise critical resources. AD CS provides essential security services. Attackers can exploit misconfigurations or weak security practices to undermine its integrity.

- Scenario 1: Certificate Theft and Malicious Enrollments
- Scenario 2: Privilege Escalation through Misconfigured Template
- Scenario 3: Unauthorized CA Compromised
- Scenario 4: Malicious CA server introduction
- Scenario 5: Weak CA Administrator Password
- Scenario 6: CA Server Compromised