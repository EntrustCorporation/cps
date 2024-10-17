---
title: Entrust Certificate Services
subtitle: Certification Practice Statement
version: 3.23
author:
  - Entrust
date: September 11, 2024

copyright: © 2024 Entrust Limited. All rights reserved
---


# 1. INTRODUCTION

Entrust Limited ("Entrust") uses its award winning suite of software products to provide standards-compliant digital certificates that enable more secure on-line communications.

The Entrust CAs issue Certificates, which include the following Certificate Types:

- OV TLS Certificate(s)
- EV TLS Certificate(s)
- Client Authentication Certificate(s)
- Code Signing Certificate(s)
- EV Code Signing Certificate(s)
- S/MIME Certificate(s)
- Document Signing Certificate(s)
- Time-Stamp Certificates(s)
- Verified Mark Certificate(s)

## 1.1 Overview

This CPS describes the practices and procedures of (i) the CAs, and (ii) RAs operating under the CAs. This CPS also describes the terms and conditions under which Entrust makes CA and RA services available in respect to Certificates. This CPS is applicable to all persons, entities, and organizations, including all Applicants, Subscribers, Relying Parties, Resellers, Co-marketers and any other persons, entities, or organizations that have a relationship with (i) Entrust in respect to Certificates and/or any services provided by Entrust in respect to Certificates, or (ii) any RAs operating under a CAs, or any Resellers or Co-marketers providing any services in respect to Certificates. This CPS is incorporated by reference into all Certificates issued by Entrust CAs. This CPS provides Applicants, Subscribers, Relying Parties, Resellers, Co-marketers and other persons, entities, and organizations with a statement of the practices and policies of the CAs and also of the RAs operating under the CAs. This CPS also provides a statement of the rights and obligations of Entrust, any third parties that are operating RAs under the CAs, Applicants, Subscribers, Relying Parties, Resellers, Co-marketers and any other persons, entities, or organizations that may use or rely on Certificates or have a relationship with a CA or a RA operating under a CA in respect to Certificates and/or any services in respect to Certificates.

In respect to OV TLS Certificates, Entrust conforms to the current version of the CA/Browser Forum Baseline Requirements for the Issuance and Management of Publicly-Trusted Certificates published at <https://www.cabforum.org>. The Baseline Requirements describe certain minimum requirements that a CA must meet in order to issue OV TLS Certificates. In the event of any inconsistency between this CPS and the Baseline Requirements, the Baseline Requirements take precedence over this CPS with respect to OV TLS Certificates.

In respect to EV TLS Certificates, Entrust conforms to the current version of the Guidelines for the Issuance and Management of Extended Validation Certificates published at <https://www.cabforum.org>. The EV SSL Guidelines describe certain minimum requirements that a CA must meet in order to issue EV TLS Certificates. In the event of any inconsistency between this CPS and the EV SSL Guidelines, the EV SSL Guidelines take precedence over this CPS with respect to EV TLS Certificates.

In respect to Code Signing Certificates, Entrust conforms to the current version of the Baseline Requirements for the Issuance and Management of Publicly-Trusted Code Signing Certificates published at <https://www.cabforum.org>. The Baseline Requirements for Code Signing describe the minimum requirements for Code Signing Certificates. If there is any inconsistency between this document and the Baseline Requirements for Code Signing, the Baseline Requirements for Code Signing take precedence over this document with respect to Code Signing Certificates.

Effective 1 September 2023, in respect to S/MIME Certificates, Entrust conforms to the current version of the Baseline Requirements for the Issuance and Management of Publicly-Trusted S/MIME Certificates published at <https://www.cabforum.org>. The S/MIME Baseline Requirements describe the minimum requirements for S/MIME Certificates. If there is any inconsistency between this document and the S/MIME Baseline Requirements, the S/MIME Baseline Requirements take precedence over this document with respect to S/MIME Certificates.

In respect to Verified Mark Certificates, Entrust conforms to the current version of the Minimum Security Requirements for Issuance of Verified Mark Certificates published at <https://bimigroup.org/supporting-documents/>. The VMC Requirements describe certain minimum requirements that a CA must meet in order to issue Verified Mark Certificates. If there is any inconsistency between this document and the VMC Requirements, the VMC Requirements take precedence over this document with respect to Verified Mark Certificates.

## 1.2 Document name and identification

This document is called the Entrust Certificate Services Certification Practice Statement.

### 1.2.1 Revisions

| Issue | Date               | Changes in this Revision |
| - | -- | ------- |
| 1.0   | May 26, 1999       | Initial version. |
| 2.0   | July 1, 2000       | Addition of provisions dealing with subordinate entities (such as third party registration authorities) in the Entrust.net SSL Web Server public key infrastructure. Revision of numerous other terms and conditions. |
| 2.01  | May 30, 2001       | Minor revisions having no substantive impact. |
| 2.02  | January 1, 2002    | Minor revisions related to replacement Cross Certificate. |
| 2.03  | January 1, 2003    | Entrust legal name change. |
| 2.04  | August 20, 2003    | Minor revisions related to use of certificates on more than one server; permitting use of asterisk in Subject name |
| 2.05  | November 28, 2003  | Minor revisions to language to handle licensing issues. |
| 2.06  | May 14, 2004       | Minor revisions to language for export requirements. |
| 2.1   | August 1, 2007     | Minor revisions to ensure consistency with the CPS for EV SSL Certificates and to add OCSP references. |
| 2.2   | August 11, 2008    | Minor revisions to terminology to replace references to Entrust SSL Web Server Certificates with Entrust SSL Certificates. Revision to authentication of individuals, routine rekey and key changeover. Other minor revisions having no substantive impact. |
| 2.3   | September 8, 2009  | Updates for Code Signing and Client Certificates. Added Appendix A with Certificate Profiles. Revisions to add additional application software vendors and relying parties as third party beneficiaries. Deleted Subscriber notice requirements. |
| 2.4   | August 16, 2010    | Updates for Class 1 and 2 Client Certificates and Document Signing Certificates |
| 2.5   | December 1, 2010   | Updates for Time-Stamp Certificates and end entity certificate key sizes |
| 2.6   | February 28, 2011  | Update disaster recovery, time-stamp authority and code signing certificate requirements |
| 2.7   | March 1, 2012      | Update to restrict use of certificates for MITM transactions or "traffic management"; Update to enable Entrust to request additional info from customers |
| 2.8   | June 25, 2012      | Update for compliance to Baseline Requirements |
| 2.9   | May 1, 2013        | Update for inclusion of data controls for certificate renewal, Private Key control, and subordinate CA certificates |
| 2.10  | December 1, 2013   | Support for smartcards and subordinate CA assessment |
| 2.11  | March 4, 2014      | Change to Loss Limitations |
| 2.12  | April 6, 2015      | Updated PKI hierarchy, SSL SHA-2 and added Certification Authority Authorization |
| 2.13  | February 12, 2016  | Update for Document Signing, Security Module and Subscriber obligations |
| 2.14  | March 7, 2016      | Remove references to 1024-bit root and update approved key sizes |
| 2.15  | September 19, 2016 | CT logging for SSL certificates, ECC key usage update and Document Signing key usage update |
| 2.16  | February 1, 2017   | Update for Minimum Requirements for Code Signing, minimum key size and validity period, changes to Definitions, Disclaimers, Loss Limitations and Conflict of Provisions |
| 2.17  | July 14, 2017      | Update for domain validation methods, inclusion of IP Address validation methods and update for CAA |
| 3.0   | May 31, 2018       | Change CPS format to RFC 3647, merge the CPS for Extended Validation (EV) Certificates into this CPS, and update to show Baseline Requirements and Mozilla Policy compliance; this CPS supersedes the CPS for Extended Validation (EV) Certificates Version 2.0 dated February 1, 2017. |
| 3.1   | August 1, 2018     | Update Roots, Subordinate and Cross Certified Cas, list of acronyms, domain validation, email address validation, CA termination, Certificate extensions, Certificate name forms, audit requirements and Certificate profiles |
| 3.2   | October 12, 2018   | Revocation update, Repository clarification and CPS alignment. |
| 3.3   | February 28, 2019  | Addition of Verified Mark Certificate (VMC) type TSA requirements and new Domain Name validation methods. Remove P-521 key size. |
| 3.4   | May 31, 2019       | Update to IP address validation methods and CPR procedure |
| 3.5   | July 25, 2019      | Update for Domain Name validation methods, VMC and Third Party RA restrictions. |
| 3.6   | September 30, 2019 | Update for Baseline Requirements for Code Signing and CAA |
| 3.7   | September 30, 2020 | Update Entrust brand, email address for CPR, implementation of CAB Forum ballots (SC23, SC24, SC25, SC28, SC30, SC31, SC33, and SC35), update for VMC Guidelines and remove from Appendix, and removal of non-inclusive language |
| 3.8   | December 31, 2020  | CAB Forum ballot CSC4 and Document Signing Certificate Subscriber key generation |
| 3.9   | July 19, 2021      | Update for CAB Forum ballots (CSC7, CSC8, SC42, SC44, SC45, SC46 and SC47), update for Mozilla policy 2.7.1, change Client Certificate to S/MIME Certificate, remove references to EV Code Signing Guidelines, update Technical Constraint requirements, update VMC requirements |
| 3.10  | February 18, 2022  | Update Entrust Ottawa address, CAB Forum ballots (CS12, SC48 and SC53), clarify application vetting methods, and define separation of duties |
| 3.11  | September 30, 2022 | Update for CAB Forum ballots (CSC13, CSC17, SC51), role of trademarks, remove CA Administrators, VMC updates for DBA, Postal Code and Government Mark, Mozilla policy 2.7.2, Time-stamp update, CSaaS update |
| 3.12  | January 31, 2023   | Update for CAB Forum ballots (SC56), add IDN practice, state Document Signing face-to-face reuse period, address illegal activities, update CA list |
| 3.13  | May 12, 2023       | Update for CAB Forum ballots (SC61), implement S/MIME BRs, CCADB self-assessment clarifications, Enterprise RA update, Policy Authority update. |
| 3.14  | June 20, 2023      | Update for CAB Forum ballots (CSC18), Signing Service, Enterprise RA and VMC face-to-face validation |
| 3.15  | October 16, 2023   | Subscriber certificate revocation, VMC 1.5 changes, posting to CCADB, Subscriber revocation actions, and certificate policy updates (ballot SC62) |
| 3.16  | February 20, 2024  | ACME update, CAB Forum ballots (CSC21, CSC22, SMC05), and certificate profile updates |
| 3.17  | March 21, 2024     | Certificate profile updates |
| 3.18  | March 22, 2024     | Certificate profile updates and Client Authentication certificates |
| 3.19  | March 25, 2024     | Update Client Authentication profile |
| 3.20  | March 26, 2024     | Certificate profile updates |
| 3.21  | May 14, 2024       | Subject/Subscriber changes, Certificate profile updates |
| 3.22  | July 31, 2024      | Change SSL Certificate to OV TLS Certificate and EV SSL Certificate to EV TLS Certificate |
| 3.23  | September 11, 2024 | Correct practices to support verification of Business Entities |

## 1.3 PKI Participants

### 1.3.1 Certification Authorities

In the Entrust public-key infrastructure, CAs may accept Certificate Signing Requests (CSRs) and Public Keys from Applicants whose identity has been verified as provided herein by an RA. If a Certificate Application is verified, the verifying RA will send a request to a CA for the issuance of a Certificate. The CA will create a Certificate containing the Public Key and identification information contained in the request sent by the RA to that CA. The Certificate created in response to the request will be digitally signed by the CA.

This CPS covers all Certificates issued and signed by the following CAs. The Root CA Certificates, Subordinate CA Certificates, and associated CRLs are disclosed through the CCADB.

**Root - Entrust.net 2048**

- CN: Entrust.net Certification Authority (2048)
  - Subject Key Identifier: 55E4 81D1 1180 BED8 89B9 08A3 31F9 A124 0916 B970
  - Thumbprint (SHA-1): 5030 0609 1D97 D4F5 AE39 F7CB E792 7D7D 652D 3431

**Subordinate CA(s)**

- CN: Entrust Class 2 Client CA
  - Subject Key Identifier: 09 91 a5 ba e9 f2 2e 2a 75 df cd 7e fe 77 ca f2 de 6b 9b 24
- CN: Entrust Class 2 Client CA - C2CA2
  - Subject Key Identifier: a2 71 4a d5 c2 64 65 2f 8d ce 2a e2 c1 b6 e7 0d d0 f9 32 e4
- CN: Entrust Class 3 Client CA - SHA256
  - Subject Key Identifier: 06 9f 6f 4e a2 29 4e 0f 0c ae 17 bf b6 98 46 ef ad b8 3b 72
- CN: Entrust Timestamping CA - TS1
  - Subject Key Identifier: c3 c2 71 d2 7b d7 68 05 ae 3b 39 9b 34 25 0c 62 03 c7 57 68
- CN: Entrust Enterprise Intermediate CA - ICA1
  - Subject Key Identifier: c8 38 d4 0a 70 dd a3 57 a8 e5 96 59 2d 13 13 c9 20 d5 dc b3

**Root - Entrust Root Certification Authority**

- CN: Entrust Root Certification Authority
  - Subject Key Identifier: 68 90 e4 67 a4 a6 53 80 c7 86 66 a4 f1 f7 4b 43 fb 84 bd 6d
  - Thumbprint (SHA-1): b3 1e b1 b7 40 e3 6c 84 02 da dc 37 d4 4d f5 d4 67 49 52 f9

**Subordinate CA(s)**

- CN: Entrust Certification Authority - L1E
  - Subject Key Identifier: 5b 41 8a b2 c4 43 c1 bd bf c8 54 41 55 9d e0 96 ad ff b9 a1

**Root G2**

- CN: Entrust Root Certification Authority - G2
  - Key Identifier: 6a 72 26 7a d0 1e ef 7d e7 3b 69 51 d4 6c 8d 9f 90 12 66 ab
  - Thumbprint (SHA-1): 8c f4 27 fd 79 0c 3a d1 66 06 8d e8 1e 57 ef bb 93 22 72 d4

**Subordinate CA(s)**

- CN: Entrust Class 1 Client CA - SHA256
  - Subject Key Identifier: e2 49 b9 ec 25 de b7 0c de e5 50 18 5b 48 cc 0c 8e 15 f2 a6
- CN: Entrust Certification Authority - L1K
  - Subject Key Identifier: 82 a2 70 74 dd bc 53 3f cf 7b d4 f7 cd 7f a7 60 c6 0a 4c bf
- CN: Entrust Certification Authority - L1M
  - Subject Key Identifier: c3 f7 d0 b5 2a 30 ad af 0d 91 21 70 39 54 dd bc 89 70 c7 3a
- CN: Entrust Extended Validation Code Signing CA - EVCS1
  - Subject Key Identifier: 2a 0a 6f 32 2c 29 20 21 76 6a b1 ac 8c 3c af 93 8e 0e 6b a2
- CN: Entrust Code Signing CA - OVCS1
  - Subject Key Identifier: 7e 1a 1f 1a 11 74 5c 64 c9 0c 1f 94 01 ab fd 81 64 2e a1 2c
- CN: CrowdStrike TLS CA 2022
  - Subject Key Identifier: 55 ea a7 45 b9 9a f7 b6 71 31 1a 31 df a1 76 fe 76 92 99 7a
- CN: Namirial EV SSL CA 2023
  - Subject Key Identifier: ea fe be 58 47 b8 33 d9 d2 36 7b c8 8c 67 7a b1 33 8b 8d 52
- CN: Namirial OV SSL CA 2023
  - Subject Key Identifier: 9a 9f 6f a5 f8 fe 34 fc 10 2d be 2f 89 c6 b9 d7 c6 92 d3 1e
- CN: Siemens Issuing CA Internet Server 2020
  - Subject Key Identifier: c9 a7 57 cb 86 c9 61 07 c6 c2 b4 86 65 a9 1e c1 ca e1 02 9b

**Root EC1**

- CN: Entrust Root Certification Authority - EC1
  - Subject Key Identifier: b7 63 e7 1a dd 8d e9 08 a6 55 83 a4 e0 6a 50 41 65 11 42 49
  - Thumbprint (SHA-1): 20 d8 06 40 df 9b 25 f5 12 25 3a 11 ea f7 59 8a eb 14 b5 47

**Subordinate CA(s)**

- CN: Entrust Certification Authority - L1F
  - Subject Key Identifier: 2e 62 f0 14 ee 87 cd b3 35 03 3d ef e4 b9 9e fd 3b b8 a3 c9
- CN: Entrust Certification Authority - L1J
  - Subject Key Identifier: c3 f9 45 03 be c8 f9 0b 3c 45 35 f3 eb 72 ec e7 e8 eb 94 9b

**Root G4**

- CN: Entrust Root Certification Authority - G4
  - Key Identifier: 9f 38 c4 56 23 c3 39 e8 a0 71 6c e8 54 4c e4 e8 3a b1 bf 67
  - SHA-1 Thumbprint: 14 88 4e 86 26 37 b0 26 af 59 62 5c 40 77 ec 35 29 ba 96 01

**Subordinate CA(s)**

- CN: Entrust Certification Authority - L1N
  - Subject Key Identifier: ee 47 d1 85 71 f1 fd 2d b7 3f bb 3e 63 58 77 17 49 40 0e 95

**Root 4K TLS 2022**

- CN: Entrust 4K TLS Root CA - 2022
  - Key Identifier: 9440ea5affef4963019e09dfe03b803373122056
  - Thumbprint (SHA-1): 193c2a76f8cadd84f35bf52ee7aa506657917a38

**Subordinate CA(s)**

- CN: Entrust 4K TLS Certification Authority - OVTLS1
  - Subject Key Identifier: a80003c10185b8c0272aa9bc08acfad44abe51a5

**Root 4K EV TLS 2022**

- CN: Entrust 4K EV TLS Root CA - 2022
  - Key Identifier: 0bdd90d58fbb3f5cbd60a0551a2482863c413041
  - Thumbprint (SHA-1): eadb0ab9dc7938021435fed13e488406a1aa292a

**Subordinate CA(s)**

- CN: Entrust 4K TLS Certification Authority - EVTLS1
  - Subject Key Identifier: 9930115c04d2448b259713c665d21616c9678792

**Root P384 TLS 2022**

- CN: Entrust P384 TLS Root CA - 2022
  - Key Identifier: c42e807c5f709204864c9e52cb2b67c5076a8293
  - Thumbprint (SHA-1): 424aae6d0c8c7624817cdb9ccb510ded6232191d

**Subordinate CA(s)**

- CN: Entrust P384 TLS Certification Authority - OVTLS2
  - Subject Key Identifier: c25b7126ed58efa51419aa2ef60456546f9a39c9

**Root P384 EV TLS 2022**

- CN: Entrust P384 EV TLS Root CA - 2022
  - Key Identifier: 137210ae82580fc1389bbcb6a64c05ca8e8468bf
  - Thumbprint (SHA-1): 1e6c44dc6473d4819be89fb237af4883fc376987

**Subordinate CA(s)**

- CN: Entrust P384 TLS Certification Authority - EVTLS2
  - Subject Key Identifier: 2cc1fad3279c77e73038c8c95ca43c02a36775c4

**Root**

- CN: Entrust SMIME Root CA - 2022
  - Key Identifier: 94c8e8468d7f53170305441810ac65e06ea2950d
  - Thumbprint (SHA-1): b8b1c5aac29bedf0ad71b2f14bfeaa38f817535e

**Subordinate CA(s)**

- CN: Entrust Personal Email Certification Authority - SMIME1
  - Subject Key Identifier: 03219b5f18632ec87ef9aedad9179fb6c91b8360

**Root CSBR1**

- CN: Entrust Root Certification Authority - CSBR1
  - Key Identifier: 82 ba d6 3d 97 ce 9f cf 71 e8 92 37 af fd b3 b5 69 35 57 cf
  - SHA-1 Thumbprint: 89 74 24 05 3a 4a 88 7a c0 98 38 02 91 03 4d 88 5c 87 14 b9

**Subordinate CA(s)**

- CN: Entrust Extended Validation Code Signing CA - EVCS2
  - Subject Key Identifier: ce 89 4f 82 51 aa 15 a2 84 62 ca 31 23 61 d2 61 fb f8 fe 78
- CN: Entrust Code Signing CA - OVCS2
  - Subject Key Identifier: ef 9f ba 79 b0 73 f2 25 1e 78 9c 03 52 9c 1b 53 84 de 8d ed
- CN: Entrust Timestamping CA - TS2
  - Subject Key Identifier: 26 0f f0 c4 48 08 1b cd dd 91 f5 54 54 b6 b3 b3 fc 99 f1 08

**Root DSR1**

- CN: Entrust Digital Signing Root Certification Authority - DSR1
  - Key Identifier: a6 65 41 81 f2 5b 87 05 6a dd fd 8a 54 4e 8f 98 7b dc 23 b8
  - Thumbprint (SHA-1): 10 4f e7 37 00 18 6e 69 2e 78 a0 15 6a 3f 9e d8 07 b0 60 8e

**Subordinate CA(s)**

- CN: Entrust Digital Signing Certification Authority - DS1
  - Subject Key Identifier: 80a1841c29b421823c0e5d17fbb21ed1a3e2d82d

**Root VMCR1**

- CN: Entrust Verified Mark Root Certification Authority - VMCR1
  - Key Identifier: 73 23 56 7b 2b 78 45 80 9a b8 c2 7c cc a5 86 39 8b 26 78 c5
  - SHA-1 Thumbprint: 4a 04 d5 a6 28 0e 98 e6 5c d4 7f 87 e8 ec a6 4c 8b 4a 9a 43

**Subordinate CA(s)**

- CN: Entrust Verified Mark CA - VMC2
  - Subject Key Identifier: ef bc 3c b4 af 3a d0 45 5e 76 54 df c7 64 78 e9 2d 1d 74 3f

**Externally Issued Cross Certificates**

- Microsoft Code Verification Root > Entrust G2
  - Issuer: CN = Microsoft Code Verification Root, O = Microsoft Corporation, L = Redmond, S = Washington, C = US
  - Subject: CN = Entrust Root Certification Authority - G2, OU = (c) 2009 Entrust, Inc. - for authorized use only, OU = See www.entrust.net/legal-terms, O = Entrust, Inc., C = US
  - Serial Number: 33 00 00 00 42 00 ba 5e 23 b0 a1 f3 99 00 00 00 00 00 42
  - Subject Key Identifier: 6a 72 26 7a d0 1e ef 7d e7 3b 69 51 d4 6c 8d 9f 90 12 66 ab
  - Valid until: July 7, 2025
  - SHA-1 Thumbprint: d8 fc 24 87 48 58 5e 17 3e fb fb 30 75 c4 b4 d6 0f 9d 8d 08

### 1.3.2 Registration Authorities

Entrust does not use Delegated Third Parties to perform RA functions.

RAs under the CA may accept Certificate Applications from Applicants and perform verification of the information contained in such Certificate Applications, according to the procedures established by the Policy Authority. A RA operating under a CA may send a request to such CA to issue a Certificate to the Applicant. Only RAs authorized by Entrust are permitted to submit requests to a CA for the issuance of Certificates.

Third Party RAs may not be delegated to validate FQDNs, IP Addresses or email addresses per §3.2.2.4, §3.2.2.5, or §3.2.2.9.

The CA may designate Enterprise RAs to verify Certificate requests from the Enterprise RA’s own organization or from an organization of which the Enterprise RA is an agent. The Enterprise RA may as stated in this CPS:

1. authorize issuance of OV TLS and EV TLS Certificates with FQDNs which must be within the Subscriber’s Domain Namespace and that the Subject organization name is either that of the Enterprise RA’s own enterprise, or an Affiliate of such enterprise, or that the Enterprise RA is an agent of the named Subject ;
2. authorize issuance of S/MIME Certificates with email domains which the enterprise owns or controls and that the Subject organization name is either that of the Enterprise RA’s own enterprise, or an Affiliate of such enterprise, or that the Enterprise RA is an agent of the named Subject;
3. authorize issuance of other Certificates;
4. verify a meaningful representation of personal name, given name, and/or surname of the Subject of an S/MIME Certificate;
5. verify email address of an S/MIME Certificate; and
6. authorize revocation of the enterprise’s Certificates.

### 1.3.3 Subscribers

Subscribers may use CA services to support transactions and communications. The Subject of a Certificate is the party named in the Certificate. A Subscriber, as used herein, may refer to both the Subject of the Certificate and the entity that contracted with the CA for the Certificate’s issuance. Prior to verification of identity and issuance of a Certificate, a Subscriber is an Applicant.

### 1.3.4 Relying Parties

A Relying Party is a person, entity, or organization that relies on or uses a Certificate and/or any other information provided in a Repository to verify the identity and Public Key of a Subscriber and/or use such Public Key to send or receive encrypted communications to or from a Subscriber.

### 1.3.5 Other Participants

Signing Services are provided by Entrust to generate the Subject Key Pair and protect the Subject Private Key on a managed and hosted cryptographic module. A Subscriber can use the Signing Services to cryptographically sign hashed data to support digital signatures.

Time-stamp Authorities are provided by Entrust which may be used by a Subscriber to provide time-stamp records to indicate data existed at a specific time. The TSA is managed in accordance with the Time-stamp Authority Practice Statement.

## 1.4 Certificate Usage

### 1.4.1 Appropriate Certificate Uses

This CPS is applicable to the following Certificate Types.

**OV and EV TLS Certificates**

OV and EV TLS Certificates are intended for use in establishing web-based data communication conduits via TLS/SSL protocols. OV and EV TLS Certificates conform to the requirements of the ITU-T X.509 v3 standard. The primary purpose of an OV or EV TLS Certificate is to facilitate the exchange of encryption keys in order to enable the encrypted communication of information over the Internet between the user of an Internet browser and a secure server.

**Client Authentication Certificates**

Client Authentication Certificates are intended for use in establishing client authentication via TLS/SSL protocols. Client Authentication Certificates conform to the requirements of the ITU-T X.509 v3 standard. The primary purpose of Client Authentication Certificates is to authenticate the identity of a client (such as a user or device) to a server.

**Code Signing and EV Code Signing Certificates**

Code Signing Certificates and EV Code Signing Certificates are used by content and software developers and publishers to digitally sign executables and other content. Code Signing and EV Code Signing Certificates conform to the requirements of the ITU-T X.509 v3 standard. The primary purpose of a Code Signing Certificate or EV Code Signing Certificate is to provide a method of ensuring that an executable object has come from an identifiable software publisher and has not been altered since signing.

**S/MIME Certificates**

S/MIME Certificates are used by individuals to digitally sign and encrypt electronic messages via an S/MIME compliant application. S/MIME Certificates conform to the requirements of the ITU-T X.509 v3 standard. The primary purpose of a S/MIME Certificate is to provide authentication, message integrity and non-repudiation of origin (using digital signatures) and privacy (using encryption).

**Document Signing Certificates**

Document Signing Certificates are used by individuals to digitally sign electronic documents. Document Signing Certificates conform to the requirements of the ITU-T X.509 v3 standard. Document Signing Certificates help to provide authentication and document integrity.

**Time-Stamp Certificates**

Time-Stamp Certificates are used by individuals to digitally sign Time-Stamp responses. Time-Stamp Certificates conform to the requirements of the ITU-T X.509 v3 standard. Time-Stamp Certificates help to provide authentication and Time-Stamp token integrity.

**Verified Mark Certificates**

Verified Mark Certificates are used to assert a brand identification for message identification. Verified Mark Certificates conform to the requirements of the ITU-T X.509 v3 standard. Verified Mark Certificates help to provide email messaging integrity.

### 1.4.2 Prohibited Certificate Uses

The use of all Certificates issued by the CA shall be for lawful purposes and consistent with applicable laws, including without limitation, applicable export or import laws.

Certificates and the services provided by Entrust in respect to Certificates are not designed, manufactured, or intended for use in or in conjunction with any application in which failure could lead to death, personal injury or severe physical or property damage, including the monitoring, operation or control of nuclear facilities, mass transit systems, aircraft navigation or communications systems, air traffic control, weapon systems, medical devices or direct life support machines, and all such uses are prohibited.

**OV and EV TLS Certificates**

Certificate issuance is prohibited unless the Domain Name Registrant has been approved or authorized a Certificate request. Certificates issued under this CPS may not be used to conduct surreptitious interception by third parties, such as "traffic management" or "man-in-the-middle".

## 1.5 Policy administration

### 1.5.1 Organization Administering the Document

The CPS is administered by the Policy Authority; it is based on the policies established by Entrust Limited.

### 1.5.2 Contact Person

The contact information for questions about Certificates is:

> Entrust Limited  
> 2500 Solandt Road, Suite 100  
> Ottawa, Ontario  
> Canada K2K 3G5  
> Attn: Entrust Certificate Services  
>   
> Tel: [1-866-267-9297](tel:+18662679297) or [1-613-270-2680](tel:+16132702680)  
> Email: [ecs.support@entrust.com](mailto:ecs.support@entrust.com)  

Certificate Problem Reports, such as Certificate misuse, vulnerability reports or external reports of key compromise, must be emailed to [ecs.support@entrust.com](mailto:ecs.support@entrust.com).

Contact details are also provided and maintained in the CCADB.

### 1.5.3 Person Determining CPS suitability for the policy

The Policy Authority determines the suitability and applicability of this CPS.

The Policy Authority:

1. Monitors and implements the approved ballots from the CA/Browser Forum;
2. Monitors and implements policy changes from applicable ASVs; and
3. Monitors discussions from the Mozilla security policy forum and the CCADB public list.

### 1.5.4 CPS approval procedures

This CPS and any subsequent changes shall be approved by the Policy Authority.

## 1.6 Definitions and Acronyms

### 1.6.1 Definitions

**Affiliate**: means with respect to Entrust, a person or entity that directly, or indirectly through one or more intermediaries, controls, is controlled by or is under common control with Entrust, and, with respect to any other party, any corporation or other entity that is directly or indirectly controlled by that party. In this context, a party "controls" a corporation or another entity if it directly or indirectly owns or controls fifty percent (50%) or more of the voting rights for the board of directors or other mechanism of control or, in the case of a non-corporate entity, an equivalent interest.

**Applicant**: means a person, entity, or organization applying for a Certificate, but which has not yet been issued a Certificate, or a person, entity, or organization that currently has a Certificate or Certificates and that is applying for renewal of such Certificate or Certificates or for an additional Certificate or Certificates.

**Applicant Representative**: as defined in the Baseline Requirements.

**Application Software Vendor**: means a developer of Internet browser software or other software that displays or uses Certificates.

**Attestation Letter:** as defined in the Baseline Requirements.

**Author Domain:** means the Domain Name of the apparent author of an email, as extracted from the RFC5322 "From field". The RFC5322 "From field" is also known by the names "Visible From field", "Message From field", and "From: field". It is the header field shown to the recipient of the message to represent the sender of the message, and is typically displayed as follows: From: "Friendly Name" &lt;<address@domain.com>&gt; The Author Domain in this field is the part of the email address between the "@" sign and the right-most angle bracket (i.e., "domain.com" in the example shown).

**Authorization Domain Name**: as defined in the Baseline Requirements.

**Authorized Port**: as defined in the Baseline Requirements.

**Base Domain Name**: as defined in the Baseline Requirements.

**Baseline Requirements**: means the CA/Browser Forum Baseline Requirements for the Issuance and Management of Publicly-Trusted Certificates published at <https://www.cabforum.org>.

**Business Day:** means any day, other than a Saturday, Sunday, statutory or civic holiday in the City of Ottawa, Ontario, Canada.

**CA Key Pair**: as defined in the Baseline Requirements.

**Certificate:** means a digital document issued by the CA that, at a minimum: (a) identifies the CA issuing it, (b) names or otherwise identifies a Subject, (c) contains a Public Key of a Key Pair, (d) identifies its operational period, and (e) contains a serial number and is digitally signed by a CA. Certificate includes the following Certificate types issued by the CA; S/MIME Certificate, Client Authentication Certificate, Code Signing Certificate, Document Signing Certificate, EV Code Signing Certificate, EV TLS Certificate, OV TLS Certificate, Subordinate CA Certificate, Time-Stamp Certificate and Verified Mark Certificate.

**Certificate Application:** means the form and application information requested by an RA operating under a CA and submitted by an Applicant when applying for the issuance of a Certificate.

**Certificate Approver:** means an employee or agent authorized to approve a request for a Certificate for an organization.

**Certificate Beneficiaries**: means, collectively, all Application Software Vendors with whom Entrust has entered into a contract to include its Root CA Certificate(s) in software distributed by such Application Software Vendors, and all Relying Parties that actually rely on such Certificate during the Operational Period of such Certificate.

**Certificate Problem Report**: as defined in the Baseline Requirements.

**Certificate Profile**: as defined in the Baseline Requirements.

**Certificate Requester**: means an employee or agent authorized to request a Certificate for an organization.

**Certificate Revocation List:** means a time-stamped list of the serial numbers of revoked Certificates that has been digitally signed by a CA.

**Certificate Systems**: as defined in the Network and Certificate System Security Requirements.

**Certificate Transparency:** a method for publicly logging Certificates in accordance with IETF RFC 6962.

**Certification Authority:** means a certification authority operated by or on behalf of Entrust for the purpose of issuing, managing, revoking, renewing, and providing access to Certificates. The CA (i) creates and digitally signs Certificates that contain among other things a Subject’s Public Key and other information that is intended to identify the Subject, (ii) makes Certificates available to facilitate communication with the Subject identified in the Certificate, and (iii) creates and digitally signs Certificate Revocation Lists containing information about Certificates that have been revoked and which should no longer be used or relied upon.

**Certification Authority Authorization**: as defined in the Baseline Requirements.

**Certification Practice Statement:** means this document, which is a statement of the practices that the CA uses in issuing, managing, revoking, renewing, and providing access to Certificates, and the terms and conditions under which the CA makes such services available.

**Client Authentication Certificate:** means a Certificate issued to authenticate clients to servers, does not include the serverAuth extended key usage, and is not asserted to meet the Baseline Requirements.

**Co-marketers:** means any person, entity, or organization that has been granted by Entrust or an RA operating under a CA the right to promote Certificates.

**Code Signing Baseline Requirements:** means the CA/Browser Forum Baseline Requirements for the Issuance and Management of Publicly-Trusted Code Signing Certificates published at <https://www.cabforum.org>.

**Code Signing Certificate:** means a Certificate issued by a CA for use by content and software developers and publishers to digitally sign executables and other content.

**Common CA Database**: a data repository of Certificate and CA information.

**Compromise:** means a suspected or actual loss, disclosure, or loss of control over sensitive information or data.

**Contract Signer:** means an employee or agent authorized to sign the Subscriber Agreement on behalf of the organization.

**Cross Certificate(s)**: as defined in the Baseline Requirements.

**Design Mark:** as defined in the VMC Requirements.

**Document Signing Certificate**: means a Certificate issued by a CA for use by individuals or systems to digitally sign documents.

**Domain Contact**: as defined in the Baseline Requirements.

**Domain Label**: as defined in the Baseline Requirements.

**Domain Name**: as defined in the Baseline Requirements.

**Domain Namespace**: as defined in the Baseline Requirements.

**Domain Name Registrant**: as defined in the Baseline Requirements.

**Domain Name Registrar**: as defined in the Baseline Requirements.

**DNS CAA Email Contact:** as defined in the Baseline Requirements.

**DNS CAA Phone Contact:** as defined in the Baseline Requirements.

**DNS TXT Record Email Contact:** as defined in the Baseline Requirements.

**DNS TXT Record Phone Contact:** as defined in the Baseline Requirements.

**Enterprise RA:** as defined in the Baseline Requirements.

**Entrust:** means Entrust Limited.

**Entrust Group:** means, collectively, Entrust, its Affiliates, its licensors (including for the avoidance of any doubt Microsoft), its resellers, its suppliers, its co-marketers, its subcontractors, its distributors and the directors, officers, employees, agents and independent contractors of any of them.

**Entrust Group Affiliates**: Collectively, Entrust Limited and its Affiliates.

**EV Code Signing Certificate:** means a Code Signing Certificate issued by a CA meeting the requirements of the EV Code Signing Certificate requirements of the Code Signing Baseline Requirements.

**EV TLS Certificate:** means a Certificate issued by a CA meeting the requirements of the EV SSL Guidelines.

**EV SSL Guidelines:** means the CA/Browser Forum Guidelines For The Issuance and Management of Extended Validation Certificates published at <https://www.cabforum.org>. The EV SSL Guidelines describe the requirements that a CA must meet in order to issue EV TLS Certificates. In the event of any inconsistency between this CPS and the EV SSL Guidelines, the EV SSL Guidelines take precedence over this CPS.

**FIPS:** means the Federal Information Processing Standards. These are U.S. Federal standards that prescribe specific performance requirements, practices, formats, communication protocols, and other requirements for hardware, software, data, and telecommunications operation.

**Fully-Qualified Domain Name**: as defined in the Baseline Requirements.

**IETF:** means the Internet Engineering Task Force. The Internet Engineering Task Force is an international community of network designers, operators, vendors, and researchers concerned with the evolution of the Internet architecture and the efficient operation of the Internet.

**Incorporating Agency:** as defined in the EV SSL Guidelines.

**Internal Name:** as defined in the Baseline Requirements.

**IP Address:** as defined in the Baseline Requirements.

**IP Address Contact:** as defined in the Baseline Requirements.

**IP Address Registration Authority:** as defined in the Baseline Requirements.

**Issuing CA:** In relation to a particular Certificate, the CA that issued the Certificate. This could be either a Root CA or a Subordinate CA.

**Key Compromise:** as defined in the Baseline Requirements.

**Key Pair:** means two mathematically related cryptographic keys, having the properties that (i) one key can be used to encrypt a message that can only be decrypted using the other key, and (ii) even knowing one key, it is believed to be computationally infeasible to discover the other key.

**Mailbox Address:** as defined in the S/MIME Baseline Requirements.

**Mailbox Field:** as defined in the S/MIME Baseline Requirements.

**Mark Representation:** as defined in the VMC Requirements.

**Object Identifier:** means a specially-formatted sequence of numbers that is registered in accordance with internationally-recognized procedures for object identifier registration.

**Operational Period:** means, with respect to a Certificate, the period of its validity. The Operational Period would typically begin on the date the Certificate is issued (or such later date as specified in the Certificate), and ends on the date and time it expires as noted in the Certificate or earlier if the Certificate is Revoked.

**OV TLS Certificate:** means a Certificate issued by a CA meeting the organization-validated requirements of the Baseline Requirements.

**Parent Company:** as defined in the Baseline Requirements.

**PKIX:** means an IETF Working Group developing technical specifications for PKI components based on X.509 Version 3 Certificates.

**Place of Business:** as defined in the EV SSL Guidelines.

**Policy Authority:** means those personnel who work for or on behalf of Entrust and who are responsible for determining the policies and procedures that govern the operation of the CAs.

**Private Key:** means the key of a Key Pair used to decrypt an encrypted message. This key must be kept secret.

**Public Key:** means the key of a Key Pair used to encrypt a message. The Public Key can be made freely available to anyone who may want to send encrypted messages to the holder of the Private Key of the Key Pair. The Public Key is usually made publicly available in a Certificate issued by a CA and is often obtained by accessing a repository or database. A Public Key is used to encrypt a message that can only be decrypted by the holder of the corresponding Private Key.

**Qualified Government Information Source:** as defined in the EV SSL Guidelines.

**Qualified Government Tax Information Source:** as defined in the EV SSL Guidelines.

**Qualified Independent Information Source:** as defined in the EV SSL Guidelines.

**Random Value**: a value that exhibits at least 112 bits of entropy.

**Registered Mark:** as defined in the VMC Requirements.

**Registration Agency:** as defined in the EV SSL Guidelines.

**Registration Authority:** means an entity that performs two functions: (1) the receipt of information from a Subject to be named in a Certificate, and (2) the performance of verification of information provided by the Subject following the procedures prescribed by the CAs. In the event that the information provided by a Subject satisfies the criteria defined by the CAs, an RA may send a request to a CA requesting that the CA generate, digitally sign, and issue a Certificate containing the information verified by the RA. An RA may be operated by Entrust or by an independent third-party.

**Registration Number:** as defined in the EV SSL Guidelines.

**Reliable Data Source:** as defined in the Baseline Requirements.

**Reliable Method of Communication:** as defined in the Baseline Requirements.

**Relying Party:** means a person, entity, or organization that relies on or uses a Certificate and/or any other information provided in a Repository under a CA to obtain and confirm the Public Key and identity of a Subscriber. For avoidance of doubt, an ASV is not a "Relying Party" when software distributed by such ASV merely displays information regarding a Certificate.

**Relying Party Agreement:** means the agreement between a Relying Party and Entrust or between a Relying Party and an independent third-party RA or Reseller under a CA in respect to the provision and use of certain information and services in respect to Certificates.

**Repository:** means a collection of databases and web sites that contain information about Certificates issued by a CA including among other things, the types of Certificates and services provided by the CA, fees for the Certificates and services provided by the CA, Certificate Revocation Lists, OCSP responses, descriptions of the practices and procedures of the CA, and other information and agreements that are intended to govern the use of Certificates issued by the CA.

**Request Token:** as defined in the Baseline Requirements.

**Request Value:** as defined in the Baseline Requirements.

**Required Website Content:** as defined in the Baseline Requirements.

**Resellers:** means any person, entity, or organization that has been granted by Entrust or an RA operating under a CA the right to license the right to use Certificates.

**Reserved IP Address:** as defined in the Baseline Requirements.

**Revoke or Revocation:** means, with respect to a Certificate, to prematurely end the Operational Period of that Certificate from a specified time forward.

**Root CA:** mean the top level CAs listed in §1.3.1.

**Signing Service:** means the services offered by Entrust relating to the generation, management and hosting of Subscriber Key Pairs to sign hashed data.

**Subordinate CA:** means collectively, the subordinate CAs listed in §1.3.1. and/or Third Party Subordinate CAs.

**Subordinate CA Certificate**: shall mean a Certificate that (i) includes the Public Key of a Public-Private Key Pair generated by a certification authority; and (ii) includes the digital signature of a Root or Subordinate CA.

**Subject:** means the person, entity, or organization identified in the "Subject" field in a Certificate.

**Subscriber:** means a person, entity, or organization that has applied for and has been issued a Certificate.

**Subscriber Agreement:** means the agreement between a Subscriber and Entrust (or an Affiliate of Entrust) or between a Subscriber and an independent third-party RA or Reseller under a CA in respect to the issuance, management, and provision of access to a Certificate and the provision of other services in respect to such Certificate. The Subscriber Agreement may consist of one or more parts.

**Subsidiary Company:** as defined in the Baseline Requirements.

**Suspect Code**: means any code or set of instructions that contains malicious functionality or serious vulnerabilities, including spyware, malware and other code that installs without the user's consent and/or resists its own removal, and code that can be exploited in ways not intended by its designers to compromise the trustworthiness of the computing environment on which it executes.

**S/MIME Baseline Requirements:** means the CA/Browser Forum Baseline Requirements for the Issuance and Management of Publicly-Trusted S/MIME Certificates published at <https://www.cabforum.org>.

**S/MIME Certificate:** means a Certificate issued by a CA for use by individuals to digitally sign and encrypt electronic messages via an S/MIME compliant application.

**Takeover Attack:** as defined in the Code Signing Baseline Requirements.

**Technically Constrained Subordinate CA Certificate:** as defined in the Baseline Requirements.

**Third Party Subordinate CA:** means a certification authority owned by a third party which has been issued a Subordinate CA Certificate.

**Time-Stamp Authority**: as defined in the Code Signing Baseline Requirements.

**Time-Stamp Certificate**: means a Certificate issued by a CA for use by a Time-Stamp Authority to digitally sign time-stamp tokens.

**TLS Certificate:** means a Certificate issued by a CA primarily to authenticate servers to clients as part of an SSL/TLS connection and to meet the Baseline Requirements. 

**Trusted Role:** as defined in the CA/Browser Forum’s Network and Certificate System Security Requirements.

**Validation Specialist:** as defined in the Baseline Requirements.

**Verified Mark Certificate (or VMC):** means a certificate that contains subject information and extensions specified in the VMC Requirements and that has been verified and issued by a CA in accordance with the VMC Requirements.

**Verified Method of Communication:** as defined in the EV SSL Guidelines.

**Verified Professional Letter:** as defined in the EV SSL Guidelines.

**VMC Requirements:** means the Minimum Security Requirements for Issuance of Verified Mark Certificates, published at <https://bimigroup.org/supporting-documents/> (as such VMC Requirements may be amended from time to time). All Subscribers/Mark Asserting Entities and Consuming Entities (as such terms are defined in the VMC Requirements) are bound by the VMC Terms according to their terms.

**VMC Terms:** The Terms of Use that apply to a Verified Mark Certificate and to the Mark Representation (as such terms are defined in the VMC Requirements) and related data contained in a Verified Mark Certificate, as set out in Appendix B to the VMC Requirements. The current version of the VMC Terms are presented in this CPS at Appendix C.

**Wildcard Domain Name:** as defined in the Baseline Requirements.

**Word Mark:** as defined in the VMC Requirements.

### 1.6.2 Acronyms

| **Acronym** | **Meaning** |
| ----------- | ----------------------------------------------------------------------------------- |
| ADN         | Authorization Domain Name |
| ASV         | Application Software Vendor |
| CA          | Certification Authority |
| CAA         | Certification Authority Authorization |
| CCADB       | Common CA Database |
| CPR         | Certificate Problem Report |
| CPS         | Certification Practice Statement |
| CRL         | Certificate Revocation List |
| CSR         | Certificate Signing Request |
| CT          | Certificate Transparency |
| DBA         | Doing Business As |
| DN          | Distinguished Name |
| DNS         | Domain Name System |
| DNSSEC      | Domain Name System Security Extensions |
| ECC         | Elliptic Curve Cryptography |
| EKU         | Extended Key Usage |
| EV          | Extended Validation |
| FIPS        | (US Government) Federal Information Processing Standard |
| FQDN        | Fully Qualified Domain Name |
| HTTP        | Hyper Text Transfer Protocol |
| HTTPS       | Hyper Text Transfer Protocol Secure |
| IANA        | Internet Assigned Numbers Authority |
| ICANN       | Internet Corporation for Assigned Names and Numbers |
| IETF        | Internet Engineering Task Force |
| ISO         | International Organization for Standardization |
| ITU         | -T International Telecommunication Union - Telecommunication Standardization Sector |
| NIST        | (US Government) National Institute of Standards and Technology |
| OCSP        | Online Certificate Status Protocol |
| OID         | Object Identifier |
| OV          | Organization Validated |
| PA          | Policy Authority |
| PIN         | Personal Identification Number |
| PKI         | Public-Key Infrastructure |
| QGIS        | Qualified Government Information Source |
| QTIS        | Qualified Government Tax Information Source |
| QIIS        | Qualified Independent Information Source |
| RA          | Registration Authority |
| RFC         | Request for Comment |
| RSA         | Rivest-Shamir-Adleman cryptosystem |
| SAN         | Subject Alternative Name |
| SSL         | Secure Sockets Layer |
| S/MIME      | Secure MIME (Multipurpose Internet Mail Extensions) |
| TLS         | Transport Layer Security |
| TSA         | Time-Stamp Authority |
| URL         | Universal Resource Locator |
| VMC         | Verified Mark Certificate |

# 2. PUBLICATION AND REPOSITORY RESPONSIBILITIES

Entrust maintains the Repository to store various information related to Certificates and the operation of the CAs and RAs. The CPS and various other related information is published in the Repository.

## 2.1 Repositories

The CAs maintain the Repositories to allow access to Certificate-related and Certificate revocation information. The information in the Repositories is accessible through a web interface, publicly available on a 24x7 basis and is periodically updated as set forth in this CPS. The Repositories are the only approved source for CRL and other information about Certificates.

The CA will adhere to the latest version of the CPS published in the Repository.

The Repository can be accessed at <https://www.entrust.net/CPS>.

## 2.2 Publication of information

The CA publishes its CPS, CA Certificates, Subscriber Agreements, Relying Party Agreements, Audit Reports, and CRLs in the Repositories. The CPS and applicable Audit Reports are provided to the CCADB.

This CPS is structured in the RFC3647 format.

**OV and EV TLS Certificates**

The CA will host test Web pages that allow ASVs to test their software with Subscriber Certificates that chain up to each publicly trusted Root CA Certificate. The CA will host separate Web pages using Subscriber Certificates that are i. valid, ii. revoked, and iii. expired.

**Code Signing, EV Code Signing and Times-stamp Certificates**

Upon request, the CA will issue and make available to ASVs valid Code Signing, EV Code Signing and Time-stamp Certificates that chain up to Root CA Certificates that support these Certificate types.

**S/MIME Certificates**

Upon request, the CA will issue and make available to ASVs valid S/MIME Certificates or signed email that chain up to Root CA Certificates that support S/MIME Certificates.

**Document Signing Certificates**

Upon request, the CA will issue and make available to ASVs valid Document Signing Certificates or signed document that chain up to Root CA Certificates that support Document Signing Certificates.

## 2.3 Time or frequency of publication

The CPS will be re-issued and published at least once per year. The CPS will be updated with an incremented version number and a new date on an annual basis even if no other changes have been made to this document.

CRLs will be updated as per §4.9.7. OCSP responses will be updated as per §4.9.10.

## 2.4 Access controls on repositories

Information published in the Repository is public information. Read only access is unrestricted. The CAs have implemented logical and physical controls to prevent unauthorized write access to its Repositories.

Historic versions of the CPS are maintained in the Repository in the archive folder.

# 3. IDENTIFICATION AND AUTHENTICATION

The Policy Authority mandates the verification practices for verifying identification and authentication, and may, in its discretion, update such practices.

## 3.1 Naming

Before issuing a Certificate, the CAs ensure that all Subject organization information in the Certificate conforms to the requirements of, and has been verified in accordance with the procedures prescribed in this CPS and matches the information confirmed and documented by the RA pursuant to its verification processes.

**EV TLS and EV Code Signing Certificates**

The CA and RA must follow the verification procedures in this CPS, the EV SSL Guidelines and/or the Code Signing Baseline Requirements and match the information confirmed and documented by the RA pursuant to its verification processes. Such verification procedures are intended to accomplish the following:

1. Verify the Applicant’s existence and identity, including;
    1. Verify the Applicant’s legal existence and identity (as stipulated in the EV SSL Guidelines),
    2. Verify the Applicant’s physical existence (business presence at a physical address) , and
    3. Verify the Applicant’s operational existence (business activity).
2. Verify the Applicant’s authorization for the Certificate, including;
    1. Verify the name, title, and authority of the Contract Signer, Certificate Approver, and Certificate Requester;
    2. Verify that Contract Signer signed the Subscriber Agreement; and
    3. Verify that a Certificate Approver has signed or otherwise approved the Certificate request.

### 3.1.1 Types of names

The Subject names in a Certificate comply with the X.501 Distinguished Name (DN) form. The CAs shall use a single naming convention as set forth below.

**OV TLS Certificates**

1. "Country Name" (C) which is the two-letter ISO 3166 code for the country of the Subscriber;
2. "Organization Name" (O) which is the name of the organization in the case of a corporation, partnership, or other entity;
3. "Common Name" (CN) which is the hostname, the fully qualified hostname or path used in the DNS of the secure server;
4. "Locality" (L), which is the city or locality of the organization’s place of business; and
5. "State" (ST) (if applicable), which is the state or province of the organization’s place of business.

**EV TLS Certificates**

1. Same as OV TLS Certificates, plus
2. `serialNumber` which is the registration number of Subscriber,
3. `businessCategory` which is the applicable business category clause per the EV SSL Guidelines,
4. `jurisdictionOfIncorporationLocalityName` (if applicable) which is the jurisdiction of registration or incorporation locality of Subscriber,
5. `jurisdictionOfIncorporationStateOrProvinceName` (if applicable) which is the jurisdiction of registration or incorporation state or province of Subscriber, and
6. `jurisdictionOfIncorporationCountry` which is the jurisdiction of registration or incorporation country of Subscriber.

The CA does not include any Subject name attributes which are not defined in EV SSL Guidelines section 9.2.

**Client Authentication Certificates**

1. "Country Name" (C) which is the two-letter ISO 3166 code for the of the Subscriber;
2. "Organization Name" (O) which is the name of the organization in the case of a corporation, partnership, or other entity;
3. "Common Name" (CN) which is the hostname, the fully qualified hostname or path used in the DNS of the secure server;
4. "Locality" (L), which is the city or locality of the organization’s place of business; and
5. "State" (ST) (if applicable), which is the state or province of the organization’s place of business.

**Code Signing Certificates**

1. "Country Name" (C) which is the two-letter ISO 3166 code for the country of the Subscriber;
2. "Organization Name" (O) which is the full legal name of the organization;
3. "Organizational Unit Name" (OU) which is an optional field;
4. "Common Name" (CN) which is the same value as the "Organization Name";
5. "Locality" (L), which is the city or locality of the organization’s place of business; and
6. "State" (ST), which is the state or province of the organization’s place of business, if applicable

**EV Code Signing Certificates**

1. Same as Code Signing Certificates, plus
2. `serialNumber` which is the registration number of Subscriber,
3. `businessCategory` which is the applicable business category clause per the Code Signing Baseline Requirements,
4. `jurisdictionOfIncorporationLocalityName` (if applicable) which is the jurisdiction of registration or incorporation locality of Subscriber,
5. `jurisdictionOfIncorporationStateOrProvinceName` (if applicable) which is the jurisdiction of registration or incorporation state or province of Subscriber, and
6. `jurisdictionOfIncorporationCountry` which is the jurisdiction of registration or incorporation country of Subscriber.

**Class 1 S/MIME Certificates**

1. "Common Name" (CN) which is the e-mail address of the Subject; and
2. "Email" (E), which is the e-mail address of the Subject.

**Class 2 S/MIME Certificates (Organization-validated)**

1. "Country Name" (C) which is the two-letter ISO 3166 code for the country of the Subscriber;
2. "Organization Name" (O) which is the organization name of the Subscriber;
3. "Organizational Unit Name" (OU) which is an optional field;
4. Effective no later than 1 September 2023, "Organization Identifier" which is the unique organization identifier of the organization
5. "Common Name" (CN) which is the organization name of the Subscriber; and
6. "Email" (E), which is the e-mail address of the Subscriber.

**Class 2 S/MIME Certificates (Sponsor-validated)**

1. "Country Name" (C) which is the two-letter ISO 3166 code for the country of the Subscriber;
2. "Organization Name" (O) which is the organization name of the Subscriber;
3. "Organizational Unit Name" (OU) which is an optional field;
4. Effective no later than 1 September 2023, "Organization Identifier" which is the unique organization identifier of the organization
5. Effective no later than 1 September 2023 for strict policy, "Surname" which is the last name of the Subject
6. Effective no later than 1 September 2023 for strict policy, "First name" which is the first name of the Subject
7. "Common Name" (CN) which is the personal name of the Subject; and
8. "Email" (E), which is the e-mail address of the Subject.

**Document Signing Certificates**

1. "Country Name" (C) which is the two-letter ISO 3166 code for the country of the Subscriber;
2. "Organization Name" (O) which is the name of the organization in the case of a corporation, partnership, or other entity.;
3. "Organizational Unit Name" (OU) which is an optional field;
4. "Email" (E) is an optional field, which is the e-mail address of the Subject;
5. `serialNumber` is an optional field, which is randomly generated and assigned to the Subject, if the Subject is an individual; and
6. "Common Name" (CN) which may be an individual’s name, an organization’s name or the name of a specific role within an organization.

**Time-Stamp Certificates**

1. "Country Name" (C) which is the two-letter ISO 3166 code for the country of the Subscriber;
2. "Organization Name" (O) which is the full legal name of the organization;
3. "Organizational Unit Name" (OU) which is an optional field;
4. "Common Name" (CN) which is an optional field;
5. "Locality" (L), which is the city or locality of the organization’s place of business; and
6. "State" (ST), which is the state or province of the organization’s place of business, if applicable

**Verified Mark Certificates**

1. "Country Name" (C) which is the two-letter ISO 3166 code for the country of the Subscriber;
2. "Organization Name" (O) which is the full legal name of the organization;
3. "Organizational Unit Name" (OU), (optional);
4. "Common Name" (CN) (optional) which is either the full legal name of the organization;
5. "Street Address", which is the number and street address of the organization’s place of business;
6. "Locality" (L), which is the city or locality of the organization’s place of business;
7. "State" (ST), (if applicable) which is the state or province of the organization’s place of business;
8. "Postal Code" which is the postal code of the organization’s place of business (optional);
9. `serialNumber` which is the registration number of Subscriber;
10. `businessCategory` which is the applicable business category clause per the VMC Requirements;
11. `jurisdictionOfIncorporationLocalityName` (if applicable) which is the jurisdiction of registration or incorporation locality of Subscriber;
12. `jurisdictionOfIncorporationStateOrProvinceName` (if applicable) which is the jurisdiction of registration or incorporation state or province of Subscriber;
13. `jurisdictionOfIncorporationCountry` which is the jurisdiction of registration or incorporation country of Subscriber;
14. markType which is Registered Mark or Government Mark

**Registered Mark Certificates**

1. `trademarkCountryOrRegionName` which is trademark country;
2. `trademarkOfficeName` (optional) which is trademark agency office name; and
3. `trademarkRegistration` which is trademark registration number.

**Government Mark Certificates**

1. `subject:statuteLocalityName`, which is required if registered at the locality level;
2. `subject:statuteStateOrProvinceName`, which is required if statute locality is in a state/province OR registered as the state/province level;
3. `subject:statuteCountryName`;
4. statuteCitation, which is official statute, regulation, treaty, or government action by which the Government Mark was granted;
5. statuteURL, which is URL where the official statute, regulation, treaty, or government action by which the Government Mark was granted or claimed can be found (optional).

### 3.1.2 Need for names to be meaningful

The Certificates issued pursuant to this CPS are meaningful only if the names that appear in the Certificates can be understood and used by Relying Parties. Names used in the Certificates must identify the person or object to which they are assigned in a meaningful way. CAs shall not issue Certificates to the Subscribers that contain Domain Names, IP Addresses, DN, URL, and/or e-mail addresses that the Subscribers do not legitimately own or control. Examples of fields and extensions where these names appear include subject DN and subject alternative names.

**TLS and Client Authentication Certificates**

The value of the Common Name to be used in the Certificate is the Subscriber’s fully qualified hostname or path that is used in the DNS of the secure server on which the Subscriber is intending to install the OV TLS Certificate. Notwithstanding the preceding sentence, the Common Name may include wildcard characters (i.e., an asterisk character).

**EV TLS Certificates**

The value of the Common Name to be used in an EV TLS Certificate is the Subscriber’s FQDN that is used in the DNS of the secure server on which the Subscriber is intending to install the EV TLS Certificate. The FQDN for an EV TLS Certificate cannot be an IP Address or a Wildcard Domain Name.

**Code Signing Certificates**

The value of the Common Name to be used in a Code Signing Certificate is the Subscriber’s organization name.

**EV Code Signing Certificates**

The value of the Common Name to be used in an EV Code Signing Certificate is the Subscriber’s organization name.

**S/MIME Certificates**

The value of the Common Name to be used in a S/MIME Certificate is the name or the email address of the Subject. Subject’s personal names will be a meaningful representation of the Subject’s name as verified in the identifying documentation or Enterprise RA records.

**Document Signing Certificates**

The value of the Common Name to be used in a Document Signing Certificate is the name of the Subject, the role of the Subject, or the group or organization that the Subject represents.

**Time-Stamp Certificates**

The value of the Common Name to be used in a Time-Stamp Certificate, if present is a name of the time-stamp service associated with the Subscriber.

**Verified Mark Certificates**

The value of the Common Name to be used in a Verified Mark Certificate, if present is the Subsciber’s organization name or Word Mark.

### 3.1.3 Anonymity or pseudonymity of subscribers

International Domain Names (IDNs) will be verified and represented in the commonName and subjectAltName using Punycode.

### 3.1.4 Rules for interpreting various name forms

**S/MIME Certificates**

In accordance with section 3.1.4 of the S/MIME Baseline Requirements.

### 3.1.5 Uniqueness of names

Names shall be defined unambiguously for each Subject in a Repository. The Distinguished Name attribute is to be unique to the Subject to which it is issued.

**EV TLS, EV Code Signing, and Verified Mark Certificates**

A unique number is included in the serial number attribute of the Subject name per the EV SSL Guidelines.

**S/MIME Certificates**

An email address for the Subject is included in the Subject name.

**Document Signing Certificates**

A unique number and/or email address for the Subject is included in the Subject name.

### 3.1.6 Recognition, authentication, and role of trademarks

Subscribers should not request Certificates with any content that infringes on the intellectual property rights of another entity. Unless otherwise specifically stated in this CPS, Entrust does not verify an Applicant’s right to use a trademark and does not resolve trademark disputes. Entrust may reject any application or require revocation of any Certificate that is part of a trademark dispute.

**Verified Mark Certificates**

The CA verifies the Applicant’s Registered Mark in accordance with §3.2.2.10.

## 3.2 Initial identity validation

### 3.2.1 Method to prove possession of private key

For Key Pairs generated by the Applicant, the CAs perform proof of possession tests for CSRs created using reversible asymmetric algorithms (such as RSA) by validating the signature on the CSR submitted by the Applicant with the Certificate Application.

### 3.2.2 Authentication of Organization and Domain Identity

Entrust uses an internal process to check the accuracy of information sources and databases to ensure the data is acceptable, including reviewing the database provider’s terms of use. Prior to using any data source as a Reliable Data Source or QIIS, the source is evaluated for its reliability, accuracy, and resistance to alteration or falsification. The accuracy process addresses the requirements of Baseline Requirements section 3.2.2.7, EV SSL Guidelines section 11.11.5, and VMC Requirements section 3.2.13.5.

#### 3.2.2.1 Identity

Unless otherwise stated below, the CA will verify the identity and/or address of the Applicant using documentation provided by, or through communication with, at least one of the following:

1. A government agency in the jurisdiction of the Applicant’s legal creation, existence, or recognition;
2. A third party database that is periodically updated and considered a Reliable Data Source;
3. A site visit by the CA or a third party who is acting as an agent for the CA; or
4. An Attestation Letter.

**EV TLS, EV Code Signing and Verified Mark Certificates**

In accordance with the EV SSL Guidelines or the VMC Requirements, the CA or the RA will determine:

5. Full legal name;
6. Business Category;
7. Jurisdiction of Incorporation or Registration, which will not include information which is not relevant to the level of the Incorporating or Registration Agency;
8. Registration Number or if there is no Registration Number, the date of registration;
9. Physical address of Place of Business; and
10. Operational Existence.

**S/MIME Certificates**

Effective no later than 1 September 2023, the CA or RA will collect and retain evidence supporting the following identity attributes for the organization:

11. Formal name of the legal entity;
12. A registered DBA or trade name of the organization (if included in the Subject);
13. An organizational unit of the organization (if included in the Subject);
14. An address of the organization (if included in the Subject);
15. Jurisdiction of Incorporation or Registration of the organization; and
16. Unique identifier and type of identifier for the organization.

The CA or RA will verify the full legal name and an address (if included in the Certificate Subject) of the Applicant using documentation provided by, or through communication with, at least one of the following:

17. A government agency in the jurisdiction of the organization’s creation, existence, or recognition;
18. Legal Entity Identifier (LEI) data reference;
19. A site visit by the CA or a third party who is acting as an agent for the CA; or
20. An Attestation which includes a copy of supporting documentation used to establish the Applicant’s legal existence, such as a certificate of registration, articles of incorporation, operating agreement, statute, or regulatory act.

**EV TLS, EV Code Signing, S/MIME and Verified Mark Certificates**

Prior to the use of an Incorporating Agency or Registration Agency to fulfill these verification requirements, the agency information about the Incorporating Agency or Registration Agency will be disclosed at <https://www.entrust.com/legal-compliance/approved-incorporating-agencies>.

This agency information includes the following:

21. Sufficient information to unambiguously identify the Incorporating Agency or Registration Agency (such as a name, jurisdiction, and website);
22. The accepted value or values for each of the  
    subject:jurisdictionLocalityName (OID: 1.3.6.1.4.1.311.60.2.1.1), subject:jurisdictionStateOrProvinceName (OID: 1.3.6.1.4.1.311.60.2.1.2), and subject:jursidictionCountryName (OID: 1.3.6.1.4.1.311.60.2.1.3) fields, when a Certificate is issued using information from that Incorporating Agency or Registration Agency, indicating the jurisdiction(s) that the agency is appropriate for; and,
23. A revision history that includes a unique version number and date of publication for any additions, modifications, and/or removals from this list.

#### 3.2.2.2 DBA/Tradename

If the subject organization field is a DBA or tradename, the CA or the RA will verify the Applicant’s right to use the DBA/tradename using at least one of the following:

1. Documentation provided by, or communication with, a government agency in the jurisdiction of the Applicant’s legal creation, existence, or recognition;
2. A Reliable Data Source;
3. Communication with a government agency responsible for the management of such DBAs or tradenames;
4. An Attestation Letter accompanied by documentary support; or
5. A utility bill, bank statement, credit card statement, government‐issued tax document, or other form of identification that the CA determines to be reliable.

The CA or RA ensures the registration of the DBA or tradename is valid.

**EV TLS, EV Code Signing Certificates, and Verified Mark Certificates**

The CA verifies the Applicant has registered its use of the DBA or tradename with the appropriate government agency for such filings in the jurisdiction of its Place of Business. If a DBA or tradename is used, it will be included at the beginning of the organization field followed by the full legal organization name in parenthesis.

#### 3.2.2.3 Verification of Country

Verification of country will be done in accordance with the methods of §3.2.2.1.

#### 3.2.2.4 Validation of Domain Authorization or Control

The CA will confirm that prior to issuance, the CA or the RA validated each Fully‐Qualified Domain Name (FQDN) listed in the OV or EV TLS Certificate using at least one of the methods listed below.

Completed validations of Applicant authority may be used for the issuance of multiple Certificates over time. For purposes of domain validation, the term Applicant includes the Applicant's Parent Company, Subsidiary Company, or Affiliate.

The CA maintains a record of which domain validation method was used to validate every domain.

##### 3.2.2.4.1 Validating the Applicant as a Domain Contact

This method of domain validation is not used.

##### 3.2.2.4.2 Email, Fax, SMS, or Postal Mail to Domain Contact

Confirm the Applicant's control over the FQDN by sending a Random Value via email, fax, SMS, or postal mail and then receiving a confirming response utilizing the Random Value. The Random Value must be sent to an email address, fax/SMS number, or postal mail address identified as a Domain Contact.

Each email, fax, SMS, or postal mail may confirm control of multiple ADNs.

The CA or RA may send the email, fax, SMS, or postal mail identified under this section to more than one recipient provided that every recipient is identified by the Domain Name Registrar as representing the Domain Name Registrant for every FQDN being verified using the email, fax, SMS, or postal mail.

The Random Value is unique in each email, fax, SMS, or postal mail.

The CA or RA may resend the email, fax, SMS, or postal mail in its entirety, including re‐use of the Random Value, provided that the communication's entire contents and recipient(s) remain unchanged.

The Random Value will remain valid for use in a confirming response for no more than 30 days from its creation.

##### 3.2.2.4.3 Phone Contact with Domain Contact

This method of domain validation is not used.

##### 3.2.2.4.4 Constructed Email to Domain Contact

Confirm the Applicant's control over the FQDN by (i) sending an email to one or more addresses created by using 'admin', 'administrator', 'webmaster', 'hostmaster', or 'postmaster' as the local part, followed by the at‐sign ("@"), followed by an ADN, (ii) including a Random Value in the email, and (iii) receiving a confirming response utilizing the Random Value.

Each email may confirm control of multiple FQDNs, provided the ADN used in the email is an ADN for each FQDN being confirmed.

The Random Value shall be unique in each email.

The email may be re‐sent in its entirety, including the re‐use of the Random Value, provided that its entire contents and recipient shall remain unchanged.

The Random Value shall remain valid for use in a confirming response for no more than 30 days from its creation.

##### 3.2.2.4.5 Domain Authorization Document

This method of domain validation is not used.

##### 3.2.2.4.6 Agreed-Upon Change to Website

This method of domain validation is not used.

##### 3.2.2.4.7 DNS Change

Confirm the Applicant's control over the FQDN by confirming the presence of a Random Value in a DNS CNAME, TXT or CAA record for an ADN or an ADN that is prefixed with a Domain Label that begins with an underscore character.

If a Random Value is used, the CA or RA shall provide a Random Value unique to the Certificate request and shall not use the Random Value after (i) 30 days or (ii) if the Applicant submitted the Certificate request, the timeframe permitted for reuse of validated information relevant to the Certificate.

##### 3.2.2.4.8 IP Address

Confirming the Applicant's control over the FQDN by confirming that the Applicant controls an IP Address returned from a DNS lookup for A or AAAA records for the FQDN in accordance with §3.2.2.5.

Once the FQDN has been validated using this method, the CA does not issue Certificates for FQDNs for higher level domain levels that end in the validated FQDN unless the CA performs a separate validation for that FQDN using an authorized method. This method not used for validating Wildcard Domain Names.

##### 3.2.2.4.9 Test Certificate

This method of domain validation is not used.

##### 3.2.2.4.10 TLS Using a Random Number

This method of domain validation is not used.

##### 3.2.2.4.11 Any Other Method

This method of domain validation is not used.

##### 3.2.2.4.12 Validating Applicant as a Domain Contact

This method of domain validation is not used.

##### 3.2.2.4.13 Email to DNS CAA Contact

Confirm the Applicant's control over the FQDN by sending a Random Value via email and then receiving a confirming response utilizing the Random Value. The Random Value will be sent to a DNS CAA Email Contact. The relevant CAA Resource Record Set will be found using the search algorithm defined in RFC 8659 Section 3.

Each email may confirm control of multiple FQDNs, provided that each email address is a DNS CAA Email Contact for each ADN Name being validated. The same email may sent to multiple recipients as long as all recipients are the DNS CAA Email Contacts for each ADN being validated.

The Random Value shall be unique in each email. The email may be re-sent in its entirety, including the reuse of the Random Value, provided that its entire contents and recipient(s) remain unchanged. The Random Value shall remain valid for use in a confirming response for no more than 30 days from its creation.

##### 3.2.2.4.14 Email to DNS TXT Contact

Confirm the Applicant's control over the FQDN by sending a Random Value via email and then receiving a confirming response utilizing the Random Value. The Random Value will be sent to a DNS TXT Record Email Contact for the ADN selected to validate the FQDN.

Each email may confirm control of multiple FQDNs, provided that each email address is DNS TXT Record Email Contact for each ADN being validated. The same email may be sent to multiple recipients as long as all recipients are the DNS TXT Record Email Contacts for each ADN being validated.

The Random Value shall be unique in each email. The email may be re-sent in its entirety, including the reuse of the Random Value, provided that its entire contents and recipient(s) remain unchanged. The Random Value shall remain valid for use in a confirming response for no more than 30 days from its creation.

##### 3.2.2.4.15 Phone Contact with Domain Contact

Confirm the Applicant’s control over the FQDN by calling the Domain Contact’s phone number and obtain a confirming response to validate the ADN. Each phone call may confirm control of multiple ADNs provided that the same Domain Contact phone number is listed for each ADN being verified and they provide a confirming response for each ADN.

In the event that someone other than a Domain Contact is reached, the CA may request to be transferred to the Domain Contact.

In the event of reaching voicemail, the CA may leave the Random Value and the ADN(s) being validated. The Random Value must be returned to the CA to approve the request.

The Random Value shall remain valid for use in a confirming response for no more than 30 days from its creation.

##### 3.2.2.4.16 Phone Contact with DNS TXT Record Phone Contact

Confirm the Applicant’s control over the FQDN by calling the DNS TXT Record Phone Contact’s phone number and obtain a confirming response to validate the ADN. Each phone call may confirm control of multiple ADNs provided that the same DNS TXT Record Phone Contact phone number is listed for each ADN being verified and they provide a confirming response for each ADN.

The CA may not knowingly be transferred or request to be transferred as this phone number has been specifically listed for the purposes of domain validation.

In the event of reaching voicemail, the CA may leave the Random Value and the ADN(s) being validated. The Random Value must be returned to the CA to approve the request.

The Random Value shall remain valid for use in a confirming response for no more than 30 days from its creation.

##### 3.2.2.4.17 Phone Contact with DNS CAA Phone Contact

Confirm the Applicant’s control over the FQDN by calling the DNS CAA Phone Contact’s phone number and obtain a confirming response to validate the ADN. Each phone call may confirm control of multiple ADNs provided that the same DNS CAA Phone Contact phone number is listed for each ADN being verified and they provide a confirming response for each ADN. The relevant CAA Resource Record Set must be found using the search algorithm defined in RFC 8659 Section 3.

The CA may not knowingly be transferred or request to be transferred as this phone number has been specifically listed for the purposes of domain validation.

In the event of reaching voicemail, the CA may leave the Random Value and the ADN(s) being validated. The Random Value must be returned to the CA to approve the request.

The Random Value shall remain valid for use in a confirming response for no more than 30 days from its creation.

##### 3.2.2.4.18 Agreed-Upon Change to Website v2

Confirm the Applicant’s control over the FQDN by verifying that the Request Token or Random Value is contained in the contents of a file.

1. The entire Request Token or Random Value must not appear in the request used to retrieve the file, and
2. the CA MUST receive a successful HTTP response from the request (meaning a 2xx HTTP status code must be received).

The file containing the Request Token or Random Number:

3. Must be located on the Authorization Domain Name, and
4. Must be located under the "/.well-known/pki-validation" directory, and
5. Must be retrieved via either the "http" or "https" scheme, and
6. Must be accessed over an Authorized Port.

The CA follows redirects and the following apply:

7. Redirects must be initiated at the HTTP protocol layer. Redirects will only be the result of a 301, 302, or 307 HTTP status code response, as defined in RFC 7231, Section 6.4, or a 308 HTTP status code response, as defined in RFC 7538, Section 3. Redirects must be to the final value of the Location HTTP response header, as defined in RFC 7231, Section 7.1.2
8. Redirects must be to resource URLs with either via the "http" or "https" scheme.
9. Redirects must be to resource URLs accessed via Authorized Ports.

If a Random Value is used, then:

10. The CA must provide a Random Value unique to the certificate request.
11. The Random Value must remain valid for use in a confirming response for no more than 30 days from its creation. The CPS MAY specify a shorter validity period for Random Values, in which case the CA must follow its CPS.

Note: Once the FQDN has been validated using this method, the CA does not issue Certificates for other FQDNs that end with all the Domain Labels of the validated FQDN. This method is not used for validating Wildcard Domain Names.

##### 3.2.2.4.19 Agreed-Upon Change to Website - ACME

Confirming the Applicant’s control over a FQDN by validating domain control of the FQDN using the ACME HTTP Challenge method defined in Section 8.3 of RFC 8555. The following are additive requirements to RFC 8555.

The CA receives a successful HTTP response from the request (meaning a 2xx HTTP status code is received).

The token (as defined in RFC 8555, Section 8.3) is not used for more than 30 days from its creation.

If the CA follows redirects, the following apply:

1. Redirects are initiated at the HTTP protocol layer. Redirects will be the result of a 301, 302, or 307 HTTP status code response, as defined in RFC 7231, Section 6.4, or a 308 HTTP status code response, as defined in RFC 7538, Section 3. Redirects must be to the final value of the Location HTTP response header, as defined in RFC 7231, Section 7.1.2.
2. Redirects must be to resource URLs with either the "http" or "https" scheme.
3. Redirects must be to resource URLs accessed via Authorized Ports.

Note: The CA will not issue Certificates for other FQDNs that end with all the labels of the validated FQDN unless the CA performs a separate validation for that FQDN using an authorized method. This method is not used for validating Wildcard Domain Names.

##### 3.2.2.4.20 TLS Using ALPN

This method of domain validation is not used.

#### 3.2.2.5 Authentication for an IP Address

This section defines the permitted processes and procedures for validating the Applicant’s ownership or control of an IP Address listed in a Certificate.

The CA will confirm that prior to issuance, the CA has validated each IP Address listed in the Certificate using at least one of the methods specified in this section.

Completed validations of Applicant authority may be valid for the issuance of multiple Certificates over time. In all cases, the validation must have been initiated within the time period specified in §4.2.1.2 prior to Certificate issuance. For purposes of IP Address validation, the term Applicant includes the Applicant's Parent Company, Subsidiary Company, or Affiliate.

CAs will maintain a record of which IP Address validation method, including the relevant Baseline Requirements version number, was used to validate every IP Address.

##### 3.2.2.5.1 Agreed-Upon Change to Website

This method of IP Address validation is not used.

##### 3.2.2.5.2 Email, Fax, SMS, or Postal Mail to IP Address Contact

Confirm the Applicant’s control over the IP Address by sending a Random Value via email, fax, SMS, or postal mail and then receiving a confirming response utilizing the Random Value. The Random Value must be sent to an email address, fax/SMS number, or postal mail address identified as an IP Address Contact.

Each email, fax, SMS, or postal mail may confirm control of multiple IP Addresses.

The CA may send the email, fax, SMS, or postal mail identified under this section to more than one recipient provided that every recipient is identified by the IP Address Registration Authority as representing the IP Address Contact for every IP Address being verified using the email, fax, SMS, or postal mail.

The Random Value is unique in each email, fax, SMS, or postal mail.

The CA may resend the email, fax, SMS, or postal mail in its entirety, including re-use of the Random Value, provided that the communication’s entire contents and recipient(s) remain unchanged. The Random Value will remain valid for use in a confirming response for no more than 30 days from its creation.

##### 3.2.2.5.3 Reverse Address Lookup

Confirm the Applicant’s control over the IP Address by obtaining a Domain Name associated with the IP Address through a reverse-IP lookup on the IP Address and then verifying control over the FQDN using a method permitted under Baseline Requirements section 3.2.2.4.

##### 3.2.2.5.4 Any Other Method

This method of IP Address validation is not used.

##### 3.2.2.5.5 Phone Contact with IP Address Contact

This method of IP Address validation is not used.

##### 3.2.2.5.6 ACME "http-01" method for IP Addresses

This method of IP Address validation is not used.

##### 3.2.2.5.7 ACME "tls-alpn-01" method for IP Addresses

This method of IP Address validation is not used.

#### 3.2.2.6 Wildcard Domain Validation

The CAs follow a documented procedure that determines if the FQDN portion of any Wildcard Domain Name in the Certificate "registry‐controlled" label or is a "public suffix" (e.g. ".com",".co.uk", see RFC 6454 Section 8.2 for further explanation). If the FQDN portion of any Wildcard Domain Name is registry‐controlled or is a "public suffix", the CA will refuse issuance unless the Applicant proves its rightful control of the entire Domain Namespace.

#### 3.2.2.7 Data Source Accuracy

Prior to using any data source as a Reliable Data Source, the RA shall evaluate the source for its reliability, accuracy, and resistance to alteration or falsification.

#### 3.2.2.8 CAA Records

Entrust policy on CAA records is stated in §4.2.4.

#### 3.2.2.9 Authentication of Email Address

##### 3.2.2.9.1 Validating authority over mailbox via domain

The CA confirms the Enterprise RA has been authorized by the email account holder to act on the account holder’s behalf by verifying the entity’s control over the domain portion of the Mailbox Address to be used in the Certificate.

The CA will only use domain validation methods in §3.2.2.4 to perform this verification. For purposes of domain validation, the term Applicant includes the Applicant’s Parent Company, Subsidiary Company, or Affiliate.

##### 3.2.2.9.2 Validating control over mailbox via email

The CA confirms the Applicant’s control over each Mailbox Field to be included in a Certificate by sending a Random Value via email and then receiving a confirming response utilizing the Random Value. Control over each Mailbox Address is confirmed using a unique Random Value. The Random Value is only to the email address being validated and is not be shared in any other way. The Random Value is unique in each email.

Effective no later than 1 September 2023, the Random Value remains valid for use in a confirming response for no more than 24 hours from its creation. The Random Value will be reset upon each instance of the email sent by the CA to a Mailbox Address, however all relevant Random Values sent to that Mailbox Address may remain valid for use in a confirming response within the validity period. In addition, the Random Value will be reset upon first use by the user if intended for additional use as an authentication factor following the Mailbox Address verification.

##### 3.2.2.9.3 Validating applicant as operator of associated mail server(s)

This method of validation is not used.

#### 3.2.2.10 Authentication of Registered Trademark

**Verified Mark Certificates**

The CA or RA will perform the following:

1. Registered Mark
    1. Registered Mark is in good standing with the official database of the applicable trademark office;
    2. Mark Representation matches the Registered Mark as it appears in the official database of the applicable trademark office. ;
    3. Either 1) the owner of the Registered Mark is the same as the Subject organization (or to a Parent, Subsidiary, or Affiliate of the organization) of the Certificate or 2) the Subject organization has obtained the right to use the Registered Mark through a mutually agreed-on license from the entity who is the owner (or a Parent, Subsidiary, or Affiliate of the owner) of record of the Registered Mark and the owner has provided an authorization letter;
    4. Mark Representations are only be in colors if and as permitted by the Registered Mark and the applicable law of the Trademark Office; and
    5. Retain a screenshot or other record of the Mark Representation provided by the Applicant and all information about the Registered Mark obtained from the applicable trademark office.;
2. Trademark country or region of the trademark office;
3. Trademark registration number provided by the trademark office; and
4. Trademark office name is required, if the applicable country/region has regional intellectual property agencies.

**Government Mark Certificates**

The CA or RA will perform the following:

1. Government Mark Verification
    1. Confirm that a Mark or equivalent was granted to or claimed by a Government Entity or Non-Commercial Entity (International Organization) (or granted to a private organization or other organization by a Government Entity or Non-Commercial Entity \[International Organization\] through official statute, regulation, treaty, or government action) as it appears or is described in the statute, regulation, treaty, or government action and confirmed by a Mark Verifying Authority;
    2. Maintain a copy of the statute, regulation, treaty, or government action including all official references (e.g., statute or regulation number and jurisdiction) and a copy of the Mark image as contained in or referenced by the statute or regulation.
    3. Retain a screenshot or other record of the Mark Representation provided by the Applicant and all information supporting the verification of the Government Mark obtained from the applicable statute, regulation, treaty, or government action.
2. Government Mark Ownership or License
    1. Confirm that the owner of the Government Mark confirmed is the same Subject organization verified by the Verified Mark vetting process under §3.2, or if the owner of the Government Mark is not the same Subject organization, that the Subject organization has obtained the right to use the Government Mark through statute, regulation, treaty, or government action, or by a mutually agreed-upon license from the entity who is the owner of record of the Government Mark. If the owner of a Government Mark is not the Applicant, the Applicant may only use the Government Mark if the CA obtains an authorization letter from the owner of record of the Government Mark.
    2. In determining whether the Applicant is the owner or a licensee of the Government Mark corresponding to the Mark Representation, the CA will maintain a record of its decisions and reasons therefor in the CA’s records required in §3.2.1
3. Confirmation of Mark Representation
    1. Confirm that the Mark Representation submitted by the Applicant matches the verified Government Mark and maintain a record of its decisions and reasons.
4. Color Restrictions
    1. Examine the Government Mark to determine what rights, if any, the Subject organization has to use of the Government Mark in the colors of the Mark Representation submitted by the Subscriber and maintain a records of its decisions and reasons.

**Common Mark Certificates**

The CA or RA will perform the following:

1. Proof of Prior Use
    1. Verify a Mark that matches the Mark Representation is currently displayed on a website. The Applicant’s control of the domain name of the website is verified using at least one method specified in Section 3.2.14, and a Mark that matches the Mark Representation was historically displayed at least 12 months earlier than the date of Mark verification on a domain currently controlled by the applicant, where the historical display is verified via one of the following archive webpage sources allowed by these Requirements.
        1. Archive.org
    2. Color Restrictions - Mark Representations in Mark Certificates follow the same color rules that apply to Common Law Marks in the applicable jurisdiction. In determining whether the colors in the Mark Representation submitted by the Subscriber match the colors permitted by the rules that apply to Common Law Marks in the applicable jurisdiction, the CA maintains a record of its decision and reasons.
2. Modification of Registered Trademark
    1. For verification of the modification of Registered Trademark, the CA performs the verification steps for the Registered Mark that is to be the basis of the modification proposed by the Applicant. The Applicant will provide the Mark Representation in SVG format that the Applicant wishes to include in the Mark Certificate.
    2. The CA accepts the following forms of modification of the Registered Mark in the Mark Representation:
        1. For Combined Marks, the location of any Word Mark elements may be rearranged in relation to the Design Mark elements (for example, the Word Mark elements may be relocated from the right side of the Design Mark elements to below the Design Mark elements, and may also include separating and stacking the Word Mark elements into a more compact area).
        2. For Design Marks and Combined Marks, a portion of the Design Mark element may be removed (but more than 49% of the Design Mark element cannot be removed), but the remaining Design Mark element cannot be altered from the original. In the case of Combined Marks, the Word Mark elements may also be relocated in relation to the remaining Design Mark element as described in (i).
        3. For Word Marks and Combined Marks where the Word Mark element consists of a single word, the one word may be separated into multiple parts which may be stacked or not.
        4. For Word Marks and Combined Marks where the Word Mark element consists of multiple words, may be separated into multiple parts which may be stacked or not, or the multiple words may be combined into a single word.
        5. Modified Word Marks may be shown in any font or color against a colored or patterned background.
    3. The CA will review the modified Mark Representation to determine if the modification makes a significant change to the obvious meaning of the original mark (as compared to the Registered Mark), and if so should notify the Applicant that the modifications cannot be accepted as submitted but must be further modified. The Applicant may continue to request a Mark Certificate with the requested further modifications at the Applicant’s option.

### 3.2.3 Authentication of individual identity

The CA or the RA use the methods set out below to verify any individual identities that are submitted by an Applicant or Subscriber.

**OV TLS Certificates**

The CA does not issue OV TLS Certificates to individuals, where the name of the individual would be included in the subject field.

**EV TLS Certificates and EV Code Signing Certificates**

RAs operating under the CAs shall perform a verification of the identity and authority of the Contract Signer, the Certificate Approver, and the Certificate Requestor associated with Certificate Applications that are submitted by an Applicant or Subscriber. In order to establish the accuracy of an individual identity, the RA operating under a CA shall perform identity and authority verification consistent with the requirements set forth in the EV SSL Guidelines or the Code Signing Baseline Requirements published by the CA/Browser Forum.

**Class 2 S/MIME Certificates**

The Subject identity is authenticated by matching the identity provided by the Applicant or Subscriber to information contained in the business records or databases (e.g. employee or customer directories) of an Enterprise RA approving Certificates to its own affiliated individuals.

**Document Signing Certificates**

The Subject identity or the Applicant Representative identity is authenticated by face-to-face meeting or by means of a secure video communication where the Subject’s valid government-issued photo ID is used to provide identity.

**Verified Mark Certificates**

The Contract Signer or the Certificate Approver is authenticated by face-to-face based on the requirements of the VMC Requirements.

### 3.2.4 Non-verified subscriber information

All Certificate request information provided by the Subscriber is verified in accordance using an independent source of information or an alternative communication channel before it is included in the Certificate.

### 3.2.5 Validation of authority

If the Applicant for a Certificate containing subject identity information is an organization, the CA or RA will use a Reliable Method of Communication to verify the authority and approval of the Applicant Representative to:

1. to act as an Enterprise RA;
2. to request issuance or revocation of Certificates; or
3. to assign responsibilities to others to act in these roles.

The CA or RA may use the sources listed in §3.2.2.1 to verify the Reliable Method of Communication. Provided that the RA uses a Reliable Method of Communication, the RA may establish the authenticity of the Certificate request directly with the Applicant Representative or with an authoritative source within the Applicant’s organization, such as the Applicant’s main business offices, corporate offices, human resource offices, information technology offices, or other department that the RA deems appropriate.

The CA allows a Subscriber to specify the individuals who may request Certificates and will not accept any Certificate requests that are outside this specification. The CAs will provide a Subscriber with a list of its authorized individuals upon the Subscriber’s verified written request.

**EV TLS and EV Code Signing Certificates**

The CA or RA verifies the identity and authority of the Contract Signer and Certificate Approver in accordance with EV SSL Guidelines section 11.8.

**Verified Mark Certificates**

The CA or RA verifies the identity and authority of the Contract Signer and Certificate Approver in accordance with VMC Requirements.

### 3.2.6 Criteria for Interoperation or Certification

Externally issued Cross Certificates that identify Entrust as the subject are disclosed in §1.3.1, provided that Entrust arranged for or accepted the establishment of the trust relationship (i.e. the Cross Certificate at issue).

## 3.3 Identification and authentication for re-key requests

### 3.3.1 Identification and authentication for routine re-key

Each Certificate contains a Certificate expiration date. The reason for having an expiration date for a Certificate is to minimize the exposure of the Key Pair associated with the Certificate. For this reason, when processing a new Certificate Application, the CA recommends that a new Key Pair be generated and that the new Public Key of this Key Pair be submitted with the Applicant’s Certificate Application. If a Subscriber wishes to continue to use a Certificate beyond the expiry date for the current Certificate, the Subscriber must obtain a new Certificate and replace the Certificate that is about to expire. Subscribers submitting a new Certificate Application will be required to complete the initial application process, as described in §4.1. The RA may reuse documents and data provided in §3.2 to verify Certificate information per §4.2.1.2.

The RA that processed the Subscriber’s Certificate Application shall make a commercially reasonable effort to notify Subscribers of the pending expiration of their Certificate by sending an email to the technical contact listed in the corresponding Certificate Application. Upon expiration of a Certificate, the Subscriber shall immediately cease using such Certificate and shall remove such Certificate from any devices and/or software in which it has been installed.

OV TLS, EV TLS, and Client Authentication Certificates

The Subscriber may request a replacement Certificate using an existing Key Pair.

### 3.3.2 Identification and authentication for re-key after revocation

The CAs and RAs operating under the CAs do not renew Certificates that have been revoked. If a Subscriber wishes to use a Certificate after revocation, the Subscriber must apply for a new Certificate and replace the Certificate that has been revoked. In order to obtain another Certificate, the Subscriber shall be required to complete the initial application process, as described in §4.1. Upon revocation of a Certificate, the Subscriber shall immediately cease using such Certificate and shall remove such Certificate from any devices and/or software in which it has been installed.

## 3.4 Identification and authentication for revocation request

A Subscriber may request revocation of their Certificate at any time provided that the CA can validate the Subscriber is the person, organization, or entity to whom the Certificate was issued. The CA will authenticate a request from a Subscriber for revocation of their Certificate by authenticating the Subscriber or confirming authorization of the Subscriber through a Reliable Method of Communication. Upon receipt and confirmation of such information, the CA will then process the revocation request as stipulated in §4.9.

An Enterprise RA may use multi-factor authentication to request revocation of a Certificate.

# 4. CERTIFICATE LIFE-CYCLE OPERATIONAL REQUIREMENTS

## 4.1 Certificate Application

To obtain a Certificate, an Applicant must:

1. generate a secure and cryptographically sound Key Pair, if not generated by a CA
2. agree to all of the terms and conditions of the CPS and the Subscriber Agreement, and
3. complete and submit a Certificate Application, providing all information requested by an RA without any errors, misrepresentation, or omissions.

Upon an Applicant’s completion of the Certificate Application and acceptance of the terms and conditions of this CPS and the Subscriber Agreement, an RA shall follow the procedures described in §3.2 to perform verification of the information contained in the Certificate Application. If the verification performed by an RA is successful, the RA may, in its sole discretion, request the issuance to the Applicant of a Certificate from a CA.

**EV TLS, EV Code Signing and Verified Mark Certificates**

1. Certificate Requester - The Certificate request must be signed and submitted by an authorized Certificate Requester.
2. Certificate Approver - The Certificate request must be reviewed and approved by an authorized Certificate Approver.
3. Contract Signer - A Subscriber Agreement applicable to the requested Certificate must be signed by an authorized Contract Signer.

One person may be authorized by the Applicant to fill one, two, or all three of these roles. An Applicant may also authorize more than one person to fill each of these roles.

### 4.1.1 Who can submit a certificate application

Either the Applicant or an individual authorized to request Certificates on behalf of the Applicant may submit Certificate requests. Applicants are responsible for any data that the Applicant or an agent of the Applicant supplies to the RA.

The CAs shall identify subsequent suspicious Certificate requests in accordance with the high risk process per §4.2.1.3.

The CAs do not issue Certificates to any persons or entities on a government denied list maintained by Canada or that is located in a country with which the laws of Canada prohibit doing business.

### 4.1.2 Enrollment process and responsibilities

The CAs require each Applicant to submit a Certificate request and application information prior to issuing a Certificate. The CAs or RAs authenticates all communication from an Applicant and protects communication from modification.

Applicants request a Certificate by completing the request forms online. Applicants are solely responsible for submitting a complete and accurate Certificate request for each Certificate.

The enrollment process includes:

1. Agreeing to the applicable Subscriber Agreement,
2. Paying any applicable fees,
3. Submitting a complete Certificate application,
4. Generating a Key Pair, and
5. Delivering the Public Key of the Key Pair to the CA.

The Subscriber Agreement may be signed in either of the following methods:

6. If the Subscriber Agreement is in electronic form, it will be signed with an online click-through process.
7. Subscribers may print and sign a signature page referring to the Subscriber Agreement, and email or upload the signed document to Entrust.
8. Subscribers may negotiate the agreement that gets signed either electronically or with manual "wet" signatures by both parties.

Signing Services are supported by Certificates issued in accordance with this CPS.

## 4.2 Certificate application processing

### 4.2.1 Performing identification and authentication functions

The CA will follow a documented procedure for verifying all data requested for inclusion in the Certificate. In cases where the Certificate request does not contain all the necessary information about the Applicant, the CA will obtain the remaining information from a reliable, independent, third-party data source.

**OV and EV TLS Certificates**

The Applicant information will include at least one FQDN or IP address. For EV TLS Certificates, the Applicant will include at least one FQDN.

#### 4.2.1.1 Applicant Communication

**All Certificates except EV TLS, EV Code Signing and Verified Mark Certificates**

The CA uses a Reliable Method of Communication to verify the authenticity of the Applicant Representative’s certificate request. The CA uses the following sources to verify the Reliable Method of

Communication:

1. A government agency in the jurisdiction of the Applicant’s legal creation, existence, or recognition;
2. A third party database that is periodically updated and considered a Reliable Data Source;
3. A site visit by the CA or a third party who is acting as an agent for the CA; or
4. An Attestation Letter.

**EV TLS, EV Code Signing and Verified Mark Certificates**

The CA uses a Verified Method of Communication to verify the authenticity of the Applicant Representative’s certificate request. The CA uses the following sources to verify the Verified Method of

Communication:

5. Verify that the Verified Method of Communication belongs to the Applicant, or a Parent/Subsidiary or Affiliate of the Applicant, by matching it with one of the Applicant’s Parent/Subsidiary or Affiliate’s Places of Business in either the records provided by the applicable phone company, a QGIS, a QTIS, a QIIS, or a Verified Professional Letter; and
6. Confirm the Verified Method of Communication by using it to obtain an affirmative response sufficient to enable a reasonable person to conclude that the Applicant, or a Parent/Subsidiary or Affiliate of Applicant, can be contacted reliably by using the Verified Method of Communication.

#### 4.2.1.2 Validated Information Reuse

The CAs and RAs may use the documents and data provided in §3.2 to verify Certificate information, or may reuse previous validations themselves provided the data or documentation was obtained from a source specified under §3.2 or completed the validation itself no more than 825 days after such data or documentation was validated.

**OV TLS, EV TLS, Client Authentication and S/MIME Certificates**

For validation of Domain Names, email domains, and IP Addresses according to §3.2.2.4 and §3.2.2.5, any reused data, document, or completed validation can be obtained no more than 398 days prior to issuing the Certificate.

**Code Signing and EV Code Signing Certificates**

Reuse of previous validation of Subscriber Private Key protection according to §6.2.11 methods iv, v and vii may be reused no more than 13 months after such data was validated.

**EV TLS and EV Code Signing Certificates**

Reuse of previous validation data or documentation obtained from a source specified under §3.2 may be used no more than 398 days after such data or documentation was validated.

**Verified Mark Certificates**

Face-to-face validation is not required more than once for any Subscriber as long as the CA maintains continuous contact with one or more Subscriber representatives and maintains a system for authorization by the Subscriber of new Subscriber representatives.

An authorization letter from the owner of record of the Registered Mark or Government Mark (as described in §3.2.2.10) may be reused for up to 1,858 days.

Other data of previous validation data or documentation obtained from a source specified under §3.2 may be reused no more than 398 days after such data or documentation was validated.

**Document Signing Certificates**

Reuse of previous validation data or documentation obtained for face-to-face meeting validation under §3.2.3 may be used no more than 60 months after such data or documentation was validated.

#### 4.2.1.3 High Risk Certificate Requests

**OV and EV TLS Certificates**

The CAs maintain procedures to identify high risk Certificate requests that require additional verification activity prior to Certificate issuance. High risk certificate procedures include processes to verify high risk Domain Names and/or evaluate deceptive Domain Names.

**Code Signing and EV Code Signing Certificates**

Prior to issuing a Code Signing or EV Code Signing Certificate, the CA will check an internal listing of organizations which have intentionally signed Suspect Code. The CA will not issue a Certificate if the organization has been listed.

The CA may issue new or replacement Code Signing Certificates to an entity who is the victim of a documented Takeover Attack, resulting in a loss of control of the Private Key associated with their Code Signing or EV Code Signing Certificate. Except where issuance is expressly authorized by the ASV, the CA will not issue new Code Signing or EV Code Signing Certificates to an entity where the CA is aware that the entity has been the victim of two Takeover Attacks or where the CA is aware that entity breached a requirement to protect Private Keys under the requirements of §6.2.11.

#### 4.2.1.4 Subscriber Private Key Verification

**Code Signing and EV Code Signing Certificates**

Subscriber’s Private Key is generated, stored, and used in a suitable cryptographic module that meets or exceeds the requirements specified in §6.2.11. One of the following methods MUST be employed to satisfy this requirement:

1. The CA ships a suitable cryptographic module, with one or more pre‐generated Key Pairs that the CA has generated using the Hardware Crypto Module;
2. The Subscriber counter‐signs certificate requests that can be verified by using a manufacturer’s certificate, commonly known as key attestation, indicating that the Private Key was generated in a non‐exportable way using a suitable cryptographic module;
3. The Subscriber uses a CA prescribed crypto library and a suitable cryptographic module combination for the Key Pair generation and storage;
4. The Subscriber provides an internal or external IT audit indicating that it is only using a suitable cryptographic module to generate the Key Pairs;
5. The Subscriber provides a suitable report from the cloud‐based key protection solution subscription and resources configuration protecting the Private Key in a suitable cryptographic module;
6. The CA relies on a report provided by the Applicant that is signed by an auditor who is approved by the CA and who has IT and security training or is a CISA witnesses the Key Pair creation in a suitable cryptographic module solution including a cloud‐based key generation and protection solution; or
7. The Subscriber provides an agreement that they use a Signing Service meeting the requirements of the Code Signing Baseline Requirements section 6.2.7.3.

### 4.2.2 Approval or rejection of certificate applications

The CA or RA rejects any Certificate application that cannot be verified. The CA may also reject a Certificate application if the CA believes that issuing the Certificate could damage or diminish the CA’s reputation or business including the Entrust business.

**OV TLS, EV TLS, Client Authentication Certificates**

The CAs do not issue OV TLS, EV TLS, or Client Authentication Certificates containing Internal Names or Reserved IP Addresses.

**EV TLS, EV Code Signing and Verified Mark Certificates**

Certificate issuance approval requires authentication by two separate Validation Specialists. The second Validation Specialist cannot be the same individual who collected the authentication documentation and originally approved the Certificate application. The second Validation Specialist reviews the collected information and documents for discrepancies or details that require further explanation. If the second Validation Specialist has any concerns about the application, the second Validation Specialist may require additional explanations and documents. If satisfactory explanations and/or additional documents are not received within a reasonable time, the CA or RA may reject the Certificate application and notify the Applicant accordingly.

If some or all of the documentation used to support the application is in a language other than English, a CA or RA employee or agent skilled in such language and having the appropriate training, experience, and judgment in confirming organizational identification and authorization performs the final cross-correlation and due diligence.

If the Certificate application is not rejected and is successfully validated in accordance with this CPS, the CA will approve the Certificate application and issue the Certificate. Additional Certificates containing the same validated Certificate information may be requested by the Subscriber via a confirmed communication and issued without further authentication during the period permitted before reauthentication of Certificate information is required. The CA is not liable for any rejected Certificate application and is not obligated to disclose the reasons for a rejection. Rejected Applicants may re-apply. Subscribers are required to check the data listed in the Certificate for accuracy prior to using the Certificate.

### 4.2.3 Time to process certificate applications

No stipulation.

### 4.2.4 Certification Authority Authorization (CAA) Records

When CAA record checking is implemented, the CA checks for CAA records for each `dNSName` in the `subjectAltName` extension of the Certificate to be issued, according to the procedure in RFC 8659, following the processing instructions set down in RFC 8659 for any records found. If the Certificate is issued, it will be issued within the TTL of the CAA record, or 8 hours, whichever is greater.

When processing CAA records, the CAs process the property tags as specified in RFC 8659. The CA does not act on the contents of the `iodef` property tag. The CAs respect the critical flag and will not issue a Certificate if they encounter an unrecognized property with this flag set.

The CAs may not check CAA records for the following exceptions:

1. For Certificates for which a Certificate Transparency pre‐certificate was created and logged in at least two public logs, and for which CAA was checked.
2. For Certificates issued by a Technically Constrained Subordinate CA Certificate as set out in Baseline Requirements section 7.1.5, where the lack of CAA checking is an explicit contractual provision in the contract with the Applicant.

The CA treats a record lookup failure as permission to issue if:

3. the failure is outside the CA's infrastructure; and
4. the lookup has been retried at least once; and
5. the domain's zone does not have a DNSSEC validation chain to the ICANN root.

The CA documents potential issuances that were prevented by a CAA record in sufficient detail to provide feedback to the CAB Forum on the circumstances, and will dispatch reports of such issuance requests to the contact(s) stipulated in the CAA `iodef` record(s), if present. The CAs support `mailto:` and `https:` URL schemes in the `iodef` record.

Entrust CAA identifying domain is ‘**entrust.net**’.

**OV and EV TLS Certificates**

The CA performs CAA record checking on `issue`, `issuewild`, and `iodef` property tags prior to issuing OV and EV TLS Certificates.

**S/MIME Certificates**

Effective 15 March 2025, the CA will perform CAA record checking on `issuemail` property tags prior to issuing S/MIME Certificates. The CA will process the `issuemail` property tag as specified in RFC 9495.

**Verified Mark Certificate**

The CA performs CAA record checking on `issuevmc` property tag prior to issuing Verified Mark Certificates. The sub-syntax of the `issuevmc` property tag value is the processed the same as the `issue` property tag as defined in section 4.2 of RFC 8659.

## 4.3 Certificate issuance

After performing verification of the information provided by an Applicant with a Certificate Application, an RA operating under a CA may request that a CA issue a Certificate. Upon receipt of a request from an RA operating under a CA, the CA may generate and digitally sign a Certificate in accordance with the Certificate profile described in §7. An Enterprise RA can approve issuance of Certificates and submit the certificate request to an RA.

If a court or government body with jurisdiction over the activities covered by a CA/Browser Forum requirements document determines the performance of any mandatory requirement is illegal, then such requirement is considered reformed to the minimum extent necessary to make the requirement valid and legal. The CA will notify the CA/Browser Forum of the facts, circumstances, and law(s) involved.

### 4.3.1 CA actions during certificate issuance

Certificate issuance by the Root CA requires an individual authorized by the CA (i.e. the CA system operator, system officer, or PKI administrator) to deliberately issue a direct command in order for the Root CA to perform a certificate signing operation.

The CA will not issue Certificates with validity period that exceeds the validity period of the corresponding Root CA Certificate. The CA will not backdate the notBefore date of a Subscriber Certificate.

The CA enforces multi-factor authentication for all accounts capable of causing certificate issuance or performing Registration Authority. In addition, the CA implements technical controls operated to restrict issuance of OV TLS, EV TLS and S/MIME Certificates through accounts which are limited to a set of pre-approved domains or email addresses.

**OV and EV TLS Certificates**

OV and EV TLS Certificate requests are reviewed using linting software to monitor adherences to this CPS, the Baseline Requirements and the EV SSL Guidelines limited to the linter coverage.

### 4.3.2 Notification to subscriber by the CA of issuance of certificate

Once a Certificate has been generated and placed in a Repository, the RA that requested the issuance of the Certificate uses commercially reasonable efforts to notify the Applicant by email that the Applicant’s Certificate is available. The email may contain a URL for use by the Applicant to retrieve the Certificate.

## 4.4 Certificate acceptance

### 4.4.1 Conduct constituting certificate acceptance

No stipulation.

### 4.4.2 Publication of the certificate by the CA

No stipulation.

### 4.4.3 Notification of certificate issuance by the CA to other entities

**Subordinate CA Certificates**

Subordinate CA Certificates are disclosed in the CCADB within one week of Certificate issuance.

**OV and EV TLS Certificates**

OV and EV TLS Certificates may include two or more signed certificate timestamps (SCT) from ASV approved independent Certificate Transparency logs.

**Verified Mark Certificates**

Verified Mark Certificates will include one or more signed certificate timestamps (SCT) from Certificate Transparency logs as defined in the VMC Requirements.

## 4.5 Key pair and certificate usage

### 4.5.1 Subscriber private key and certificate usage

Subscriber shall conform to §9.6.3.

**Managed and Hosted Cryptographic Module**

In the case a CA managed and hosted cryptographic module is used, the Certificate is required to be valid to allow the Subject to activate the associated Private Key.

### 4.5.2 Relying party public key and certificate usage

Relying Parties shall conform to §9.6.4.

## 4.6 Certificate renewal

### 4.6.1 Circumstance for certificate renewal

In accordance with the Subscriber Agreement, CAs or RAs will provide a Certificate lifecycle monitoring service which will support Certificate renewal.

### 4.6.2 Who may request renewal

Subscribers or Subscriber agents may request renewal of Certificates.

### 4.6.3 Processing certificate renewal requests

CAs or RAs will process Certificate renewal requests with validated verification data. Previous verification data may be used as specified in §4.2.1.2.

Certificates may be renewed using the previously accepted Public Key, if the Public Key meets the key size requirements of §6.1.5. The Public Key may not be reused if another Certificate with the same Public Key has been revoked due to Key Compromise.

### 4.6.4 Notification of new certificate issuance to subscriber

CAs or RAs will provide Certificate renewal notification to the Subscriber or Subscriber agents through an Internet link or by email. Subscribers or Subscriber agents may request that email renewal notices are not sent for their expiring Certificates.

### 4.6.5 Conduct constituting acceptance of a renewal certificate

No stipulation.

### 4.6.6 Publication of the renewal certificate by the CA

CAs or RAs will provide the Subscriber with a Certificate through an Internet link.

### 4.6.7 Notification of certificate issuance by the CA to other entities

No stipulation.

## 4.7 Certificate re-key

### 4.7.1 Circumstance for certificate re-key

No stipulation.

### 4.7.2 Who may request certification of a new public key

No stipulation.

### 4.7.3 Processing certificate re-keying requests

No stipulation.

### 4.7.4 Notification of new certificate issuance to subscriber

No stipulation.

### 4.7.5 Conduct constituting acceptance of a re-keyed certificate

No stipulation.

### 4.7.6 Publication of the re-keyed certificate by the CA

No stipulation.

### 4.7.7 Notification of certificate issuance by the CA to other entities

No stipulation.

## 4.8 Certificate modification

### 4.8.1 Circumstance for certificate modification

No stipulation.

### 4.8.2 Who may request certificate modification

No stipulation.

### 4.8.3 Processing certificate modification requests

No stipulation.

### 4.8.4 Notification of new certificate issuance to subscriber

No stipulation.

### 4.8.5 Conduct constituting acceptance of modified certificate

No stipulation.

### 4.8.6 Publication of the modified certificate by the CA

No stipulation.

### 4.8.7 Notification of certificate issuance by the CA to other entities

No stipulation.

## 4.9 Certificate revocation and suspension

The CA revokes a Certificate after receiving a valid revocation request from an RA operating under such CA. An RA operating under a CA is entitled to request and may request that a CA revoke a Certificate after such RA receives a valid revocation request from the Subscriber for such Certificate. An RA operating under a CA is entitled to request and shall request that a CA revoke a Certificate if such RA becomes aware of the occurrence of any event that would require a Subscriber to cease to use such Certificate.

CAs do not support the suspension of Certificates.

### 4.9.1 Circumstances for revocation

#### 4.9.1.1 Reasons for Revoking a Subscriber Certificate

The CA shall be entitled to revoke and may revoke, and an RA operating under a CA shall be entitled to request revocation of and shall request revocation of, a Subscriber’s Certificate if the CA or RA has knowledge of or a reasonable basis for believing that of any of the events listed in this section have occurred.

Where required by the third party requirements specified in §1.1, the CA will revoke a Certificate within 24 hours and use the corresponding reasonCode if one or more of the following occurs:

1. The Subscriber requests in writing, without specifying a CRLreason, that the CA revoke the Certificate (no reasonCode in CRL);
2. The Subscriber notifies the CA that the original Certificate request was not authorized and does not retroactively grant authorization (privilegeWithdrawn (9) reasonCode);
3. The CA obtains evidence that the Subscriber’s Private Key corresponding to the Public Key in the Certificate suffered a Key Compromise (keyCompromise (1) reasonCode);
4. The CA is made aware of a demonstrated or proven method that can easily compute the Subscriber's Private Key based on the Public Key in the Certificate (such as a Debian weak key, see <https://wiki.debian.org/SSLkeys>) (keyCompromise (1) reasonCode);or
5. The CA obtains evidence that the validation of the domain authorization or control for any FQDN, IP Address or email address in the Certificate should not be relied upon (superceded (4) reasonCode).
6. A Certificate is used to digitally sign Suspect Code (keyCompromise (1) reasonCode).

Where required by the third party requirements specified in §1.1, the CA will revoke a Certificate within 5 days and use the corresponding reasonCode if one or more of the following occurs:

7. The Certificate no longer complies with the requirements of §6.1.5 and §6.1.6 (superseded (4) reasonCode);
8. The CA obtains evidence that the Certificate was misused (privilegeWithdrawn (9) reasonCode);
9. The CA is made aware that a Subscriber has violated one or more of its material obligations under the Subscriber Agreement (privilegeWithdrawn (9) reasonCode);
10. The CA is made aware of any circumstance indicating that use of a FQDN, IP Address, or email address in the Certificate is no longer legally permitted (e.g. a court or arbitrator has revoked a Domain Name Registrant’s right to use the Domain Name, a relevant licensing or services agreement between the Domain Name Registrant and the Applicant has terminated, or the Domain Name Registrant has failed to renew the Domain Name) (cessationOfOperation (5) reasonCode);
11. The CA is made aware that a Certificate with a Wildcard Domain Name has been used to authenticate a fraudulently misleading subordinate FQDN (privilegeWithdrawn (9) reasonCode);
12. The CA is made aware of a material change in the information contained in the Certificate (privilegeWithdrawn (9) reasonCode);
13. The CA is made aware that the Certificate was not issued in accordance with the third party requirements specified in §1.1 or this CPS (superseded (4) reasonCode);
14. The CA determines that any of the information appearing in the Certificate is inaccurate (privilegeWithdrawn (9) reasonCode);
15. The CA’s right to issue Certificates under this CPS expires or is revoked or terminated, unless the CA has made arrangements to continue maintaining the CRL/OCSP Repository (no reasonCode in CRL);
16. Revocation is required by any other section in this CPS for a reason that is not otherwise required to be specified by this §4.9.1.1 (no reasonCode in CRL);
17. The CA is made aware of a demonstrated or proven method that exposes the Subscriber's Private Key to compromise or if there is clear evidence that the specific method used to generate the Private Key was flawed (keyCompromise (1) reasonCode); or
18. Any other reason that may be reasonably expected to affect the integrity, security, or trustworthiness of a Certificate or CA (no reasonCode in CRL).

When none of the third party requirements specified in §1.1 apply to a Certificate, the CA may revoke a Certificate for any of the reasons set out above in its reasonable discretion and on a timeline determined by the CA in its reasonable discretion.

**Code Signing or EV Code Signing Certificate**

The CA will revoke a Certificate within 5 days and use the corresponding reasonCode if one or more of the following occurs:

19. Effective 15 April 2024, when a Certificate is revoked due to a Key Compromise or use in Suspect Code, the CA will determine an appropriate value for the revocationDate based on its own investigation. The CA will set a historic date as revocationDate if deemed appropriate.
20. The CA may delay revocation based on a request from an ASV where immediate revocation has a potentially large negative impact to the ecosystem.

**Verified Mark or Mark Certificate**

The CA will revoke a Certificate within 5 days and use the corresponding reasonCode if one or more of the following occurs:

21. The CA receives a Court Order of Infringement, confirms the authenticity of the Court Order of Infringement, and provides 3 business days' notice to the Subscriber that the VMC or MC will be revoked (privilegeWithdrawn (9) reasonCode).

Subscribers may perform actions to revoke their Certificates as follows:

22. Subscriber revokes Certificate without specifying a CRLreason (unspecified (0) reasonCode with no reasonCode in CRL);
23. Subscriber knows or suspects their Certificate Private Key has suffered a Key Compromise (keyCompromise (1) reasonCode);
24. Subscriber knows the Subject’s name or other Subject Identity Information in the Certificate has changed, but there is no cause to suspect that the Certificate’s Private Key has suffered a Key Compromise (affiliationChanged (3) reasonCode);
25. Subscriber has replaced the Certificate with a new Certificate (superseded (4) reasonCode);
26. Subscriber has shut down the website prior to the expiration of the Certificate, or if the Subscriber no longer owns or controls the Domain Name in the Certificate prior to the expiration of the Certificate (cessationOfOperation (5) reasonCode).

Subscribers may request the CA to revoke their Certificates as follows:

27. Subscriber notifies the CA that the original Certificate request was not authorized and does not retroactively grant authorization (privilegeWithdrawn (9) reasonCode).

#### 4.9.1.2 Reasons for Revoking a Subordinate CA Certificate

The Issuing CA shall revoke a Subordinate CA Certificate within seven (7) days if one or more of the following occurs:

1. The Subordinate CA requests revocation in writing;
2. The Subordinate CA notifies the Issuing CA that the original Certificate request was not authorized and does not retroactively grant authorization;
3. The Issuing CA obtains evidence that the Subordinate CA’s Private Key corresponding to the Public Key in the Certificate suffered a Key Compromise or no longer complies with the requirements of §6.1.5 and §6.1.6,
4. The Issuing CA obtains evidence that the Certificate was misused;
5. The Issuing CA is made aware that the Certificate was not issued in accordance with or that Subordinate CA has not complied with the Baseline Requirements, EV SSL Guidelines, Baseline Requirements for Code Signing or this CPS;
6. The Issuing CA determines that any of the information appearing in the Certificate is inaccurate or misleading;
7. The Issuing CA or Subordinate CA ceases operations for any reason and has not made arrangements for another CA to provide revocation support for the Certificate;
8. The Issuing CA’s or Subordinate CA's right to issue Certificates under the Baseline Requirements expires or is revoked or terminated, unless the Issuing CA has made arrangements to continue maintaining the CRL/OCSP Repository; or
9. Revocation is required by the Issuing CA’s CPS.

### 4.9.2 Who can request revocation

CAs, RAs and Subscribers may initiate revocation.

A Subscriber or another appropriately authorized party (such as an administrative contact, a Contract Signer, Certificate Approver, Certificate Requester, or Enterprise RA) may request revocation of their Certificate at any time for any reason. If a Subscriber requests revocation of their Certificate, the Subscriber must be able to validate themselves as set forth in §3.4 to the RA that processed the Subscriber’s Certificate Application. The CAs shall not be required to revoke and the RAs operating under the CAs shall not be required to request revocation of a Certificate until a Subscriber can properly validate themselves as set forth in §4.9.3. A CA shall be entitled to revoke and shall revoke, and an RA operating under a CA shall be entitled to request revocation of and shall request revocation of, a Subscriber’s Certificate at any time for any of the reasons set forth in §4.9.1.

Subscribers, Relying Parties, ASVs, Anti-Malware Organizations and other third parties may submit CPRs informing the CA of a reasonable cause to revoke the Certificate.

### 4.9.3 Procedure for revocation request

A Subscriber shall request revocation of their Certificate if the Subscriber has a suspicion or knowledge of or a reasonable basis for believing that of any of the following events have occurred:

1. Compromise of the Subscriber’s Private Key;
2. Knowledge that the original Certificate request was not authorized and such authorization will not be retroactively granted;
3. Change in the information contained in the Subscriber’s Certificate;
4. Change in circumstances that cause the information contained in Subscriber’s Certificate to become inaccurate, incomplete, or misleading.

A Subscriber request for revocation of their Certificate may be verified by (i) Subscriber authentication credentials, or (ii) authorization of the Subscriber through a Reliable Method of Communication.

If a Subscriber’s Certificate is revoked for any reason, the Subscriber shall be notified by sending an email to the technical and security contacts listed in the Certificate Application. Revocation of a Certificate shall not affect any of the Subscriber’s contractual obligations under this CPS, the Subscriber’s Subscriber Agreement, or any Relying Party Agreements.

Subscribers, Relying Parties, ASVs, Anti-Malware Organizations and other third parties may submit a CPR by notification through the contact information specified in §1.5.2. If a CPR is received, the CA shall:

5. Log the CPR as high severity into a ticketing system for tracking purposes;
6. Review the CPR and engage the necessary parties to verify the CPR, draft a CPR investigation report and provide the CPR investigation report to the Subscriber and the party that provided the CPR within 24 hours from receipt of the CPR;
7. Determine if there was Certificate mis-issuance. In the case of Certificate miss-issuance, the incident must be 1) escalated to the policy authority team and to service management and 2) a Certificate mis-issuance report must be publicly posted within one business day;
8. If Certificate revocation is required, perform revocation in accordance with the requirements of §4.9.1.1;
9. Update the Certificate mis-issuance report within 5 days from receipt of CPR; and
10. Complete the CPR investigation report when the incident is closed and provide a copy to the Subscriber and the party that provided the CPR.

### 4.9.4 Revocation request grace period

In the case of Private Key Compromise, or suspected Private Key Compromise, a Subscriber shall request revocation of the corresponding Certificate immediately upon detection of the Compromise or suspected Compromise. Revocation requests for other required reasons shall be made as soon as reasonably practicable.

### 4.9.5 Time within which CA must process the revocation request

Within 24 hours after receiving a CPR, the CA will investigate the facts and circumstances related to the CPR and provide a preliminary report to both the Subscriber and the entity who filed the CPR.

After reviewing the facts and circumstances, the CA will work with the Subscriber and any entity reporting the CPR or other revocation-related notice to establish whether or not the Certificate will be revoked, and if so, a date which the CA will revoke the Certificate. The period from receipt of the CPR or revocation-related notice to published revocation will not exceed the timeframe set forth in §4.9.1.1. The date selected by the CA will consider the following criteria:

1. The nature of the alleged problem (scope, context, severity, magnitude, risk of harm);
2. The consequences of revocation (direct and collateral impacts to Subscribers and Relying Parties);
3. The number of CPRs received about a particular Certificate or Subscriber;
4. The entity making the complaint (for example, a complaint from a law enforcement official that a Web site is engaged in illegal activities should carry more weight than a complaint from a consumer alleging that they didn’t receive the goods they ordered); and
5. Relevant legislation.

### 4.9.6 Revocation checking requirement for relying parties

A Relying Party shall check whether the Certificate that the Relying Party wishes to rely on has been revoked. A Relying Party shall check the Certificate Revocation Lists maintained in the appropriate Repository or perform an on-line revocation status check using OCSP to determine whether the Certificate that the Relying Party wishes to rely on has been revoked. In no event shall the Entrust Group be liable for any damages whatsoever due to (i) the failure of a Relying Party to check for revocation or expiration of a Certificate, or (ii) any reliance by a Relying Party on a Certificate that has been revoked or that has expired.

### 4.9.7 CRL issuance frequency

The CAs issue CRLs as follows:

1. CRLs for Certificates issued to Subordinate CAs are be issued at least once every twelve months or with 24 hours after revoking a Subordinate CA Certificate. The next CRL update will not be more than twelve months from the last update.
2. CRLs for Subscriber Certificates are issued at least once every 24 hours. The CRL validity interval is not more than ten days.


### 4.9.8 Maximum latency for CRLs (if applicable)

No stipulation.

### 4.9.9 On-line revocation/status checking availability

On-line revocation/status checking of Certificates is available on a continuous basis by CRL or On-line Certificate Status Protocol (OCSP).

OCSP responses are signed by the CA or an OCSP responder whose Certificate is signed by the CA that issued the Certificate whose revocation status is being checked. The OCSP signing Certificate contains an extension of type `id-pkix-ocsp-nocheck`, as defined by RFC 6960.

### 4.9.10 On-line revocation checking requirements

The CAs support an OCSP capability using the GET method as described in RFC6960 for Certificates issued in accordance with this CPS.

The CAs sign and make available OCSP as follows:

1. OCSP responses for Certificates issued to Subordinate CAs are issued at least once every twelve months or within 24 hours after revoking a Subordinate CA Certificate.
2. OCSP responses for precertificates (RFC 6962) and Subscriber Certificates are issued at least once every 24 hours. OCSP responses will have a validity interval that is greater than 8 hours and not more than 10 days.

Note, the validity interval of an OCSP response is the difference in time between the `thisUpdate` and `nextUpdate` field, inclusive. For purposes of computing differences, a difference of 3,600 seconds shall be equal to one hour, and a difference of 86,400 seconds shall be equal to one day, ignoring leap-seconds.

Code Signing Certificates that have been revoked due to Key Compromise or issued to unauthorized person will be maintained in the Repository for at least ten years following revocation.

A certificate serial number within an OCSP request is either "assigned" with a Certificate or "reserved" with a precertificate. If not "assigned’ or "reserved", then the serial number is "unused". If the OCSP responder receives a request for status of a Certificate serial number that is "unused", then the responder will not respond with a "good" status.

The on-line locations of the CRL and the OCSP response are included in the Certificate to support software applications that perform automatic Certificate status checking. A Relying Party can also be check Certificate revocation status directly with the Repository at <https://www.entrust.net/CPS>.

### 4.9.11 Other forms of revocation advertisements available

No Stipulation.

### 4.9.12 Special requirements re key compromise

If a Subscriber suspects or knows that the Private Key corresponding to the Public Key contained in the Subscriber’s Certificate has been Compromised, the Subscriber shall immediately notify the RA that processed the Subscriber’s Certificate Application, using the procedures set forth in §3.4, of such suspected or actual Compromise. The Subscriber shall immediately stop using such Certificate and shall remove such Certificate from any devices and/or software in which such Certificate has been installed. The Subscriber shall be responsible for investigating the circumstances of such Compromise or suspected Compromise and for notifying any Relying Parties that may have been affected by such Compromise or suspected Compromise.

Subscribers, Relying Parties, ASVs, Anti-Malware Organizations and other third parties may advise Entrust of a Private Key Compromise using one of the following demonstration methods:

1. Submission of a signed CSR with a common name of "Proof of Key Compromise for Entrust", or
2. Submission of a Private Key.

### 4.9.13 Circumstances for suspension

The Repository will not include entries that indicate that a Certificate has been suspended.

### 4.9.14 Who can request suspension

Not applicable.

### 4.9.15 Procedure for suspension request

Not applicable.

### 4.9.16 Limits on suspension period

Not applicable.

## 4.10 Certificate status services

### 4.10.1 Operational characteristics

**OV TLS, EV TLS, Client Authentication and S/MIME Certificates**

Revocation entries on a CRL or OCSP response are not removed until after the expiry date of the revoked Certificate.

### 4.10.2 Service availability

The CA operates and maintains its CRL and OCSP capability with resources sufficient to provide a response time of ten seconds or less under normal operating conditions.

The CA maintains an online 24x7 Repository that application software can use to automatically check the current status of all unexpired Certificates issued by the CA.

The CA maintains a continuous 24x7 ability to respond internally to a high-priority CPR. Where appropriate, the CA forwards such a complaint to law enforcement authorities, and/or revokes a Certificate that is the subject of such a complaint.

### 4.10.3 Optional features

No stipulation.

## 4.11 End of subscription

No stipulation.

## 4.12 Key escrow and recovery

### 4.12.1 Key escrow and recovery policy and practices

**S/MIME Certificates**

Subscribers may choose to have the CA generate the Key Pair and escrow the Private Key. The Private Key is stored in encrypted form and protected from unauthorized disclosure. The Private Key will be recovered at the time of S/MIME Certificate renewal or reissue.

**Managed and Hosted Cryptographic Module**

In the case a CA managed and hosted cryptographic module is used, the Private Key will be escrowed on behalf of the Subscriber.

### 4.12.2 Session key encapsulation and recovery policy and practices

No stipulation.

# 5. FACILITY, MANAGEMENT, AND OPERATIONAL CONTROLS

The CA/Browser Forum’s Network and Certificate System Security Requirements are incorporated by reference as if fully set forth herein.

## 5.1 Physical Security Controls

### 5.1.1 Site location and construction

The computing facilities that host the CA services are located in Ottawa, Canada. The CA equipment is located in a security zone that is physically separated from Entrust’s other systems to restrict access to personnel in Trusted Roles. The security zone is constructed with privacy and secured with slab-to-slab wire mesh. The security zone is protected by electronic control access systems, alarmed doors and is monitored via a 24x7 recorded security camera and motion detector system.

### 5.1.2 Physical access

The room containing the CA software is designated a two (2) person zone, and controls are used to prevent a person from being in the room alone. Alarm systems are used to notify security personnel of any violation of the rules for access to a CA.

### 5.1.3 Power and air conditioning

The Security zone is equipped with:

- Filtered, conditioned, power connected to an appropriately sized UPS and generator;
- Heating, ventilation, and air conditioning appropriate for a commercial data processing facility; and
- Emergency lighting.

The environmental controls conform to local standards and are appropriately secured to prevent unauthorized access and/or tampering with the equipment. Temperature control alarms and alerts are activated upon detection of threatening temperature conditions.

### 5.1.4 Water exposures

No liquid, gas, exhaust, etc. pipes traverse the controlled space other than those directly required for the area’s HVAC system and for the pre-action fire suppression system. Water pipes for the pre-action fire suppression system are only filled on the activation of multiple fire alarms.

### 5.1.5 Fire prevention and protection

The CA facility is fully wired for fire detection, alarm and suppression. Routine, frequent inspections of all systems are made to assure adequate operation.

### 5.1.6 Media storage

All media is stored away from sources of heat and from obvious sources of water or other obvious hazards. Electromagnetic media (e.g. tapes) are stored away from obvious sources of strong magnetic fields. Archived material is stored in a room separate from the CA equipment until it is transferred to the archive storage facility.

### 5.1.7 Waste disposal

Waste is removed or destroyed in accordance with industry best practice. Media used to store sensitive data is destroyed, such that the information is unrecoverable, prior to disposal.

### 5.1.8 Off-site backup

As stipulated in §5.5.

## 5.2 Procedural controls

### 5.2.1 Trusted roles

The CAs have a number of Trusted Roles for sensitive operations of the CA software.

### 5.2.2 Number of persons required per task

CA operations related to changing CA policy settings require more than one person with a Trusted Role to perform the operation.

The CA Private Keys are backed up, stored, and recovered only by personnel in Trusted Roles using dual control in a physically secured environment.

### 5.2.3 Identification and authentication for each role

Personnel in Trusted Roles must undergo background investigations and must be trained for their specific role.

### 5.2.4 Roles requiring separation of duties

Roles requiring a separation of duties include those performing:

1. Authorization functions such as the verification of information in Certificate applications and approvals of Certificate applications and revocation requests,
2. Certificate revocation,
3. Backups, recording, and record keeping functions;
4. Audit, review, oversight, or reconciliation functions; and
5. Duties related to CA key management or administration.

## 5.3 Personnel controls

Operational personnel for a CA will not be assigned other responsibilities that conflict with their operational responsibilities for the CA. The privileges assigned to operational personnel for a CA will be limited to the minimum required to carry out their assigned duties.

### 5.3.1 Qualifications, experience, and clearance requirements

Prior to the engagement of any person in the Certificate management process, the CA or RA shall verify the identity and trustworthiness of such person.

### 5.3.2 Background check procedures

No stipulation.

### 5.3.3 Training requirements

Personnel in Trusted Roles and Validation Specialists are provided skills-training which is based on industry requirements including the Baseline Requirements, EV SSL Guidelines, Code Signing Baseline Requirements, S/MIME Baseline Requirements and VMC Requirements.

Validation Specialists perform information verification duties with skills-training that covers basic PKI knowledge, authentication and vetting policies and procedures (including this CPS), and common threats to the information verification process (including phishing and other social engineering tactics). Validation Specialists receive skills-training prior to commencing their job role and are required them to pass an examination on the applicable information verification requirements. The CA maintains records of such training and ensures that personnel entrusted with Validation Specialist duties maintain an appropriate skill level.

### 5.3.4 Retraining frequency and requirements

CAs and RAs provide refresher training and informational updates sufficient to ensure that all personnel in Trusted Roles retain the requisite degree of expertise.

### 5.3.5 Job rotation frequency and sequence

No stipulation.

### 5.3.6 Sanctions for unauthorized actions

No stipulation.

### 5.3.7 Independent contractor requirements

Third Party RAs personnel involved in the issuance of a Certificate shall meet the training and skills requirements of §5.3.3 and the document retention and event logging requirements of §5.4.1.

### 5.3.8 Documentation supplied to personnel

No stipulation.

## 5.4 Audit logging procedures

Significant security events in the CAs and all RAs operating under a CA are automatically time-stamped and recorded as audit logs in audit trail files. The audit trail files are processed (reviewed for policy violations or other significant events) on a regular basis. Audit trail files are archived periodically. All files including the latest audit trail file are moved to backup media and stored in a secure archive facility.

The time for the CAs computer systems is synchronized with the service provided by the National Research Council Canada.

### 5.4.1 Types of events recorded

The CAs and all RAs operating under a CA record in detail every action taken to process a Certificate request and to issue a Certificate, including all information generated or received in connection with a Certificate request, and every action taken to process the Request, including time, date, and personnel involved in the action.

The foregoing record requirements include, but are not limited to, an obligation to record the following events:

1. CA Certificate key lifecycle events, including:
    1. Key generation, backup, storage, recovery, archival, and destruction;
    2. Certificate requests, renewal and re-key requests, and revocation;
    3. Approval and rejection of Certificate requests;
    4. Cryptographic device lifecycle management events ;
    5. Generation of CRLs;
    6. Signing of OCSP responses; and
    7. Introduction of new Certificate Profiles and retirement of existing Certificate Profiles.
2. Subscriber Certificate lifecycle management events, including:
    1. Certificate requests, renewal and re-key requests, and revocation;
    2. All verification activities required by this CPS;
    3. Approval and rejection of Certificate requests;
    4. Issuance of Certificates; and
    5. Generation of CRLs;
    6. Signing of OCSP responses.
3. Security events, including:
    1. Successful and unsuccessful PKI system access attempts;
    2. PKI and security system actions performed;
    3. Security profile changes;
    4. System crashes, hardware failures, and other anomalies;
    5. Firewall and router activities; and
    6. Entries to and exits from the CA facility.

Log entries include the following elements:

1. Date and time of event;
2. Identity of the person making the journal record; and
3. Description of event.

### 5.4.2 Frequency of processing log

No stipulation

### 5.4.3 Retention period for audit log

The CA will retain, for at least two years:

(i) CA Certificate and key lifecycle management event records, as set forth in §5.4.1(i), after either: the destruction of the CA key, or the revocation or expiration of the CA Certificate, whichever occurs later;

(ii) Subscriber Certificate lifecycle management event records, as set forth in §5.4.1(ii), after the expiration of the Subscriber Certificate; and

(iii) Any security event records, as set forth in §5.4.1(iii), after the event occurred.

### 5.4.4 Protection of audit log

No stipulation.

### 5.4.5 Audit log backup procedures

No stipulation.

### 5.4.6 Audit collection system (internal vs. external)

No stipulation.

### 5.4.7 Notification to event-causing subject

No stipulation.

### 5.4.8 Vulnerability assessments

CAs annually perform a risk assessment that:

1. Identifies foreseeable internal and external threats that could result in unauthorized access, disclosure, misuse, alteration, or destruction of any Certificate data or Certificate management processes;
2. Assesses the likelihood and potential damage of these threats, taking into consideration the sensitivity of the Certificate data and Certificate management processes; and
3. Assesses the sufficiency of the policies, procedures, information systems, technology, and other arrangements that the CA has in place to counter such threats.

Based on the risk assessment, a security plan is developed, implemented, and maintained consisting of security procedures, measures, and products designed to achieve the objectives set forth above and to manage and control the risks identified during the risk assessment. The security plan includes administrative, organizational, technical, and physical safeguards appropriate to the sensitivity of the Certificate data and Certificate management processes. The security plan also takes into account then-available technology and the cost of implementing the specific measures, and implements a reasonable level of security appropriate to the harm that might result from a breach of security and the nature of the data to be protected.

CAs will perform a vulnerability scan if:

1. Receiving a request from the CA/Browser Forum;
2. After any system or network changes which the CA determines are significant; and
3. At least every three months on public and private IP addresses identified by the CA as the CA’s Certificate Systems.

## 5.5 Records archival

### 5.5.1 Types of records archived

The CA archives:

1. All audit logs as set forth in §5.4.1;
2. Documentation related to the security of their Certificate systems, Certificate management systems, and Root CA systems; and
3. Documentation related to their verification, issuance, and revocation of certificate requests and Certificates.

### 5.5.2 Retention period for archive

Archived audit logs (as set forth in §5.5.1 will be retained for a period of at least two (2) years from their record creation timestamp, or as long as they are required to be retained per §5.4.3, whichever is longer.

The CA retains, for at least two (2) years:

1. All archived documentation related to the security of Certificate systems, Certificate management systems, and Root CA systems as set forth in §5.5.1); and
2. All archived documentation relating to the verification, issuance, and revocation of certificate requests and Certificates (as set forth in §5.5.1) after the later occurrence of:
    1. Such records and documentation were last relied upon in the verification, issuance, or revocation of certificate requests and Certificates; or
    2. The expiration of the Subscriber Certificates relying upon such records and documentation.

### 5.5.3 Protection of archive

The databases for CAs and RAs are protected by encryption. The archive media is protected through storage in a restricted-access facility to which only Entrust-authorized personnel have access. Archive files are backed up as they are created. Originals are stored on-site and housed with a CA system. Backup files are stored at a secure and separate geographic location.

### 5.5.4 Archive backup procedures

No stipulation.

### 5.5.5 Requirements for time-stamping of records

No stipulation.

### 5.5.6 Archive collection system (internal or external)

No stipulation.

### 5.5.7 Procedures to obtain and verify archive information

No stipulation.

## 5.6 Key changeover

CAs’ Key Pairs will be retired from service at the end of their respective lifetimes as defined in §6.3. New CA Key Pairs will be created as required to support the continuation of CA Services. Each CA will continue to publish CRLs signed with the original Key Pair until all Certificates issued using that original Key Pair have expired. The CA key changeover process will be performed such that it causes minimal disruption to Subscribers and Relying Parties.

## 5.7 Compromise and disaster recovery

### 5.7.1 Incident and compromise handling procedures

CAs have a security incident response plan, a disaster recovery plan, and a business continuity plan to provide for timely recovery of services in the event of a security incident, breach of security, loss of system integrity, or system outage. They address the following:

1. the conditions for activating the plans;
2. resumption procedures;
3. a maintenance schedule for the plan;
4. awareness and education requirements;
5. the responsibilities of the individuals;
6. recovery point objective (RPO) of fifteen minutes;
7. recovery time objective (RTO) of 24 hours for essential CA operations which include Certificate revocation, and issuance of Certificate revocation status; and
8. testing of recovery plans.

In order to mitigate the event of a disaster, the CAs have implemented the following:

9. secure on-site and off-site storage of backup HSMs containing copies of all CA Private Keys
10. secure on-site and off-site storage of all requisite activation materials
11. regular synchronization of critical data to the disaster recovery site
12. regular incremental and daily backups of critical data within the primary site
13. environmental controls as described in §5.1
14. high availability architecture for critical systems

Entrust has implemented a secure disaster recovery facility that is greater than 250 km from the primary secure CA facilities.

Entrust has policies and procedures that will be employed in the event of such a Compromise. At a minimum, all Subscribers and ASVs shall be informed as soon as practicable of such a Compromise and information shall be posted in the Repository.

### 5.7.2 Computing resources, software, and/or data are corrupted

No stipulation.

### 5.7.3 Entity private key compromise procedures

No stipulation.

### 5.7.4 Business continuity capabilities after a disaster

No stipulation.

## 5.8 CA or RA termination

In the event of CA termination, Entrust will:

1. Provide notice and information about the CA termination by sending notice to Subscribers with unrevoked unexpired Certificates, Application Software Vendors, and Third Party Subordinate CAs and by posting such information in the Repository; and
2. Transfer all responsibilities to a qualified successor entity.

If a qualified successor entity does not exist, Entrust will:

1. Transfer those functions capable of being transferred to a reliable third party and arrange to preserve all relevant records with a reliable third party or a government, regulatory, or legal body with appropriate authority;
2. Revoke all Certificates that are still unrevoked or unexpired on a date as specified in the notice and publish final CRLs;
3. Destroy all CA Private Keys; and
4. Make other necessary arrangements that are in accordance with this CPS.

# 6. TECHNICAL SECURITY CONTROLS

## 6.1 Key pair generation and installation

### 6.1.1 Key pair generation

#### 6.1.1.1 CA Key Pair Generation

The CAs will perform the following when generating a CA Key Pair:

1. Prepare and follow a Key Pair generation script;
2. Have a qualified auditor witness the CA Key Pair generation process;
3. Have a qualified auditor issue a report opining that the CA followed its CA Key Pair generation ceremony during its key generation process and the controls to ensure the integrity and confidentiality of the CA Key Pair;
4. Generate the CA Key Pair in a physically secured environment;
5. Generate the CA Key Pair using personnel in Trusted Roles under the principles of multiple person control and split knowledge;
6. Generate the CA Key Pair within cryptographic modules meeting the applicable requirements of §6.2.11;
7. Log its CA Key Pair generation activities; and
8. Maintain effective controls to provide reasonable assurance that the Private Key was generated and protected in conformance with the procedures described in this CPS and (if applicable) its CA Key Pair generation script.

Key Pair generation ceremony reports are provided to CCADB for new Root CA Certificates which are submitted for inclusion.

#### 6.1.1.2 RA Key Pair Generation

No stipulation.

#### 6.1.1.3 Subscriber Key Pair Generation

The Applicant or Subscriber is required to generate or initiate a new, secure, and cryptographically sound Key Pair to be used in association with the Subscriber’s Certificate or Applicant’s Certificate Application.

The CA will reject a Certificate request if one or more of the following conditions are met:

1. The Key Pair does not meet the requirements set forth in §6.1.5 and/or §6.1.6;
2. There is clear evidence that the specific method used to have generate the Private Key was flawed;
3. The CA is aware of a demonstrated or proven method that exposes the Private Key to compromise;
4. The CA has previously been made aware that the Private Key has suffered a Key Compromise, such as through the provisions of §4.9.1.1;
5. The CA is aware of a demonstrated or proven method to easily compute the Private Key based on the Public Key (such as a Debian weak key, see <https://wiki.debian.org/SSLkeys>).

**OV and EV TLS Certificates**

The CA will not generate a Key Pair on behalf of a Subscriber, and will not accept a Certificate request using a Key Pair previously generated by the CA.

**S/MIME Certificates**

In order to support key backup, the CA may optionally provide a service to generate the Key Pair on behalf of the Applicant or Subscriber. The Key Pair is generated on a cryptographic module that meets or exceeds the requirements as defined in §6.2.11.

**Code Signing, EV Code Signing and Document Signing Certificates**

Subscriber Key Pairs must be generated in a manner that ensures that the Private Key is not known to or accessible by anybody other than the Subject, Subscriber, or a Subscriber’s authorized representative. Subscriber Key Pairs must be generated in a cryptographic module that prevents exportation or duplication and that meets or exceed the requirements as defined in §6.2.11.

**Time-Stamp Certificates**

Subscriber Key Pairs must be generated in a manner that ensures that the Private Key is not known to or accessible by anybody other than the Subscriber or a Subscriber’s authorized representative. Subscriber Key Pairs must be generated in a cryptographic module that prevents exportation or duplication and that meets or exceed the requirements as defined in §6.2.11.

### 6.1.2 Private key delivery to subscriber

CAs do not generate, archive or deliver the Key Pair on behalf of the Subscriber with the following exceptions.

**S/MIME Certificates**

In the case where the Key Pair is generated on behalf of the Subscriber by the CA, the Private Key will be delivered to the Subscriber in a cryptographically secure manner with at least 128-bits encryption strength in a PKCS #12 format.

**Managed and Hosted Cryptographic Module**

In the case a CA managed and hosted cryptographic module is used, the Private Key will be generated, stored and managed on a cryptographic module which meets the requirements as defined in §6.2.11. The CA enforces multi‐factor or secure server-to-server authentication to allow the Subscriber to enroll to generate the Key Pair or to use the Private Key for signing. The Private Key is not delivered to the Subscriber.

### 6.1.3 Public key delivery to certificate issuer

The Public Key to be included in a Certificate is delivered to the CA in a signed Certificate Signing Request (CSR) as part of the Certificate Application process. The signature on the CSR will be verified by the CA prior to issuing the Certificate.

### 6.1.4 CA public key delivery to relying parties

The Public-Key Certificate for CAs are made available to Subscribers and Relying parties through inclusion in third party software as distributed by the applicable software manufacturers. The Public Key Certificate for cross certified Subordinate CAs is provided to the Subscriber with the Subscriber certificate.

Public Key Certificates for CAs are also available for download from the Repository.

### 6.1.5 Key sizes

For RSA Key Pairs the CA will ensure that the modulus size, when encoded, is at least 2048 bits, and that the modulus size, in bits, is evenly divisible by 8.

**CA Key Size**

For CAs using RSA keys, the size is 2048, 3072 or 4096-bits. For CAs using ECC keys, the size is NIST P-384.

As of July 1, 2017, the minimum key size for a Root CA supporting the Adobe Approved Trust List is 3072-bit RSA or ECC NIST P-384.

The minimum key size for new CA Certificates which issue Code Signing and Time-stamping Certificates is 3072-bit RSA and ECC NIST P-384.

**OV and EV TLS Certificates**

The RSA key size is 2048, 3072 or 4096-bits. The ECC key size is NIST P-256 or P-384.

**Client Authentication Certificates**

The RSA key size is 2048, 3072 or 4096-bits. The ECC key size is NIST P-256 or P-384.

**S/MIME Certificates**

The RSA key size is 2048, 3072 or 4096-bits.

**Code Signing and EV Code Signing Certificates**

The RSA key size is 2048, 3072 or 4096-bits. As of June 1, 2021, the minimum key size is RSA 3072 bits. The ECC key size is NIST P-256 or P-384.

**Document Signing Certificates**

The RSA key size is 2048, 3072 or 4096-bits. The ECC key size is NIST P-256 or P-384.

**Time-Stamp Certificates**

The RSA key size is 2048, 3072 or 4096-bits. As of June 1, 2021, the minimum key size is RSA 3072 bits. The ECC key size is NIST P-256 or P-384.

**Verified Mark Certificates**

The RSA key size is 2048, 3072 and 4096-bits. The ECC key size is NIST P-256 and P-384.

### 6.1.6 Public key parameters generation and quality checking

For RSA Public Keys, CAs confirm that the value of the public exponent is an odd number equal to 3 or more. Additionally, the public exponent will be in the range between 2^16 + 1 and 2^256 - 1. The modulus will also have the following characteristics: an odd number, not the power of a prime, and have no factors smaller than 752.

For ECC Public Keys, CAs confirm the validity of all keys using either the ECC Full Public Key Validation Routine or the ECC Partial Public Key Validation Routine.

**S/MIME and Document Signing Certificates**

In the case where the CA has generated the Key Pair on behalf of the Subscriber, the Key Pair is generated in accordance with FIPS 186.

### 6.1.7 Key usage purposes (as per X.509 v3 key usage field)

Root CA Private Keys must not be used to sign Certificates except in the following cases:

1. Self-signed Certificates to represent the Root CA itself;
2. Certificates for Subordinate CAs and Cross Certificates;
3. Certificates for infrastructure purposes (e.g. administrative role certificates, internal CA operational device certificates, and OCSP Response verification Certificates); and
4. Certificates issued solely for the purpose of testing products with Certificates issued by a Root CA.

**Verified Mark Certificates**

Private Keys corresponding to Root CA Certificates will not sign Subordinate CA or Cross Certificates unless the Certificate to be signed contains `id-kp-BrandIndicatorforMessageIdentification` (OID: 1.3.6.1.5.5.7.3.31) as the sole KeyPurposeId in the extendedKeyUsage extension.

Private Keys corresponding to Subordinate CA or Cross Certificates will not sign Certificates unless the Certificate to be signed contains `id-kp-BrandIndicatorforMessageIdentification` (OID: 1.3.6.1.5.5.7.3.31) or `id-kp-OCSPSigning` (OID: 1.3.6.1.5.5.7.3.9) as the sole KeyPurposeId in the extendedKeyUsage extension.

## 6.2 Private Key Protection and Cryptographic Module Engineering Controls

The CAs have implemented physical and logical safeguards to prevent unauthorized Certificate issuance. Protection of the CA Private Key outside the validated system consist of physical security, encryption, or a combination of both, implemented in a manner that prevents disclosure of the CA Private Key. The CA encrypts its Private Key with an algorithm and key-length that are capable of withstanding cryptanalytic attacks for the residual life of the encrypted key.

### 6.2.1 Cryptographic module standards and controls

**CA Private Keys**

CA Private Keys must be stored and protected on cryptographic modules that meet or exceed the requirements as defined in §6.2.11. Private Keys on cryptographic modules are held in secure facilities under two-person control. RA Private Keys must be stored and protected on cryptographic modules that meet or exceed the requirements defined in §6.2.11.

**S/MIME Certificates**

For cases where the CA has generated the Key Pair on behalf of the Subscriber, the CA use cryptographic modules which meet or exceed the requirements as defined in §6.2.11.

**Document Signing Certificates**

Subscribers are responsible for protecting the Private Key associated with the Public Key in the Subscriber’s Certificate. Subscribers must use cryptographic hardware modules that meet or exceed the requirements as defined in §6.2.11.

**Managed and Hosted Cryptographic Module**

In the case a CA managed and hosted cryptographic module is used, the cryptographic modules meets or exceeds the requirements as defined in §6.2.11.

### 6.2.2 Private key (n out of m) multi-person control

A minimum of two-person control is be established on any CA Private Key for all purposes including activation and backup, and may be implemented as a combination of technical and procedural controls. Persons involved in management and use of the CA Private Keys are designated as authorized by the CA for this purpose. The names of the parties used for two-person control are maintained on a controlled list.

### 6.2.3 Private key escrow

Entrust does not escrow Private Keys.

### 6.2.4 Private key backup

**CA Private Keys**

CA Private Keys are backed up under the two-person control used to create the original version of the Private Keys. All copies of the CA Private Key are securely protected.

**S/MIME Certificates**

For cases where the CA has generated the Key Pair on behalf of the Subscriber, the CA securely maintains a backup copy of the Private Key during the term of services.

**Managed and Hosted Cryptographic Module**

In the case a CA managed and hosted cryptographic module is used, the encrypted Private Keys are backed up on a regular basis for disaster recovery purposes.

### 6.2.5 Private key archival

**CA Private Keys**

Upon retirement of a CA, the Private Keys will be archived securely using hardware cryptographic modules that meet the requirements §6.2.11. The Key Pairs are not be used unless the CA has been removed from retirement or the keys are required temporarily to validate historical data. Private Keys required for temporary purposes may be removed from archive for a short period of time.

The archived CA Private Keys will be reviewed on an annual basis. After the minimum period of 5 years, the CA Private Keys may be destroyed according to the requirements in §6.2.10. The CA Private Keys must not be destroyed if they are still required for business or legal purposes.

Third parties will not archive CA Private Keys.

**S/MIME Certificates**

For cases where the CA has generated the Key Pair on behalf of the Subscriber, the CA may securely maintain an archive of the Subscriber Private Key in the secure long-term backups.

**Managed and Hosted Cryptographic Module**

In the case a CA managed and hosted cryptographic module is used, the Private Key is not archived.

### 6.2.6 Private key transfer into or from a cryptographic module

CA Private Keys are generated by and secured in a cryptographic module. In the event that a Private Key is to be transported from one cryptographic module to another, the Private Key must be migrated using the secure methodology supported by the cryptographic module.

If the Private Key of a Subordinate CA is communicated to an unauthorized third party, then the Subordinate CA will revoke all Certificates corresponding to Private Key.

**Managed and Hosted Cryptographic Module**

In the case a CA managed and hosted cryptographic module is used, the Private Key will be encrypted using the AES 256 key wrapping functionality of the cryptographic module and stored in a secure database.

### 6.2.7 Private key storage on cryptographic module

CA Private Keys are stored on a cryptographic module are secured in cryptographic module as defined in §6.2.11.

A TSA will use Time-Stamp Certificates where the Private Keys are generated and stored on a cryptographic module as defined in §6.2.11.

Signing Services will use Subscriber Certificates where the Private Keys are generated and stored on an Entrust managed and hosted cryptographic module as defined in §6.2.11. The Signing Service enforces multi-factor authentication or server-to-server authentication to access and authorize Code Signing.

### 6.2.8 Method of activating private key

**CA Private Keys**

CA Private Keys are activated under two-person control using the methodology provided with the cryptographic module.

**Subscriber Private Keys**

Subscriber Private Keys should be activated by the Subscriber to meet the requirements of the security software used for their applications. Subscribers shall protect their Private Keys corresponding to the requirements in §9.6.3.

**Managed and Hosted Cryptographic Module**

In the case a CA managed and hosted cryptographic module is used, the Private Key activation is performed with the Subject’s authentication. The Subject shall protect access credentials to the Private Key in accordance with §9.6.3.

### 6.2.9 Method of deactivating private key

**CA Private Keys**

CA Private Keys will be deactivated when the CA is not required for active use. Deactivation of the Private Keys is done in accordance with the methodology provided with the cryptographic module.

**Subscriber Private Keys**

Subscriber Private Keys are deemed to be deactivated when the Private Key is no longer needed or all Certificates associated with the Private Key have expired or been revoked.

### 6.2.10 Method of destroying private key

**CA Private Keys**

CA Private Keys destruction will be two-person controlled and may be accomplished by executing a "zeroize" command or by destruction of the cryptographic module. Destruction of CA Private Keys must be authorized by the Policy Authority.

If the CA is removing a cryptographic module from service, then all Private Keys must be removed from the module. If the CA cryptographic module is intended to provide tamper-evident characteristics is removed from service, then the device will be destroyed.

**S/MIME Certificates**

For cases where the CA has generated the Key Pair on behalf of the Subscriber, Private Keys which have been archived will be destroyed in accordance with the backup destruction process.

**Managed and Hosted Cryptographic Module**

The CA may destroy the Private Key when the Certificate has expired or when the subscription to the service has terminated.

### 6.2.11 Cryptographic Module Rating

**CA Key Pairs**

CA Key Pairs must be generated and protected on a cryptographic module that is compliant to at least FIPS 140-2 Level 3, FIPS 140-3 Level 3, or an appropriate Common Criteria Protection Profile or Security Target, EAL 4 (or higher), which includes requirements to protect the Private Key and other assets against known threats.

**S/MIME Certificates**

For cases where the CA has generated the Key Pair on behalf of the Subscriber, the CA uses cryptographic modules which meet FIPS 140-2 Level 1 certification standards.

**Code Signing and EV Code Signing Certificates**

Subscriber Private Keys must be protected per the following requirements. The CA will obtain a contractual representation from the Subscriber that the Subscriber will use one of the following options to generate and protect their Private Keys in a cryptographic module with a unit design form factor certified as conforming to at least FIPS 140‐2 Level 2, FIPS 140-3 Level 2, or Common Criteria EAL 4+:

1. Subscriber uses a cryptographic module meeting the specified requirement;
2. Subscriber uses a cloud‐base key generation and protection solution with the following requirements: a. Key creation, storage, and usage of Private Key must remain within the security boundaries of the cloud solution’s cryptographic module that conforms to the specified requirements; b. Subscription at the level that manages the Private Key must be configured to log all access, operations, and configuration changes on the resources securing the Private Key.
3. Subscriber uses a Signing Service which meets the requirements of Code Signing Baseline Requirements section 6.2.7.3.

**Document Signing Certificates**

Subscriber Key Pairs must be generated and protected in a cryptographic module that meets or exceed FIPS 140-2 Level 2, FIPS 140-3 Level 2, or Common Criteria EAL 4+ certification standards.

**Time-Stamp Certificates**

Subscriber Key Pairs must be generated and protected in a cryptographic module that meets or exceed FIPS 140-2 Level 3, FIPS 140-3 Level 3, or Common Criteria EAL 4+ certification standards.

**Managed and Hosted Cryptographic Module**

In the case a CA managed and hosted cryptographic module is used, the Key Pairs will be generated and protected in a cryptographic module that meets FIPS 140-2 Level 3, FIPS 140-3 Level 3, or Common Criteria EAL 4+ certification standards.

## 6.3 Other aspects of key pair management

### 6.3.1 Public key archival

No stipulation.

### 6.3.2 Certificate operational periods and key pair usage periods

**CA Key Pairs**

CA 2048-bit RSA Key Pairs may have a validity period expiring no later than 31 December 2030.

Root CA Certificates may have a validity period of up to, but no more than 9132-days (~25-years).

**OV and EV TLS Certificates**

OV and EV TLS Certificates may have a validity period of up to, but no more than, 398-days.

**Client Authentication Certificates**

Client Authentication Certificates may have a validity period of up to, but no more than, 398-days.

**S/MIME Certificates**

S/MIME Certificates may have a validity period of up to, but no more than, 39 months. S/MIME Certificates issued on or after 1 April 2022 may have a validity period of up to, but no more than, 1185-days.

**Code Signing and EV Code Signing Certificates**

Code Signing Certificates may have a validity period of up to, but no more than, 39 months.

**Document Signing Certificates**

Document Signing Certificates may have a validity period of up to, but no more than, 39 months.

**Time-Stamp Certificates**

Time-Stamp Certificates may have a validity period of up to, but no more than 135 months. Private Key usage period is no greater than 15 months.

**Verified Mark Certificates**

Verified Mark Certificates may have a validity period of up to, but no more than, 398-days. If the Applicant is a licensee of a Registered Mark rather than the Registrant, the expiration date of the certificate will have an expiration date that is no later than the final expiration date of the license held by the Applicant to use the Registered Mark.

## 6.4 Activation data

### 6.4.1 Activation data generation and installation

No stipulation.

### 6.4.2 Activation data protection

No stipulation.

### 6.4.3 Other aspects of activation data

No stipulation.

## 6.5 Computer security controls

### 6.5.1 Specific computer security technical requirements

The workstations on which the CAs operate are physically secured as described in §5.1. The operating systems on the workstations on which the CAs operate enforce identification and authentication of users. Access to CA software databases and audit trails is restricted as described in this CPS. All operational personnel that are authorized to have access to the CAs are required to use hardware tokens in conjunction with a PIN to gain access to the physical room that contains the CA software being used for such CAs.

The CA enforces multi‐factor authentication for all RA and Enterprise RA accounts capable of directly causing Subscriber Certificate issuance.

For Subscriber accounts, the CA has implemented technical controls to restrict Certificate issuance to a limited set of pre-approved domains.

### 6.5.2 Computer security rating

No stipulation.

## 6.6 Life cycle technical controls

### 6.6.1 System development controls

Systems developed by the CA are deployed in accordance with Entrust software lifecycle development standards.

### 6.6.2 Security management controls

The configuration of the CA system as well as any modifications and upgrades are documented and controlled. Methods of detecting unauthorized modifications to the CA equipment and configuration are in place to ensure the integrity of the security software, firmware, and hardware for correct operation. A formal configuration management methodology is used for installation and ongoing maintenance of the CA system.

When first loaded, the CA software is verified as being that supplied from the vendor, with no modifications, and be the version intended for use.

### 6.6.3 Life cycle security controls

In the case a CA managed and hosted cryptographic module is used, the Subject of the Certificate controls the life cycle of the Key Pair. The Subject may destroy the Private Key in accordance with §6.2.10.

## 6.7 Network security controls

The CA has implemented security controls to comply with the CA/Browser Forum’s Network and Certificate System Security Requirements.

## 6.8 Time-stamping

Entrust provides a TSA service, which is operated in accordance with the Time-Stamp Authority Practice Statement.

Code Signing, EV Code Signing and Document Signing Certificates

Subscribers of Code Signing, EV Code Signing or Document Signing Certificates are recommended to time-stamp digital signatures when signing code or data.

# 7. CERTIFICATE, CRL, AND OCSP PROFILES

## 7.1 Certificate profile

CAs issue Certificates in accordance with the X.509 version 3. Certificate profiles for Root CA Certificate, Subordinate CA Certificates, and Subscriber Certificates are described in Appendix A and the sections below.

Certificates have a serial number greater than zero (0) that contains at least 64 unpredictable bits.

Subscriber Certificates are issued from dedicated Subordinate CAs based on the policy identifiers listed in §7.1.6.4.

### 7.1.1 Version number(s)

All Certificates issued by the CAs are X.509 version 3 certificates.

### 7.1.2 Certificate extensions

All TLS, Code Signing, S/MIME and Time-stamp Certificates are issued in accordance with profiles specified in the Baseline Requirements, Code Signing Baseline Requirements or S/MIME Baseline Requirements as applicable.

CAs will not include extensions or values unless the CA is aware of a reason for including the data in the Certificate.

#### 7.1.2.1 Root CA Certificate

Certificate extensions are as set as stipulated in IETF RFC 5280 and in accordance with Appendix A.

If the Root CA will sign OCSP responses, then the digitalSignature key usage will be set in the Root CA Certificate.

#### 7.1.2.2 Subordinate CA Certificate

Certificate extensions are as set as stipulated in IETF RFC 5280 and in accordance with Appendix A.

If the Subordinate CA will sign OCSP responses, then the digitalSignature key usage will be set in the Subordinate CA Certificate.

The extension requirements for extended key usage are:

1. Must contain an EKU extension,
2. Must not include the anyExtendedKeyUsage EKU,
3. Must not include either `id-kp-serverAuth`, `id-kp-emailProtection`, `id-kp-codeSigning` or `id-kp-timeStamping` EKUs in the same Certificate, and
4. Must not include additional key usage purposes unless the CA is aware of a reason for including the key usage purpose in the Certificate.

**OV TLS, EV TLS, Code Signing, EV Code Signing and S/MIME Certificates**

Cross-certificates issued to support OV TLS, EV TLS, Code Signing, EV Code Signing or S/MIME Certificates will only be issued to a CA which meets the Baseline Requirements, S/MIME Baseline Requirements, or Code Signing Baseline Requirements, as applicable. The Cross-certificate subject name will be byte-for-byte identical to the encoded subject name of the existing CA Certificate.

#### 7.1.2.3 Subscriber Certificate

Certificate extensions are as set as stipulated in IETF RFC 5280 and in accordance with Appendix A.

Subscriber Certificates contain the HTTP URL of the CA’s OCSP response in the accessMethod extension.

**Verified Mark Certificate**

Logotype Extension (OID: 1.3.6.1.5.5.7.1.12) contains the `subjectLogo` with a `LogotypeData` element (RFC 3709) containing the Mark Representation asserted by the Subject of the Verified Mark Certificate. The Mark Representation must be an embedded secured SVG image (RFC 6170). More specifically the extension must embed the image element in `data:` URL as defined in RFC 6170 Section 4. Further, to secure the SVG, it must use the SVG tiny profile (W3C Recommendation, "Scalable Vector Graphics (SVG) Tiny 1.2 Specification", December 2008), must not contain &lt;script&gt; tags, must be compressed, and must follow other requirements set forth in RFC 6170 Section 5.2.

#### 7.1.2.4 All Certificates

Except as indicated in this CPS, all other fields and extensions are set in accordance with RFC 5280.

#### 7.1.2.5 Application of RFC 5280

For purposes of clarification, a precertificate, as described in RFC 6962 (Certificate Transparency), is not be considered to be a "certificate" subject to the requirements of RFC 5280.

### 7.1.3 Algorithm object identifiers

#### 7.1.3.1 SubjectPublicKeyInfo

For RSA, the CA will indicate an RSA key using the rsaEncryption (OID: 1.2.840.113549.1.1.1) algorithm identifier. The parameters must be present and must be explicit `NULL`.

For ECDSA, the CA must indicate an ECDSA key using the `id-ecPublicKey` (OID: 1.2.840.10045.2.1) algorithm identifier. The parameters must use the namedCurve encoding:

1. For P-256 keys, the namedCurve must be secp256r1 (OID: 1.2.840.10045.3.1.7), or
2. For P-384 keys, the namedCurve must be secp384r1 (OID: 1.3.132.0.34).

#### 7.1.3.2 Signature AlgorithmIdentifier

All objects signed by a CA Private Key must conform to these requirements on the use of the AlgorithmIdentifier or AlgorithmIdentifier-derived type in the context of signatures.

For RSA, the CA must use one of the following signature algorithms and encodings.

1. RSASSA-PKCS1-v1_5 with SHA-256
2. RSASSA-PKCS1-v1_5 with SHA-384
3. RSASSA-PKCS1-v1_5 with SHA-512

For ECDSA, the CA must use the appropriate signature algorithm and encoding based upon the signing key used.

1. If the signing key is P-256, the signature MUST use ECDSA with SHA-256.
2. If the signing key is P-384, the signature MUST use ECDSA with SHA-384.
3. If the signing key is P-521, the signature MUST use ECDSA with SHA-512.

### 7.1.4 Name forms

#### 7.1.4.1 Name Encoding

For every valid Certification Path (as defined by RFC 5280, Section 6) for all Certificate and Subordinate CA Certificate, the following must be met:

1. For each Certificate in the Certification Path, the encoded content of the issuer distinguished name field of a Certificate shall be byte-for-byte identical with the encoded form of the Subject distinguished name field of the issuing CA certificate.
2. For each CA Certificate in the Certification Path, the encoded content of the Subject distinguished name field of a Certificate shall be byte-for-byte identical among all Certificates whose Subject distinguished names can be compared as equal according to RFC 5280, Section 7.1, and including expired and revoked Certificates

#### 7.1.4.2 Subject Information - Subscriber Certificates

Subject information must meet the requirements stated in Appendix A.

Name forms for Subscriber Certificates are as stipulated in §3.1.1. All other optional attributes must contain information that has been verified by the CA or RA. Optional attributes will not contain only metadata such as ‘.’, ‘‐‘, and ‘ ‘ (i.e. space) characters, and/or any other indication that the value is absent, incomplete, or not applicable.

Entries in the `dNSName` are in the "preferred name syntax" as specified in IETF RFC 5280 and thus do not contain underscore characters.

**OV TLS, EV TLS, Client Authentication and Verified Mark Certificates**

CAs do not issue a Certificate with a Domain Name containing a Reserved IP Address or Internal Name.

#### 7.1.4.3 Subscriber Certificate Common Name Attribute

Common Name will contain only one entry.

**OV TLS, EV TLS and Client Authentication Certificates**

Common Name value will also be contained in the `subjectAltName`.

#### 7.1.4.4 Other Subject Attributes

Subject information must meet the requirements stated in Appendix A.

### 7.1.5 Name constraints

Technically Constrained Subordinate CA Certificates are issued with an extended key usage extension. The extension will not include the `anyExtendedKeyUsage` key usage purpose. The extension will include one of, but will not combine the following key usage purposes: `serverAuth`, `codesigning`, `emailProtection` and `timeStamping`.

To support enterprise usage, if a Technically Constrained Subordinate CA Certificate includes the `emailProtection` key usage purpose, then the Certificate may also include the following key usage purposes: Client Authentication (1.3.6.1.5.5.7.3.2), Smart Card Logon (1.3.6.1.4.1.311.20.2.2), Encrypting File System (1.3.6.1.4.1.311.10.3.4), File Recovery (1.3.6.1.4.1.311.10.3.4.1), and BitLocker Drive Encryption (1.3.6.1.4.1.311.67.1.1).

The Technically Constrained Subordinate CA Certificate will be restricted to only permit values in accordance with the included extended key usages and policies.

If the Technically Constrained Subordinate CA Certificate includes the `serverAuth` key usage purpose, the `nameConstraints` extension will include `dNSName`, `iPAddress`, `directoryName` and `otherName:SRVName` (1.3.6.1.5.5.7.8.7 as defined in rfc4985) as described in section 7.1.5 of the Baseline Requirements.

If the Technically Constrained Subordinate CA Certificate includes the `emailProtection` key usage purpose, the nameConstraints extension will include `rfc882Name` and `directoryName` as described in section 7.1.5 of the S/MIME Requirements. The extension may include additional constraints.

### 7.1.6 Certificate policy object identifier

#### 7.1.6.1 Root CA Certificates

Root CA Certificates do not contain the certificate policy object identifiers.

#### 7.1.6.2 Subordinate CA Certificates

**Subordinate CA**

Subordinate CA Certificates may include either the "any policy" certificate policy object identifier or one or more explicit certificate policy object identifiers that indicates compliance with a specific certificate policy.

**Third Party Subordinate CA**

Subordinate CA Certificates issued to a Third Party Subordinate CA may include one or more explicit certificate policy object identifiers that indicates the Third Party Subordinate CA’s adherence to and compliance with the requirements documented in its CP and/or CPS. For Third Party Subordinate CAs which issue TLS Certificates, these requirements must include adherence and compliance to the Baseline Requirements.

#### 7.1.6.3 Subscriber Certificates

Subscriber Certificates may (or must, if required by an applicable third party requirement specified in §1.1) include one or more of the following Certificate policy identifiers, if the CA is asserting the Certificate meets the associated certificate policy:

**CA/Browser Forum Requirements:**

- OV TLS Certificates **2.23.140.1.2.2**
- EV TLS Certificates **2.23.140.1.1**
- Code Signing Certificates **2.23.140.1.4.1**
- EV Code Signing Certificates **2.23.140.1.3**
- Time-Stamp Certificates (CSBR) **2.23.140.1.4.2**
- S/MIME Mailbox-validated Strict **2.23.140.1.5.1.3**
- S/MIME Sponsor-validated Legacy **2.23.140.1.5.3.1**
- S/MIME Sponsor-validated Strict **2.23.140.1.5.3.3**

**Verified Marked Certificate Requirements:**

- Verified Mark Certificates **1.3.6.1.4.1.53087.1.1**

**Entrust Certificate Policies:**

- EV TLS Certificates **2.16.840.1.114028.10.1.2**
- Client Authentication Certificates **2.16.840.1.114028.10.1.5.1; or 2.16.840.1.114028.10.1.5.2**
- Document Signing Certificates **2.16.840.1.114028.10.1.6**
- Time-Stamp Certificates **2.16.840.1.114028.10.3.5**
- Verified Mark Certificates **2.16.840.1.114028.10.1.11**

### 7.1.7 Usage of Policy Constraints extension

No stipulation.

### 7.1.8 Policy qualifiers syntax and semantics

As stipulated in Appendix A.

### 7.1.9 Processing semantics for the critical Certificate Policies extension

Certificate policies extension is marked Not Critical.

### 7.1.10 PreCertificate Profile

A Precertificate (RFC 6962) appears structurally identical to a Certificate, with the exception of a special critical poison extension in the extensions field, with the OID of 1.3.6.1.4.1.11129.2.4.3.

## 7.2 CRL profile

The following fields of the X.509 version 2 CRL format are used by the CAs:

1. version: set to v2
2. signature: identifier of the algorithm used to sign the CRL
3. issuer: the byte-for-byte equivalent of the Distinguished Name of the CA issuing the CRL
4. this update: time of CRL issuance
5. next update: time of next expected CRL update
6. revoked Certificates: list of revoked Certificate information

**Code Signing and EV Code Signing Certificates**

CA may allow the CRL date and time of revocation to be backdated to convey the invalidity date in the event of Private Key Compromise or prior to date of signature on Suspect Code.

### 7.2.1 Version number(s)

CRLs issued by the CAs are X.509 version 2.

### 7.2.2 CRL and CRL entry extensions

**reasonCode (OID 2.5.29.21)**

The CRLReason code extension may be used for revoked Certificates and will not be marked critical. The CRLReason indicated must not be unspecified (0) and if reasonCode unspecified (0) is used, the CA will omit the reasonCode entry in the CRL.

This extension must not be marked critical. The most appropriate reason must be selected by the Subscriber or the CA from one the following:

1. `keyCompromise` (1), if the key to the certificate has been or is suspected to be compromised or has signed Suspect Code;
2. `cACompromise` (2), if the CA has been or is suspected to be compromised;
3. `affiliationChanged` (3), if verified information in the Certificate has changed and as such the Relying Parties should no longer trust the Certificate;
4. `superseded` (4), if the Certificate has been reissued, rekeyed or renewed by another Certificate, the CA has evidence the validation of domain or IP address should not be relied upon or the Certificate was not issued in accordance with the requirements of §1.1 or this CPS;
5. `cessationOfOperation` (5), if the website or device is no longer in service or the Subscriber no longer controls the Domain Name or IP address; or
6. `privilegeWithdrawn` (9), if the CA determines the privilege of the Certificate issued the Subscriber no longer exists.

The default revocation reason is unspecified (0) which results in no reasonCode being provided in the CRL. The CA will not use reasonCode `certificateHold` (6). The `priviledgeWithdrawn` (9) reasonCode is not made available to the Subscriber.

If the CA obtains evidence of Key Compromise or the Private Key has signed Suspect Code for a Certificate whose CRL entry does not contain a reasonCode extension or has a reasonCode extension with a non-keyCompromise (1) reason, the CA may update the CRL reasonCode to `keyCompromise` (1).

If a Certificate previously has been revoked, and the CA later becomes aware of a more appropriate revocation date, then the CA may use that revocation date in subsequent CRL entries for that Certificate. A more appropriate revocation date may be the date of Compromise or a date prior to the signature on Suspect Code.

#### 7.2.2.1 CRL Issuing Distribution Point

The CRLs do not support the Issuing Distribution Point extension.

## 7.3 OCSP profile

The profile for the Online Certificate Status Protocol (OCSP) messages issued by a CA conform to the specifications contained in the IETF RFC 6960 Internet X.509 PKI Online Certificate Status Protocol (OCSP) Profile.

If an OCSP responder is used, then the issuing CA of the responder will be the same as the issuing CA for the Certificates it provides responses for. The OCSP responder Certificate will not be a CA Certificate.

If an OCSP response is for a Root CA or Subordinate CA Certificate, including Cross Certificates, and that certificate has been revoked, then the `revocationReason` field within the `RevokedInfo` of the CertStatus will be present.

The CRLReason indicated contains a value permitted for CRLs, as specified in §7.2.2.

### 7.3.1 Version number(s)

No stipulation.

### 7.3.2 OCSP extensions

The `singleExtensions` of an OCSP response does not contain the `reasonCode` (OID 2.5.29.21) CRL entry extension.

The OCSP responder Certificate:

1. Does not include `AuthorityInformationAccesssSyntax` extension;
2. Includes the `id-pkix-ocsp-nocheck` extension (OID: 1.3.6.1.5.5.7.48.1.5);
3. Is not a CA Certificate, so the `basicConstraints` extension for the cA boolean is set to `FALSE`; and
4. The is no `certificatePolicy` extension.

# 8. COMPLIANCE AUDIT AND OTHER ASSESSMENTS

The CA complies to the requirements stated in §1.1, which includes the Baseline Requirements, EV SSL Guidelines, Code Signing Baseline Requirements, S/MIME Baseline Requirements, and VMC Requirements.

The CA complies to compliance audit requirements of this section.

The CA is licensed if applicable to each jurisdiction where it issues Certificates.

## 8.1 Frequency or circumstances of assessment

Root and Subordinate Private Keys and CA are audited continually from key generation until the CA is no longer trusted from CA Certificate expiry or revocation.

CAs with unconstrained Certificates are audited for compliance with the practices and procedures set forth in the CPS in which the CA operates. The period during which the CA issues Certificates will be divided into an unbroken sequence of audit periods. An audit period will not exceed one year in duration.

CAs with Technically Constrained Subordinate CA Certificates will be audited for compliance with the practices and procedures set forth in the CPS in which the CA operates.

A CA implementation will no longer need to be audited, if all CA Certificates for the CA have expired or have been revoked before commencement of the audit period.

## 8.2 Identity/qualifications of assessor

The compliance audit of the CAs is performed by an auditor which possesses the following qualifications and skills:

1. Independence from the subject of the audit;
2. Ability to conduct an audit that addresses the criteria of the audit schemes specified in §8.4;
3. Employs individuals who have proficiency in examining PKI technology, information security tools and techniques, information technology and security auditing, and the third-party attestation function;
4. Licensed by WebTrust;
5. Bound by law, government regulation, or professional code of ethics; and
6. Maintains professional liability/errors and omissions insurance policy limits of at least one million US dollars coverage.

## 8.3 Assessor's relationship to assessed entity

The certified public accounting firm selected to perform the compliance audit for the CAs and RAs will be independent from the entity being audited.

## 8.4 Topics covered by assessment

The compliance audit will test compliance of the CAs and RAs against the policies and procedures set forth, as applicable in:

1. This CPS;
2. WebTrust for Certification Authorities;
3. WebTrust for Network Security;
4. WebTrust for Baseline Requirements;
5. WebTrust for Extended Validation SSL;
6. WebTrust for Code Signing Baseline Requirements;
7. WebTrust for S/MIME Baseline Requirements; and
8. WebTrust for Verified Mark Certificates.

## 8.5 Actions taken as a result of deficiency

Upon receipt of a compliance audit that identifies any incidents, the audited CA or RA will report the incident to the ASVs.

## 8.6 Communication of results

The audit report will state it covers the relevant systems and processes used in the issuance of all Certificates that assert one or more of the policy identifiers listed in §7.1.6.1.

The results of all compliance audits will be communicated to the Policy Authority and to any third party entities which are entitled by law or regulation to receive a copy of the audit results.

The results of the most recent compliance audit will be posted within three months from the end of the audit period to the Repository and, if applicable to the CCADB. In the event of a delay greater than three months, the CA will provide an explanatory letter signed by the qualified auditor.

The audit report will contain at least the following information:

1. name of the organization being audited;
2. name and address of the organization performing the audit;
3. the SHA-256 fingerprint of all Roots and Subordinate CA Certificates, including Cross Certificates, that were in-scope of the audit, where the fingerprint uses uppercase letters and does not contain colons, spaces or line feeds;
4. audit criteria, with version number(s), that were used to audit each of the certificates (and associated keys);
5. a list of the CA policy documents, with version numbers, referenced during the audit;
6. whether the audit assessed a period of time or a point in time;
7. the start date and end date of the Audit Period, for those that cover a period of time;
8. the point in time date, for those that are for a point in time;
9. the date the report was issued, which will necessarily be after the end date or point in time date;
10. all incidents disclosed by the CA, or reported by a third party, and all findings reported by a qualified auditor, that, at any time during the audit period, occurred, were open in Bugzilla, or were reported to a store; and
11. an explicit statement indicating the audit covers the relevant systems and processes used in the issuance of all Certificates that assert one or more of the policy identifiers in §7.1.6.1.

The authoritative version of the audit report must be English language, available as a PDF and text searchable for all required information.

## 8.7 Self-Audits

All Subscriber Certificates are self-audited using post-issuance linting software to monitor adherence to the applicable items of this CPS, limited to the linter coverage.

**OV and EV TLS Certificates**

OV and EV TLS Certificates are self-audited using linting software to monitor adherences to this CPS, the Baseline Requirements and the EV SSL Guidelines, limited to the linter coverage.

**Technically Constrained Subordinate CA Certificates**

Entrust will monitor CAs which have been issued a Technically Constrained Subordinate CA Certificate to ensure adherence to the Subordinate CA’s CPS. In addition, Entrust will review a randomly selected sample of at least three percent of the Certificates issued by the Subordinate CA on a quarterly basis.

# 9. OTHER BUSINESS AND LEGAL MATTERS

## 9.1 Fees

Unless otherwise set out in a Subscriber Agreement, the fees for services provided by Entrust with respect to Certificates are set forth on the websites (including e-commerce sites)operated by Entrust. Unless otherwise set out in a Subscriber Agreement, these fees are subject to change, and any such changes shall become effective immediately after posting on such websites (including e-commerce sites). The fees for services provided by independent third-party RAs, Resellers and Co-marketers in respect to Certificates are set forth on the websites operated by such RAs, Resellers and Co-marketers. These fees are subject to change, and any such changes shall become effective immediately after posting on such websites.

### 9.1.1 Certificate issuance or renewal fees

No stipulation.

### 9.1.2 Certificate access fees

No stipulation.

### 9.1.3 Revocation or status information access fees

No stipulation.

### 9.1.4 Fees for other services

No stipulation.

### 9.1.5 Refund policy

Except for a formal written Entrust refund policy, if any, neither Entrust nor any RAs operating under the CAs provide any refunds for Certificates or services provided in respect to Certificates.

## 9.2 Financial responsibility

Subscribers and Relying Parties shall be responsible for the financial consequences to such Subscribers, Relying Parties, and to any other persons, entities, or organizations for any transactions in which such Subscribers or Relying Parties participate and which use Certificates or any services provided in respect to Certificates.

### 9.2.1 Insurance coverage

Entrust maintains (a) Commercial General Liability insurance with policy limits of at least two million US dollars (US$2,000,000.00) in coverage; and (b) Professional Liability/Errors and Omissions insurance, with policy limits of at least five million US dollars (US$5,000,000.00) in coverage. Such insurance policies will be carried with companies rated no less than A- as to Policy Holder’s Rating in the current edition of Best’s Insurance Guide.

### 9.2.2 Other assets

No stipulation.

### 9.2.3 Insurance or warranty coverage for end-entities

No stipulation.

## 9.3 Confidentiality of business information

### 9.3.1 Scope of confidential information

The following information is considered confidential information of Entrust and is protected against disclosure using a reasonable degree of care:

- Private Keys;
- Activation data used to access Private Keys or to gain access to the CA system;
- Business continuity, incident response, contingency, and disaster recovery plans;
- Other security practices used to protect the confidentiality, integrity, or availability of information;
- Information held by Entrust as private information in accordance with 9.4;
- Audit logs and archive records; and
- Transaction records, financial audit records, and external or internal audit trail records and any audit reports (with the exception of an auditor’s letter confirming the effectiveness of the controls set forth in this CPS).

### 9.3.2 Information not within the scope of confidential information

Information that is included in a Certificate or a Certificate Revocation List are considered public.

### 9.3.3 Responsibility to protect confidential information

Entrust’s employees, agents, and contractors are responsible for protecting confidential information and are contractually obligated to do so. Entrust systems are configured to protect confidential information.

## 9.4 Privacy of personal information

### 9.4.1 Privacy plan

Entrust follows the policies, statements and practices available at <https://www.entrust.com/legal-compliance/privacy> ("Privacy Plan") when handling personal information.

### 9.4.2 Information treated as private

Entrust treats all personal information about an individual that is not publicly available in the contents of a Certificate, CRL or OCSP as personal information in accordance with the Privacy Plan.

### 9.4.3 Information not deemed private

Subject to applicable law, Certificates, CRLs, and OCSP and the personal or corporate information appearing in them are not considered personal or private information.

### 9.4.4 Responsibility to protect private information

Entrust personnel are required to protect personal information in accordance with the Privacy Plan.

### 9.4.5 Notice and consent to use private information

Unless otherwise stated in the CPS, Privacy Plan or other agreement (such as a Subscriber Agreement or Relying Party Agreement), personal information will not be used without the consent of the subject of such personal information. Notwithstanding the foregoing, personal information contained in a Certificate may be published in online public repositories and all Subscribers consent to the global transfer of any personal data contained in the Certificate.

### 9.4.6 Disclosure pursuant to judicial or administrative process

Entrust, independent third-party RAs under a CA, Resellers, and Co-marketers shall have the right to release information that is considered to be personal or confidential to law enforcement officials in compliance with applicable law.

Entrust, independent third-party RAs under a CA, Resellers, and Co-marketers may disclose information that is considered confidential during the course of any arbitration, litigation, or any other legal, judicial, or administrative proceeding relating to such information. Any such disclosures shall be permissible provided that Entrust, the independent third-party RA, Reseller, or Co-marketer uses commercially reasonable efforts to obtain a court-entered protective order restricting the use and disclosure of any such information to the extent reasonably required for the purposes of such arbitration, litigation, or any other legal, judicial, or administrative proceeding.

### 9.4.7 Other information disclosure circumstances

Entrust, independent third-party RAs under a CA, Resellers, and Co-marketers may disclose information provided to Entrust, such RA, Reseller or Co-marketer, by an Applicant, a Subscriber, or a Relying Party upon request of such Applicant, Subscriber, or Relying Party.

If a Certificate is revoked by a CA, the Certificate status will be provided by the CRL and OCSP response.

## 9.5 Intellectual property rights

Entrust retains all right, title, and interest (including all intellectual property rights), in, to and under the CPS and all Certificates, except for any information that is supplied by an Applicant or a Subscriber and that is included in a Certificate, which information shall remain the property of the Applicant or Subscriber. Subject to availability, Entrust may in its discretion make copies of one or more Subordinate CA Certificate(s) available to Subscribers for use solely with the Certificate issued to such Subscribers. Entrust retains all right, title, and interest (including all intellectual property rights), in, to and under the Subordinate CA Certificate(s). Except as expressly set forth herein in Subscriber Agreement no right is or shall be deemed to be granted, whether by implication, estoppel, inference or otherwise.

## 9.6 Representations and warranties

### 9.6.1 CA representations and warranties

Entrust makes the following limited warranties with respect to the operation of the CAs. A CA shall:

1. provide CA services in accordance with the CPS;
2. upon receipt of a request from an RA operating under such CA, issue a Certificate in accordance with the practices and procedures set forth in the CPS;
3. make available Certificate revocation information by issuing Certificates and by issuing and making available Certificate CRLs and OCSP responses in a Repository in accordance with the CPS;
4. issue and publish Certificate CRLs and OCSP responses on a regular schedule in accordance with the CPS;
5. provide revocation services consistent with the procedures set forth in the CPS; and
6. provide Repository services consistent with the practices and procedures set forth in the CPS.

In operating the CAs, Entrust may use one or more representatives or agents to perform its obligations under the CPS, any Subscriber Agreements, or any Relying Party Agreements, provided that Entrust shall remain responsible for its performance.

If Entrust appoints any Third Party Subordinate CAs then, _as between themselves, Entrust and the Third Party Subordinate CA’s responsibilities and liabilities will be as mutually agreed in writing between them.  However, as between Entrust and any other party_, Entrust will be responsible for the performance and warranties of the Third Party Subordinate CA, for the Third Party Subordinate CA’s compliance with these practices, and for all liabilities and indemnification obligations of the Third Party Subordinate CA under these practices, as if the Entrust were the Subordinate CA issuing the Certificates.

In no event does the Entrust Group make any representations, or provide any warranties, or conditions to any Applicants, Subscribers, Relying Parties, or any other persons, entities, or organizations with respect to (i) the techniques used by any party other than Entrust in the generation and storage of the Private Key corresponding to the Public Key in a Certificate, including, whether such Private Key has been Compromised or was generated using sound cryptographic techniques, (ii) the reliability of any cryptographic techniques or methods used in conducting any act, transaction, or process involving or utilizing a Certificate, or (iii) non-repudiation of any Certificate or any transaction facilitated through the use of a Certificate, since such determination is a matter of applicable law.

### 9.6.2 RA representations and warranties

RAs operating under a CA shall:

1. receive Certificate Applications in accordance with the CPS;
2. perform, log and secure verification of information submitted by Applicants when applying for Certificates, and if such verification is successful, submit a request to a CA for the issuance of a Certificate, all in accordance with the CPS;
3. receive and verify requests from Subscribers for the revocation of Certificates, and if the verification of a revocation request is successful, submit a request to a CA for the revocation of such Certificate, all in accordance with the CPS;
4. notify Subscribers, in accordance with the CPS, that a Certificate has been issued to them; and
5. notify Subscribers, in accordance with the CPS that a Certificate issued to them has been revoked or will soon expire.

Entrust may use one or more representatives or agents to perform its obligations in respect of an Entrust RA under the CPS, any Subscriber Agreements, or any Relying Party Agreements, provided that Entrust shall remain responsible for the performance of such representatives or agents under the CPS, any Subscriber Agreements, or any Relying Party Agreements. Entrust may appoint independent third parties to act as RAs under a CA. Such independent third-party RAs shall be responsible for their performance under the CPS, any Subscriber Agreements, or any Relying Party Agreements. Entrust shall not be responsible for the performance of such independent third-party RAs. Independent third-party RAs may use one or more representatives or agents to perform their obligations when acting as an RA under a CA. Independent third-party RAs shall remain responsible for the performance of such representatives or agents under the CPS, any Subscriber Agreements, or any Relying Party Agreements. Entrust may appoint Resellers and Co-marketers for (i) Certificates, and (ii) services provided in respect to Certificates. Such Resellers and Co-marketers shall be responsible for their performance under the CPS, any Subscriber Agreements, or any Relying Party Agreements. Entrust shall not be responsible for the performance of any such Resellers and Co-marketers. Resellers and Co-marketers may use one or more representatives or agents to perform their obligations under the CPS, any Subscriber Agreements, or any Relying Party Agreements. Resellers and Co-marketers shall remain responsible for the performance of such representatives or agents under the CPS, any Subscriber Agreements, or any Relying Party Agreements. Independent third-party RAs, Resellers, and Co-marketers shall be entitled to receive all of the benefit of all (i) disclaimers of representations, warranties, and conditions, (ii) limitations of liability, (iii) representations and warranties from Applicants, Subscribers, and Relying Parties, and (iv) indemnities from Applicants, Subscribers, and Relying Parties, set forth in this CPS, any Subscriber Agreements, and any Relying Party Agreements.

### 9.6.3 Subscriber representations and warranties

As a condition of having any Certificate issued to or for Subscriber, each Subscriber (in this section, "Subscriber" includes "Applicant" when referring to any time prior to issuance of the Certificate) makes, on its own behalf and if applicable on behalf of its principal or agent under a subcontractor or hosting service relationship, the following representations, commitments, affirmations and warranties for the benefit of Certificate Beneficiaries, Entrust and any of Entrust’s Affiliates that will issue Certificates to or for Subscriber:

**9.6.3.1 For all Certificates:**

1. If Subscriber is applying for a Certificate to be issued to or for another Person, such Person has authorized Subscriber to act on its behalf, including to request Certificates on behalf of such Person, and to make the representations, commitments, affirmations and warranties in this §9.6.3 on behalf of such Person as well as on Subscriber’s own behalf.
2. All information provided, and all representations made, at all times, by Subscriber in relation to any Certificate Services, including in the Certificate request and otherwise in connection with Certificate issuance, are and will be complete, correct and accurate, including that any legal entity Subject legally exists as a valid entity in the jurisdiction of incorporation or registration specified in the Certificate (and such information and representations will be promptly updated from time to time as necessary to maintain such completeness, correctness and accuracy), and does not infringe, misappropriate, dilute, unfairly compete with, or otherwise violate the intellectual property, or other rights of any person, entity, or organization in any jurisdiction. For clarity, in submitting any request for a Certificate using pre-qualified information, a Subscriber is deemed to be making anew the representations, commitments, affirmations and warranties set out in this §9.6.3, and Entrust will have no obligation to issue any Certificate containing pre-qualified information if such information is subsequently found to have changed or to be in any way inaccurate, incorrect, or misleading.
3. The Private Key corresponding to the Public Key submitted to Entrust with the Certificate request was created using sound cryptographic techniques and all reasonable measures have been taken to, at all times, assure control of (and, in the case of Code Signing Certificates and EV Code Signing Certificates, sole control of), keep confidential, properly protect, and prohibit unauthorized use of, the Private Key (and any associated access or activation data or device, e.g., password or token), including, in the case of Code Signing Certificates and EV Code Signing Certificates, in accordance with the "Private Key Storage" provisions of the Code Signing Baseline Requirements. For clarity, Key Pairs for Code Signing and EV Code Signing Certificates, Document Signing Certificates, and Time-Stamp Certificates are required to be generated in a cryptographic module that prevents exportation or duplication and that meets or exceed the requirements as defined in §6.2.11.
4. Any device storing Private Keys will be operated and maintained in a secure manner.
5. A Certificate will not be installed or used until Subscriber (or, in the case of Code Signing Certificates, Subscriber’s Agent) has reviewed and verified that the content of the Certificate is accurate and correct.
6. In the case of all Entrust OV TLS Certificates and EV TLS Certificates the Certificate will be installed only on servers that are accessible at the Domain Name (subjectAltName(s)) listed in the Certificate, and in the case of S/MIME Certificates, the Certificate will only be used on email addresses listed in the Certificate.
7. Certificates and the Private Key corresponding to the Public Key listed in such Certificate will only be used in compliance with all applicable laws and solely in accordance with the Subscriber Agreement.
8. The contents of Certificates will not be improperly modified.
9. Subscriber will notify Entrust, cease all use of the Certificate and the Private Key corresponding to the Public Key in the Certificate, and request the revocation of the Certificate,
    1. promptly, if any information included in the Certificate or the application for a Certificate changes, is or becomes incorrect or inaccurate, or if any change in any circumstances would make the information in the Certificate misleading.
    2. immediately, if there is any actual or suspected Key Compromise, or if control over the Private Key has been lost for other reasons.
    3. immediately, in the case of a Code Signing Certificate or EV Code Signing Certificate, if there is evidence that the Certificate was used to sign Suspect Code.
10. Subscriber will promptly cease all use of the Certificate and the Private Key corresponding to the Public Key in such Certificate upon expiration or revocation of such Certificate.
11. Subscriber will immediately respond to Entrust’s instructions concerning any Key Compromise or misuse or suspected misuse of a Certificate.
12. Subscriber acknowledges and agrees that Entrust is entitled to revoke a Certificate immediately if:
    1. Subscriber breaches the Subscriber Agreement.
    2. Entrust discovers that there has been a Key Compromise of the Certificate’s Private Key.
    3. Revocation is required under the CPS, the Baseline Requirements, the EV SSL Guidelines, the Code Signing Baseline Requirements or the VMC Requirements.
    4. Entrust discovers that the Certificate is compromised or being used for Suspect Code or the Private Key corresponding to the Public Key in the Certificate has been used to digitally sign Suspect Code.
13. Where the Subject named in the Certificate(s) is a separate entity from the Subscriber, the Subject has authorized the inclusion of the Subject’s information in the Certificate.
14. Subscriber owns, controls, or has the exclusive right to use the Domain Name or email address listed in Certificate.
15. Subscriber acknowledges and agrees that Entrust is entitled to modify the Agreement when necessary to comply with any changes in Industry Standards as defined in the Subscriber Agreement.
16. Subscriber will use appropriate judgment about whether it is appropriate, given the level of security and trust provided by Certificate, to use the Certificate in any given circumstance.

**9.6.3.2 In addition, in the case of Code Signing Certificates and EV Code Signing Certificates,**

1. Subscriber will use commercially reasonable efforts to employ the code signing practices set out in the Code Signing Best Practices document made available <https://www.entrust.com/-/media/documentation/whitepapers/code-signing-best-practices-v2.pdf> or by contacting Entrust ("Code Signing Best Practices").
2. Subscriber will generate and operate any device storing Private Keys in a secure manner, as described in the Code Signing Best Practices, and will use passwords that are randomly generated with at least 16 characters containing uppercase letters, lowercase letters, numbers, and symbols to transport Private Keys. Without limiting the foregoing, Subscriber will use one of the following options to generate and protect its Certificate private keys:
    1. Subscriber uses a tamper‐resistant device, with a cryptography processor, used for the specific purpose of protecting the lifecycle of cryptographic keys (generating, managing, processing, and storing) ("Hardware Crypto Module") with a unit design form factor certified as conforming to at least FIPS 140‐2 Level 2, FIPS 140-3 Level 2, or Common Criteria EAL 4+ ("Specified Requirements");
    2. Subscriber uses a cloud‐base key generation and protection solution with the following requirements: a. key creation, storage, and usage of private key must remain within the security boundaries of the cloud solution’s Hardware Crypto Module that conforms to the Specified Requirements; b. subscription at the level that manages the private key must be configured to log all access, operations, and configuration changes on the resources securing the private key.
    3. Subscriber uses an organization that signs code on behalf of Subscriber using a private key associated with a code signing Certificate which meets the requirements of the Code Signing Baseline Requirements.
3. Subscriber will not request a Code Signing Certificate or EV Code Signing Certificate containing a Public Key that is, or will be used with any other type of Certificate.
4. The Certificate and the Private Key corresponding to the Public Key in such Certificate will only be used for authorized and legal purposes, and will not be used to digitally sign Suspect Code.
5. An adequate network and other security controls will be provided to protect against misuse of the Private Key corresponding to the Public Key in the Certificate.
6. Subscriber acknowledges and agrees that Entrust is authorized to share information about the Subscriber, signed application, Certificate, and surrounding circumstances with other certification authorities or industry groups, including the CA/Browser Forum, if:
    1. the Certificate or Subscriber is identified as a source of Suspect Code,
    2. the authority to request the Certificate cannot be verified, or
    3. the Certificate is revoked for reasons other than at Subscriber’s request (e.g. as a result of Private Key compromise, discovery of malware, etc.).
7. Subscriber acknowledges that ASVs may independently determine that a Certificate is malicious or compromised and that ASVs and ASV products may have the ability to modify its customer experiences or "blocklist" a Code Signing Certificate or EV Code Signing Certificate without notice to Subscriber or Entrust and without regard to the revocation status of the Code Signing Certificate or EV Code Signing Certificate.
8. Subscriber acknowledges that (a) the CA will not provide Certificates with signing keys that are less than 2048 bits, and (b) the CA will hash the Certificate with the SHA-2 algorithm.

**9.6.3.3 In addition, in the case of VMCs:**

1. Subscriber will apply for and use VMCs in accordance with and subject to the VMC Requirements.
2. The trademarks submitted in a VMC application represent registered trademarks that the Subscriber owns or for which it has obtained sufficient license to be able to grant the limited license in the VMC Terms, and that it will immediately revoke the VMC if it no longer owns or has a sufficient license to the applicable trademarks.

### 9.6.4 Relying party representations and warranties

Each Relying Party makes the following representations, commitments, affirmations and warranties:

1. The Relying Party shall understand and, if necessary, receive proper education in the use of Public-Key cryptography and Certificates including Certificates.
2. The Relying Party shall read and agree to all terms and conditions of the CPS and the Relying Party Agreement.
3. The Relying Party shall verify Certificates, including use of CRLs, in accordance with the certification path validation procedure specified in ITU-T Rec. X.509:2005 | ISO/IEC 9594-8 (2005), taking into account any critical extensions and approved technical corrigenda as appropriate.
4. The Relying Party shall trust and make use of a Certificate only if the Certificate has not expired or been revoked and if a proper chain of trust can be established to a trustworthy Root CA.
5. the Relying Party shall properly validate a Certificate before making a determination about whether to rely on such Certificate, including confirmation that the Certificate has not expired or been revoked and that a proper chain of trust can be established to a trustworthy Root CA.
6. the Relying Party shall not rely on a Certificate that cannot be validated back to a trustworthy Root CA.
7. The Relying Party shall make its own judgment and rely on a Certificate only if such reliance is reasonable in the circumstances, including determining whether such reliance is reasonable given the nature of the security and trust provided by a Certificate and the value of any transaction that may involve the use of a Certificate.
8. The Relying Party shall exercise its own judgment in determining whether it is reasonable under the circumstances to rely on a Certificate, including determining whether such reliance is reasonable given the nature of the security and trust provided by an Certificate and the value of any transaction that may involve the use of a Certificate.
9. The Relying Party shall not use a Certificate for any hazardous or unlawful (including tortious) activities.
10. With respect to OV and EV TLS Certificates, the Relying Party shall trust and make use of a Certificate only if the Certificate has not expired or been revoked and if a proper chain of trust can be established to a trustworthy Root CA, and the Relying Party shall not rely on a revoked or expired Certificate.
11. With respect to Code Signing, EV Code Signing, S/MIME and Document Signing Certificates, the Relying Party shall trust and make use of a digital signature created using the Private Key corresponding to the Public Key listed in the Certificate only if the Certificate was not expired or revoked at the time the digital signature was created and if a proper chain of trust can be established to a trustworthy Root CA.
12. With respect to Code Signing, EV Code Signing, S/MIME, Document Signing and Time-Stamp Certificates, the Relying Party shall not rely on a digital signature created using the Private Key corresponding to the Public Key listed in the Certificate if the Certificate was expired at the time the digital signature was created or if the Certificate is revoked.

### 9.6.5 Representations and warranties of other participants

No stipulation.

## 9.7 Disclaimers of warranties

EXCEPT FOR THE LIMITED WARRANTY DESCRIBED IN §9.6.1 ABOVE, AND EXCEPT AS OTHERWISE PROVIDED IN THE SUBSCRIBER AGREEMENT, ENTRUST GROUP EXPRESSLY DISCLAIMS AND MAKES NO REPRESENTATION, WARRANTY OR COVENANT OF ANY KIND, WHETHER EXPRESS OR IMPLIED, EITHER IN FACT OR BY OPERATION OF LAW, WITH RESPECT TO THIS CPS OR ANY CERTIFICATE ISSUED HEREUNDER, INCLUDING WITHOUT LIMITATION, ALL WARRANTIES OF QUALITY, MERCHANTABILITY, NON-INFRINGEMENT, TITLE AND FITNESS FOR A PARTICULAR PURPOSE, AND ALL WARRANTIES, REPRESENTATIONS, CONDITIONS, UNDERTAKINGS, TERMS AND OBLIGATIONS IMPLIED BY STATUTE OR COMMON LAW, TRADE USAGE, COURSE OF DEALING OR OTHERWISE ARE HEREBY EXCLUDED TO THE FULLEST EXTENT PERMITTED BY LAW. EXCEPT FOR THE LIMITED WARRANTY DESCRIBED ABOVE, ENTRUST GROUP FURTHER DISCLAIM AND MAKES NO REPRESENTATION, WARRANTY OR COVENANT OF ANY KIND, WHETHER EXPRESS OR IMPLIED, EITHER IN FACT OR BY OPERATION OF LAW, TO ANY APPLICANT, SUBSCRIBER OR ANY RELYING PARTY THAT (A) THE SUBSCRIBER TO WHICH IT HAS ISSUED A CERTIFICATE IS IN THE FACT THE PERSON, ENTITY OR ORGANIZATION IT CLAIMS TO HAVE BEEN (B) A SUBSCRIBER IS IN FACT THE PERSON, ENTITY OR ORGANIZATION LISTED IN THE CERTIFICATE, OR (C) THAT THE INFORMATION CONTAINED IN THE CERTIFICATES OR IN ANY CERTIFICATE STATUS MECHANISM COMPILED, PUBLISHED OR OTHERWISE DISSEMINATED BY ENTRUST, OR THE RESULTS OF ANY CRYPTOGRAPHIC METHOD IMPLEMENTED IN CONNECTION WITH THE CERTIFICATES IS ACCURATE, AUTHENTIC, COMPLETE OR RELIABLE.

IT IS AGREED AND ACKNOWLEDGED THAT APPLICANTS AND SUBSCRIBERS ARE LIABLE FOR ANY MISREPRESENTATIONS MADE TO ENTRUST AND RELIED UPON BY A RELYING PARTY. ENTRUST GROUP DOES NOT WARRANT OR GUARANTEE UNDER ANY CIRCUMSTANCES THE "NON-REPUDIATION" BY A SUBSCRIBER AND/OR RELYING PARTY OF ANY TRANSACTION ENTERED INTO BY THE SUBSCRIBER AND/OR RELYING PARTY INVOLVING THE USE OF OR RELIANCE UPON A CERTIFICATE.

IT IS UNDERSTOOD AND AGREED UPON BY SUBSCRIBERS AND RELYING PARTIES THAT IN USING AND/OR RELYING UPON A CERTIFICATE THEY ARE SOLELY RESPONSIBLE FOR THEIR RELIANCE UPON THAT CERTIFICATE AND THAT SUCH PARTIES MUST CONSIDER THE FACTS, CIRCUMSTANCES AND CONTEXT SURROUNDING THE TRANSACTION IN WHICH THE CERTIFICATE IS USED IN DETERMINING SUCH RELIANCE.

THE SUBSCRIBERS AND RELYING PARTIES AGREE AND ACKNOWLEDGE THAT CERTIFICATES HAVE A LIMITED OPERATIONAL PERIOD AND MAY BE REVOKED AT ANY TIME. SUBSCRIBERS AND RELYING PARTIES ARE UNDER AN OBLIGATION TO VERIFY WHETHER A CERTIFICATE IS EXPIRED OR HAS BEEN REVOKED. ENTRUST GROUP HEREBY DISCLAIM ANY AND ALL LIABILITY TO SUBSCRIBERS AND RELYING PARTIES WHO DO NOT FOLLOW SUCH PROCEDURES. MORE INFORMATION ABOUT THE SITUATIONS IN WHICH A CERTIFICATE MAY BE REVOKED CAN BE FOUND IN §4.9.3 OF THIS CPS.

## 9.8 Limitations of liability

9.8.1 ENTRUST GROUP’S ENTIRE LIABILITY UNDER THIS CPS TO: (I) AN APPLICANT OR SUBSCRIBER IS SET OUT IN THE SUBSCRIBER AGREEMENT BETWEEN ENTRUST (OR AN ENTRUST GROUP AFFILIATE) AND SUCH SUBSCRIBER; AND (II) A RELYING PARTY IS SET OUT IN THE RELYING PARTY AGREEMENT POSTED IN THE REPOSITORY ON THE DATE THE RELYING PARTY RELIES ON SUCH CERTIFICATE.THE ENTRUST GROUP’S ENTIRE LIABILITY TO ANY OTHER PARTY IS SET OUT IN THE AGREEMENT(S) BETWEEN ENTRUST AND SUCH OTHER PARTY.

9.8.2 SUBJECT TO THE FOREGOING AND IF §9.8.1 ABOVE DOES NOT APPLY:

9.8.2.1 TO THE EXTENT ENTRUST HAS ISSUED THE CERTIFICATE(S) IN COMPLIANCE WITH THE CPS, THE ENTRUST GROUP SHALL HAVE NO LIABILITY TO ANY PERSON FOR ANY CLAIMS, DAMAGES OR LOSSES SUFFERED AS THE RESULT OF THE USE OF OR RELIANCE ON SUCH CERTIFICATE. IN NO EVENT WILL ENTRUST GROUP BE LIABLE FOR, AND CUSTOMER WAIVES ANY RIGHT IT MAY HAVE TO, ANY CONSEQUENTIAL, INDIRECT, SPECIAL, INCIDENTAL, PUNITIVE OR EXEMPLARY DAMAGES OR FOR ANY LOSS OF BUSINESS, OPPORTUNITIES, CONTRACTS, REVENUES, PROFITS, SAVINGS, GOODWILL, REPUTATION, USE, OR DATA, OR COSTS OF REPROCUREMENT OR BUSINESS INTERRUPTION, OR ANY LOSS OR DAMAGE THAT IS NOT DIRECTLY ATTRIBUTABLE TO THE USE OR RELIANCE ON A CERTIFICATE OR THE CERTIFICATE SERVICES PROVIDED UNDER THIS AGREEMENT AND THE CPS INCLUDING ANY LOSS OR DAMAGE RESULTING FROM THE COMBINATION OR INTEGRATION OF THE CERTIFICATE OR CERTIFICATE SERVICES WITH ANY SOFTWARE OR HARDWARE NOT PROVIDED BY ENTRUST IF THE LOSS OR DAMAGE WOULD NOT HAVE OCCURRED AS A RESULT OF USE OF THE CERTIFICATE OR CERTIFICATE SERVICES ALONE.

9.8.2.2 IN NO EVENT WILL ENTRUST GROUP’S TOTAL AGGREGATE LIABILITY ARISING OUT OF OR RELATED TO THE SUBCRIPTION AGREEMENT, THE CPS AND THE USE AND PERFORMANCE OF ANY PRODUCTS AND SERVICES PROVIDED HEREUNDER EXCEED THE GREATER OF ONE THOUSAND UNITED STATES DOLLARS ($1,000.00 U.S.), OR (2) THE FEES PAID BY SUCH PARTY TO ENTRUST UNDER THIS CPS DURING THE TWELVE MONTHS PRIOR TO THE INITIATION OF THE CLAIM TO A MAXIMUM OF ONE HUNDRED THOUSAND DOLLARS ($100,000.00) (EXCEPT THAT FOR ANY EV TLS CERTIFICATE OR EV CODE SIGNING CERTIFICATE ISSUED UNDER THIS CPS, ENTRUST AND ITS ENTITIES’ AGGREGATE LIABILITY TO ANY SUBSCRIBER OR RELYING PARTY IS LIMITED TO TWO THOUSAND U.S. DOLLARS (US$2,000.00) PER EV TLS CERTIFICATE OR EV CODE SIGNING CERTIFICATE, UP TO A MAXIMUM OF ONE HUNDRED THOUSAND U.S. DOLLARS (US$100,000.00).

9.8.2.3 THE EXCLUSIONS AND LIMITS IN THIS SECTION (LIMITATIONS OF LIABILITY) APPLY: (A) REGARDLESS OF THE FORM OF ACTION, WHETHER IN CONTRACT (INCLUDING FUNDAMENTAL BREACH), TORT (INCLUDING NEGLIGENCE), WARRANTY, BREACH OF STATUTORY DUTY, MISREPRESENTATION, STRICT LIABILITY, STRICT PRODUCT LIABILITY, OR OTHERWISE; (B) ON AN AGGREGATE BASIS, REGARDLESS OF THE NUMBER OF CLAIMS, TRANSACTIONS, DIGITAL SIGNATURES OR CERTIFICATES; (C) EVEN IF THE POSSIBILITY OF THE DAMAGES IN QUESTION WAS KNOWN OR COMMUNICATED IN ADVANCE AND EVEN IF SUCH DAMAGES WERE FORESEEABLE; AND (D) EVEN IF THE REMEDIES FAIL OF THEIR ESSENTIAL PURPOSE. ENTRUST HAS SET ITS PRICES AND PROVIDES CERTIFICATES IN RELIANCE ON THE EXCLUSIONS AND LIMITS IN THIS SECTION (LIMITATIONS OF LIABILITY), WHICH FORM AN ESSENTIAL BASIS OF THE PROVISION OF THE SERVICES DESCRIBED IN THIS CPS.

9.8.2.4 In no event will Entrust or its Affiliates be liable to Subscribers, Relying Parties or any other person, entity or organization for any losses, costs, expenses, liabilities, damages, claims, or settlement amounts arising out of or related to the use or misuse of, or reliance on any Certificate issued under this CPS that: (i) has expired or been revoked; (ii) has been used for any purpose other than as set forth in this CPS or an applicable Subscriber Agreement; (iii) has been tampered with; (iv) with respect to which the Key Pair underlying such Certificate or the cryptography algorithm used to generate such Certificate's Key Pair, has been compromised by the action of any party other than Entrust or its Affiliates (including without limitation the Subscriber or Relying Party); or (v) is the subject of misrepresentations or other misleading acts or omissions of any other party, including but not limited to Subscribers and Relying Parties. Except to the extent expressly provided in this CPS or an applicable Subscriber Agreement or Relying Party Agreement, in no event shall Entrust or its Affiliates be liable to the Subscriber, Relying Party or other party for damages arising out of any claim that the content of a Certificate (including any verified marks in a VMC) infringes any patent, trademark, copyright, trade secret or other intellectual property right of any party.

9.8.2.5 Notwithstanding anything to the contrary in this Section (Limitation of Liability) or elsewhere in the Subscriber Agreement, to the extent required by applicable law Entrust neither excludes nor limits its liability for: (i) death or bodily injury caused by its own negligence; (ii) its own fraud or fraudulent misrepresentation; or (iii) other matters for which liability cannot be excluded or limited under applicable law.

## 9.9 Indemnities

### 9.9.1 Indemnification by CAs

Entrust will defend, indemnify, and hold harmless each Application Software Vendor for any and all third party claims, damages, and losses suffered by such Application Software Vendor related to a Certificate issued by the CA that is not in compliance with the Baseline Requirements in effect at the time the Certificate was issued, regardless of the cause of action or legal theory involved. This does not apply, however, to any claim, damages, or loss suffered by such Application Software Vendor related to a Certificate issued by the CA where such claim, damage, or loss was directly or indirectly caused by such Application Software Vendor’s software displaying as not trustworthy a Certificate that is still valid, or displaying as trustworthy: (1) a Certificate that has expired, or (2) a Certificate that has been revoked (but only in cases where the revocation status is currently available from the CA online, and the application software either failed to check such status or ignored an indication of revoked status).

### 9.9.2 Indemnification for Relying Parties

RELYING PARTIES SHALL INDEMNIFY AND HOLD ENTRUST GROUP AND ALL INDEPENDENT THIRD-PARTY REGISTRATION AUTHORITIES OPERATING UNDER A CERTIFICATION AUTHORITY, AND APPLICATION SOFTWARE VENDORS(COLLECTIVELY, THE "INDEMNIFIED PARTIES") HARMLESS FROM AND AGAINST ANY AND ALL LIABILITIES, LOSSES, COSTS, EXPENSES, DAMAGES, CLAIMS, AND SETTLEMENT AMOUNTS (INCLUDING REASONABLE ATTORNEY’S FEES, COURT COSTS, AND EXPERT’S FEES) ARISING OUT OF OR RELATING TO ANY USE OR RELIANCE BY A RELYING PARTY ON ANY CERTIFICATE OR ANY SERVICE PROVIDED IN RESPECT TO CERTIFICATES, INCLUDING (I) LACK OF PROPER VALIDATION OF A CERTIFICATE BY A RELYING PARTY, (II) RELIANCE BY THE RELYING PARTY ON AN EXPIRED OR REVOKED CERTIFICATE, (III) USE OF A CERTIFICATE OTHER THAN AS PERMITTED BY THE CPS, THE SUBSCRIBER AGREEMENT, ANY RELYING PARTY AGREEMENT, AND APPLICABLE LAW, (IV) FAILURE BY A RELYING PARTY TO EXERCISE REASONABLE JUDGMENT IN THE CIRCUMSTANCES IN RELYING ON A CERTIFICATE, OR (V) ANY CLAIM OR ALLEGATION THAT THE RELIANCE BY A RELYING PARTY ON A CERTIFICATE OR THE INFORMATION CONTAINED IN A CERTIFICATE INFRINGES, MISAPPROPRIATES, DILUTES, UNFAIRLY COMPETES WITH, OR OTHERWISE VIOLATES THE RIGHTS INCLUDING INTELLECTUAL PROPERTY RIGHTS OR ANY OTHER RIGHTS OF ANYONE IN ANY JURISDICTION. NOTWITHSTANDING THE FOREGOING, RELYING PARTIES SHALL NOT BE OBLIGATED TO PROVIDE ANY INDEMNIFICATION TO AN INDEMNIFIED PARTY IN RESPECT TO ANY LIABILITIES, LOSSES, COSTS, EXPENSES, DAMAGES, CLAIMS, AND SETTLEMENT AMOUNTS (INCLUDING REASONABLE ATTORNEY’S FEES, COURT COSTS AND EXPERT’S FEES) TO THE EXTENT THAT SUCH LIABILITIES, LOSSES, COSTS, EXPENSES, DAMAGES, CLAIMS, AND SETTLEMENT AMOUNTS (INCLUDING REASONABLE ATTORNEY’S FEES, COURT COSTS, AND EXPERT’S FEES) ARISE OUT OF OR RELATE TO ANY WILLFUL MISCONDUCT BY SUCH INDEMNIFIED PARTY.

### 9.9.3 Indemnification by Subscribers

Unless otherwise set out in in a SUBSCRIBER Agreement SUBSCRIBERS SHALL INDEMNIFY AND HOLD ENTRUST AND ALL INDEPENDENT THIRD-PARTY REGISTRATION AUTHORITIES OPERATING UNDER A CERTIFICATION AUTHORITY, AND ALL APPLICATION SOFTWARE VENDORS(COLLECTIVELY, THE "INDEMNIFIED PARTIES") HARMLESS FROM AND AGAINST ANY AND ALL LIABILITIES, LOSSES, COSTS, EXPENSES, DAMAGES, CLAIMS, AND SETTLEMENT AMOUNTS (INCLUDING REASONABLE ATTORNEY’S FEES, COURT COSTS, AND EXPERT’S FEES) ARISING OUT OF OR RELATING TO ANY RELIANCE BY A RELYING PARTY ON ANY CERTIFICATE OR ANY SERVICE PROVIDED IN RESPECT TO CERTIFICATES, INCLUDING ANY (I) ERROR, MISREPRESENTATION OR OMISSION MADE BY A SUBSCRIBER IN USING OR APPLYING FOR A CERTIFICATE, (II) MODIFICATION MADE BY A SUBSCRIBER TO THE INFORMATION CONTAINED IN A CERTIFICATE, (III) USE OF A CERTIFICATE OTHER THAN AS PERMITTED BY THE CPS, THE SUBSCRIBER AGREEMENT, ANY RELYING PARTY AGREEMENT, AND APPLICABLE LAW, (IV) FAILURE BY A SUBSCRIBER TO TAKE THE NECESSARY PRECAUTIONS TO PREVENT LOSS, DISCLOSURE, COMPROMISE OR UNAUTHORIZED USE OF THE PRIVATE KEY CORRESPONDING TO THE PUBLIC KEY IN SUCH SUBSCRIBER’S CERTIFICATE, OR (V) ALLEGATION THAT THE USE OF A SUBSCRIBER’S CERTIFICATE OR THE INFORMATION CONTAINED IN A SUBSCRIBER’S CERTIFICATE INFRINGES, MISAPPROPRIATES, DILUTES, UNFAIRLY COMPETES WITH, OR OTHERWISE VIOLATES THE RIGHTS INCLUDING INTELLECTUAL PROPERTY RIGHTS OR ANY OTHER RIGHTS OF ANYONE IN ANY JURISDICTION. NOTWITHSTANDING THE FOREGOING, A SUBSCRIBER SHALL NOT BE OBLIGATED TO PROVIDE ANY INDEMNIFICATION TO AN INDEMNIFIED PARTY IN RESPECT TO ANY LIABILITIES, LOSSES, COSTS, EXPENSES, DAMAGES, CLAIMS, AND SETTLEMENT AMOUNTS (INCLUDING REASONABLE ATTORNEY’S FEES, COURT COSTS AND EXPERTS FEES) TO THE EXTENT THAT SUCH LIABILITIES, LOSSES, COSTS, EXPENSES, DAMAGES, CLAIMS, AND SETTLEMENT AMOUNTS (INCLUDING REASONABLE ATTORNEY’S FEES, COURT COSTS, AND EXPERT’S FEES) ARISE OUT OF OR RELATE TO ANY WILLFUL MISCONDUCT BY SUCH INDEMNIFIED PARTY.

## 9.10 Term and termination

### 9.10.1 Term

This CPS will be effective on the date this CPS is published in the Repository and will continue until a newer version of the CPS is published.

### 9.10.2 Termination

This CPS will remain in effect until replaced by a newer version.

### 9.10.3 Effect of termination and survival

The provisions of sections 1.6, 3.1.6, 5.5, 9.1, 9.3, 9.4, 9.5, 9.7, 9.8, 9.9.2, 9.9.3, 9.10.3, 9.13, 9.14 and 9.16 shall survive termination or expiration of the CPS, any Subscriber Agreements, and any Relying Party Agreements. All references to sections that survive termination of the CPS, any Subscriber Agreements, and any Relying Party Agreements, shall include all sub-sections of such sections. All payment obligations shall survive any termination or expiration of the CPS, any Subscriber Agreements, and any Relying Party Agreements.

## 9.11 Individual notices and communications with participants

Unless otherwise set out in in a Subscriber Agreement or Relying Party Agreement, any notice to be given to Entrust under this CPS, a Subscriber Agreement, or a Relying Party Agreement shall be given in writing to the address specified in §1.5.2 by prepaid receipted mail, or overnight courier, and shall be effective as follows (i) in the case of courier, on the next Business Day, and (ii) in the case of receipted mail, five (5) Business Days following the date of deposit in the mail. Any notice to be given by Entrust under the CPS or any Subscriber Agreement shall be given by email or by prepaid receipted mail or courier to the last address, email address for the Subscriber on file with Entrust. In the event of notice by email, the notice shall become effective on the next Business Day. In the event of notice by prepaid receipted mail, or overnight courier, notice shall become effective as specified in (i) or (ii), depending on the means of notice utilized.

## 9.12 Amendments

### 9.12.1 Procedure for amendment

Entrust may, in its discretion, modify the CPS and the terms and conditions contained herein from time to time. Entrust shall modify the CPS to stay concurrent with the latest version of the Baseline Requirements, EV SSL Guidelines, Code Signing Baseline Requirements, S/MIME Baseline Requirements, and Verified Mark Certificate Requirements.

### 9.12.2 Notification mechanism and period

Modifications to the CPS shall be published in the Repository and shall become effective fifteen (15) days after publication in the Repository unless Entrust withdraws such modified CPS prior to such effective date. In the event that Entrust makes a significant modification to CPS, the version number of the CPS shall be updated accordingly. Unless a Subscriber ceases to use, removes, and requests revocation of such Subscriber’s Certificate(s) prior to the date on which an updated version of the CPS becomes effective, such Subscriber shall be deemed to have consented to the terms and conditions of such updated version of the CPS and shall be bound by the terms and conditions of such updated version of the CPS.

### 9.12.3 Circumstances under which OID must be changed

No stipulation.

## 9.13 Dispute resolution provisions

Unless otherwise set out in in a Subscriber Agreement or Relying Party Agreement, any disputes between a Subscriber or an Applicant and Entrust or any third-party RAs operating under the CAs, or a Relying Party and Entrust or any third-party RAs operating under the CAs, shall be submitted to mediation in accordance with the Commercial Mediation Rules of the American Arbitration Association which shall take place in English in Ottawa, Ontario. In the event that a resolution to such dispute cannot be achieved through mediation within thirty (30) days, the dispute shall be submitted to binding arbitration. The arbitrator shall have the right to decide all questions of arbitrability. The dispute shall be finally settled by arbitration in accordance with the rules of the American Arbitration Association, as modified by this provision. Such arbitration shall take place in English in Ottawa, Ontario, before a sole arbitrator appointed by the American Arbitration Association (AAA) who shall be appointed by the AAA from its Technology Panel and shall be reasonably knowledgeable in electronic commerce disputes. The arbitrator shall apply the laws of the Province of Ontario, without regard to its conflict of laws provisions, and shall render a written decision within thirty (30) days from the date of close of the arbitration hearing, but no more than one (1) year from the date that the matter was submitted for arbitration. The decision of the arbitrator shall be binding and conclusive and may be entered in any court of competent jurisdiction. In each arbitration, the prevailing party shall be entitled to an award of all or a portion of its costs in such arbitration, including reasonable attorney’s fees actually incurred. Nothing in the CPS, or in any Subscriber Agreement, or any Relying Party Agreement shall preclude Entrust or any third-party RAs operating under the CAs from applying to any court of competent jurisdiction for temporary or permanent injunctive relief, without breach of this §9.13 and without any abridgment of the powers of the arbitrator, with respect to any (i) alleged Compromise that affects the integrity of a Certificate, or (ii) alleged breach of the terms and conditions of the CPS, any Subscriber Agreement, or any Relying Party Agreement. The institution of any arbitration or any action shall not relieve an Applicant, Subscriber or Relying Party of its obligations under the CPS, any Subscriber Agreement, or any Relying Party Agreement.

Any and all arbitrations or legal actions in respect to a dispute that is related to a Certificate or any services provided in respect to a Certificate shall be commenced prior to the end of one (1) year after (i) the expiration or revocation of the Certificate in dispute, or (ii) the date of provision of the disputed service or services in respect to the Certificate in dispute, whichever is sooner. If any arbitration or action in respect to a dispute that is related to a Certificate or any service or services provided in respect to a Certificate is not commenced prior to such time, any party seeking to institute such an arbitration or action shall be barred from commencing or proceeding with such arbitration or action.

## 9.14 Governing law

Unless otherwise set out in in a Subscriber Agreement or Relying Party Agreement, the laws of the Province of Ontario, Canada, excluding its conflict of laws rules, shall govern the construction, validity, interpretation, enforceability and performance of the CPS, all Subscriber Agreements and all Relying Party Agreements. The application of the United Nations Convention on Contracts for the International Sale of Goods to the CPS, any Subscriber Agreements, and any Relying Party Agreements is expressly excluded. Any dispute arising out of or in respect to the CPS, any Subscriber Agreement, any Relying Party Agreement, or in respect to any Certificates or any services provided in respect to any Certificates that is not resolved by alternative dispute resolution, shall be brought in the provincial or federal courts sitting in Ottawa, Ontario, and each person, entity, or organization hereby agrees that such courts shall have personal and exclusive jurisdiction over such disputes. In the event that any matter is brought in a provincial or federal court, Applicants, Subscribers, and Relying Parties waive any right that such Applicants, Subscribers, and Relying Parties may have to a jury trial.

## 9.15 Compliance with applicable law

Certificates and related information may be subject to export, import, and/or use restrictions. Subscribers and Relying Parties will comply in all respects with any and all applicable laws, rules and regulations and obtain all permits, licenses and authorizations or certificates that may be required in connection with their exercise of their rights and obligations under any part of the CPS, Subscriber Agreement, and/or Relying Party Agreement, including use or access by any of Subscriber or Relying Party’s users. Without limiting the foregoing, Subscribers and Relying Parties will comply with all applicable trade control laws, including but not limited to any sanctions or trade controls of the European Union ("E.U."), Canada, the United Kingdom ("U.K."), and United Nations ("U.N."); the Export Administration Regulations administered by the U.S. Department of Commerce’s Bureau of Industry and Security; U.S. sanctions regulations administered by the U.S. Treasury Department’s Office of Foreign Assets Control ("OFAC"); or on the U.S. Department of Commerce Entities List ("Entities List"); and any import or export licenses required pursuant to any of the foregoing; and all applicable anti-money laundering laws, including the U.S. Bank Secrecy Act, Money Laundering Control Act, and Patriot Act, the Canadian Proceeds of Crime (Money Laundering) and Terrorist Financing Act, the U.K. Proceeds of Crime Act, and legislation implementing the International Convention on the Suppression of the Financing of Terrorism or the money laundering provisions of the U.N. transnational Organized Crime Convention. Each Subscriber and Relying Party represents and warrants that: (a) neither it nor any of its users is located in, under the control of, or a national or resident of any country to which the export of any software or technology licensed under the Agreement, or related information, would be prohibited by the applicable laws, rules or regulations of the U.S., Canada, U.K., E.U., or other applicable jurisdiction; (b) neither it nor any of its users is a Person to whom the export of any software or technology licensed under the Agreement, or related information, would be prohibited by the laws of the U.S., Canada, U.K., E.U., or other applicable jurisdiction; (c) it and each of its users has and will comply with applicable laws, rules and regulations of the U.S., Canada, U.K., E.U., or other applicable jurisdiction(s) and of any state, province, or locality or applicable jurisdiction governing exports of any product or service provided by or through Entrust; (d) it and all its users will not use any product or service for any purposes prohibited by applicable laws, rules or regulations on trade controls, including related to nuclear, chemical, or biological weapons proliferation, arms trading, or in furtherance of terrorist financing; (e) neither it nor any of its users nor any of its affiliates, officers, directors, or employees is (i) an individual listed on, or directly or indirectly owned or controlled by, a Person (whether legal or natural) listed on, or acting on behalf of a Person listed on, any U.S, Canadian, E.U., U.K., or U.N. sanctions list, including OFAC’s list of Specially Designated Nationals or the Entities List; or (ii) located in, incorporated under the laws of, or owned (meaning 50% or greater ownership interest) or otherwise, directly or indirectly, controlled by, or acting on behalf of, a person located in, residing in, or organized under the laws of any of the countries listed at <https://www.entrust.com/legal-compliance/denied-parties> (each of (i) and (ii), a "Denied Party"); and (f) it and each of its users is legally distinct from, and not an agent of any Denied Party. In the event any of the above representations and warranties is incorrect or the Subscriber, Relying Party or any their users engages in any conduct that is contrary to sanctions or trade controls or other applicable laws, regulations, or rules, any agreements, purchase orders, performance of services, or other contractual obligations of Entrust are immediately terminated.

## 9.16 Miscellaneous provisions

### 9.16.1 Entire agreement

No stipulation.

### 9.16.2 Assignment

Certificates and the rights granted under the CPS, any Subscriber Agreement, or any Relying Party Agreement are personal to the Applicant, Subscriber, or Relying Party that entered into the Subscriber Agreement or Relying Party Agreement and cannot be assigned, sold, transferred, or otherwise disposed of, whether voluntarily, involuntarily, by operation of law, or otherwise, without the prior written consent of Entrust or the RA under a CA with which such Applicant, Subscriber, or Relying Party has contracted. Any attempted assignment or transfer without such consent shall be void and shall automatically terminate such Applicant’s, Subscriber’s or Relying Party’s rights under the CPS, any Subscriber Agreement, or any Relying Party Agreement. Entrust may assign, sell, transfer, or otherwise dispose of the CPS, any Subscriber Agreements, or any Relying Party Agreements together with all of its rights and obligations under the CPS, any Subscriber Agreements, and any Relying Party Agreements (i) to an Affiliate, or (ii) as part of a sale, merger, or other transfer of all or substantially all the assets or stock of the business of Entrust to which the CPS, the Subscriber Agreements, and Relying Party Agreements relate. Subject to the foregoing limits, this Agreement shall be binding upon and shall inure to the benefit of permitted successors and assigns of Entrust, any third-party RAs operating under the CAs, Applicants, Subscribers, and Relying Parties, as the case may be.

The CPS, the Subscriber Agreements, and the Relying Party Agreements state all of the rights and obligations of the Entrust Group, any Applicant, Subscriber, or Relying Party and any other persons, entities, or organizations in respect to the subject matter hereof and thereof and such rights and obligations shall not be augmented or derogated by any prior agreements, communications, or understandings of any nature whatsoever whether oral or written. The rights and obligations of the Entrust Group may not be modified or waived orally and may be modified only in a writing signed or authenticated by a duly authorized representative of Entrust.

### 9.16.3 Severability

To the extent permitted by applicable law, any provision of law is waived that would render any provision of the CPS, any Subscriber Agreements, and any Relying Party Agreements invalid or otherwise unenforceable in any respect. In the event that any provision of the CPS, any Subscriber Agreements, or any Relying Party Agreements is held to be invalid or otherwise unenforceable in application to particular facts or circumstances: (a)  such provision will be interpreted and amended to the extent necessary to fulfill its intended purpose to the maximum extent permitted by applicable law and its validity and enforceability as applied to any other facts or circumstances will not be affected or impaired; and (b) the remaining provisions of the CPS, Subscriber Agreement, or Relying Party Agreement will continue in full force and effect. For greater certainty, it is expressly understood and intended that each provision that deals with limitations and exclusions of liability, disclaimers of representations, warranties and conditions, or indemnification is severable from any other provisions.

### 9.16.4 Enforcement (attorneys' fees and waiver of rights)

No stipulation.

### 9.16.5 Force Majeure

"Force Majeure Event" means any event or circumstance beyond Entrust Group’s reasonable control, including but not limited to, floods, fires, hurricanes, earthquakes, tornados, epidemics, pandemics, other acts of God or nature, strikes and other labor disputes, failure of utility, transportation or communications infrastructures, riots or other acts of civil disorder, acts of war, terrorism (including cyber terrorism), malicious damage, judicial action, lack of or inability to obtain export permits or approvals, acts of government such as expropriation, condemnation, embargo, changes in applicable laws or regulations, and shelter-in-place or similar orders, and acts or defaults of third party suppliers or service providers. In the event that a Force Majeure Event directly or indirectly causes a failure or delay in Entrust Group’s performance of its obligations under the CPS, any Subscriber Agreement, or any Relying Party Agreement, Entrust Group shall not be in default or liable for any loss or damages where performance is impossible or commercially impracticable.

## 9.17 Other provisions

### 9.17.1 Conflict of Provisions

In the event of any conflict between the provisions of this CPS and the provisions of any Subscriber Agreement or any Relying Party Agreement, the terms and conditions of this CPS shall govern.

### 9.17.2 Fiduciary Relationships

Nothing contained in this CPS, or in any Subscriber Agreement, or any Relying Party Agreement shall be deemed to constitute the Entrust Group as the fiduciary, partner, agent, trustee, or legal representative of any Applicant, Subscriber, Relying Party or any other person, entity, or organization or to create any fiduciary relationship between the Entrust Group and any Subscriber, Applicant, Relying Party or any other person, entity, or organization, for any purpose whatsoever. Nothing in the CPS, or in any Subscriber Agreement or any Relying Party Agreement shall confer on any Subscriber, Applicant, Relying Party, or any other third party, any authority to act for, bind, or create or assume any obligation or responsibility, or make any representation on behalf of the Entrust Group.

### 9.17.3 Waiver

The failure of Entrust to enforce, at any time, any of the provisions of this CPS, a Subscriber Agreement with Entrust, or a Relying Party Agreement with Entrust or the failure of Entrust to require, at any time, performance by any Applicant, Subscriber, Relying Party or any other person, entity, or organization of any of the provisions of this CPS, a Subscriber Agreement with Entrust, or a Relying Party Agreement with Entrust, shall in no way be construed to be a present or future waiver of such provisions, nor in any way affect the ability of Entrust to enforce each and every such provision thereafter. The express waiver by Entrust of any provision, condition, or requirement of this CPS, a Subscriber Agreement with Entrust, or a Relying Party Agreement with Entrust shall not constitute a waiver of any future obligation to comply with such provision, condition, or requirement.

### 9.17.4 Interpretation

All references in this CPS to "section" or "§" refer to the sections of this CPS unless otherwise stated. As used in this CPS, neutral pronouns and any variations thereof shall be deemed to include the feminine and masculine and all terms used in the singular shall be deemed to include the plural, and vice versa, as the context may require. The words "hereof", "herein", and "hereunder" and other words of similar import refer to this CPS as a whole, as the same may from time to time be amended or supplemented, and not to any subdivision contained in this CPS. The words "including", "include" and "includes" will each be deemed to be followed by the phrase "without limitation".

# Appendix A - Certificate Profiles

## Root CA Certificate

| **Root CA Certificate Field**      | **Critical Extension** | **Content** |
| --- | -- | ------ |
| Issuer                             |                        | Must match subject |
| Subject                            |                        | Must contain countryName, organizationName and commonName |
| Extension: authoritytKeyIdentifier | Not critical           | If included, must be identical to the subjectKeyIdentifier field |
| Extension: subjectKeyIdentifier    | Not critical           | 160-bit SHA-1 hash of subjectPublicKey per RFC 5280 |
| Extension: basicConstraints        | Critical               | cA is TRUE; pathLenConstraint is not present |
| Extension: keyUsage                | Critical               | keyCertsign and cRLSign bits are set; digitalSignature if Root signs OCSP responses |

## Cross Certificate or Subordinate CA Certificate

| **Field**                         | **Critical Extension** | **Content** |
| --- | -- | ------ |
| Validity: notAfter                |                        | Not later than the notAfter of the signing certificate |
| Subject                           |                        | Must contain countryName, organizationName and commonName |
| Extension: subjectKeyIdentifier   | Not critical           | 160-bit SHA-1 hash of subjectPublicKey per RFC 5280 |
| Extension: authorityKeyIdentifier | Not critical           | Matches subjectKeyIdentifier of signing certificate |
| Extension: certificatePolicies    | Not critical           | Must contain at least one set of policyInformation containing at least a policyIdentifier |
| Extension: basicConstraints       | Critical               | cA is TRUE |
| Extension: keyUsage               | Critical               | keyCertsign and cRLSign bits are set; digitalSignature if CA signs OCSP responses |
| Extension: extKeyUsage            | Not critical           | Must be present |
| Extension: authorityInfoAccess    | Not critical           | Must contain one AccessDescription with an accessMethod of ocsp and a Location of type uniformResourceIdentifier |
| Extension: cRLDistributionPoints  | Not critical           | Must have at least one DistributionPoint containing a fullName of type uniformResourceIdentifier |

## Technically Constrained Subordinate CA Certificate

| **Field**                         | **Critical Extension** | **Content** |
| --- | -- | ------ |
| Validity: notAfter                |                        | Not later than the notAfter of the signing certificate |
| Subject                           |                        | Must contain countryName, organizationName and commonName |
| Extension: subjectKeyIdentifier   | Not critical           | 160-bit SHA-1 hash of subjectPublicKey per RFC 5280 |
| Extension: authorityKeyIdentifier | Not critical           | Matches subjectKeyIdentifier of signing certificate |
| Extension: certificatePolicies    | Not critical           | Must contain at least one set of policyInformation containing at least a policyIdentifier |
| Extension: basicConstraints       | Critical               | cA is TRUE |
| Extension: keyUsage               | Critical               | keyCertsign and cRLSign bits are set |
| Extension: extKeyUsage            | Not critical           | Must be present per §7.1.5 |
| Extension: nameConstraint         | Critical               | Must contain constraints per §7.1.5 |
| Extension: authorityInfoAccess    | Not critical           | Must contain one AccessDescription with an accessMethod of ocsp and a Location of type uniformResourceIdentifier |
| Extension: cRLDistributionPoints  | Not critical           | Must have at least one DistributionPoint containing a fullName of type uniformResourceIdentifier |

## OV TLS Certificate

| **Field**                         | **Critical Extension** | **Content** |
| --- | -- | ------ |
| Subject                           |                        | Must contain countryName, localityName organizationName and commonName |
| Extension: subjectKeyIdentifier   | Not critical           | 160-bit SHA-1 hash of subjectPublicKey per RFC 5280 |
| Extension: authorityKeyIdentifier | Not critical           | Matches subjectKeyIdentifier of signing certificate |
| Extension: certificatePolicies    | Not critical           | Must contain at least one set of policyInformation containing reserved certificate policy identifier |
| Extension: basicConstraints       | Critical               | Empty or not present |
| Extension: subjectAltName         | Not critical           | Must contain at the commonName and all names must either be of type dNSName or iPAddress |
| Extension: keyUsage               | Critical               | digitalSignature bit must be set, keyEncipherment may be set, other bits should not be set |
| Extension: extKeyUsage            | Not critical           | Must include serverAuth, may includeclientAuth, other values must not be set |
| Extension: authorityInfoAccess    | Not critical           | Must contain one AccessDescription with an accessMethod of caIssuers and a Location of type uniformResourceIdentifier and one AccessDescription with an accessMethod of ocsp and a Location of type uniformResourceIdentifier |
| Extension: cRLDistributionPoints  | Not critical           | Must have at least one DistributionPoint containing a fullName of type uniformResourceIdentifier |

## EV TLS Certificate

| **Field**                         | **Critical Extension** | **Content** |
| --- | -- | ------ |
| Subject                           |                        | Must contain countryName, localityName jurisdiction country, organizationName business category, serial number of subscriber and commonName |
| Extension: subjectKeyIdentifier   | Not critical           | 160-bit SHA-1 hash of subjectPublicKey per RFC 5280 |
| Extension: authorityKeyIdentifier | Not critical           | Matches subjectKeyIdentifier of signing certificate |
| Extension: certificatePolicies    | Not critical           | Must contain at least one set of policyInformation containing reserved certificate policy identifier and may contain policyQualifier with cPSuri |
| Extension: basicConstraints       | Critical               | Empty or not present |
| Extension: subjectAltName         | Not critical           | Must contain at the commonName and all names must either be of type dNSName |
| Extension: keyUsage               | Critical               | digitalSignature bit must be set, keyEncipherment may be set, other bits should not be set |
| Extension: extKeyUsage            | Not critical           | Must include serverAuth, may includeclientAuth, other values must not be set |
| Extension: authorityInfoAccess    | Not critical           | Must contain one AccessDescription with an accessMethod of caIssuers and a Location of type uniformResourceIdentifier and one AccessDescription with an accessMethod of ocsp and a Location of type uniformResourceIdentifier |
| Extension: cRLDistributionPoints  | Not critical           | Must have at least one DistributionPoint containing a fullName of type uniformResourceIdentifier |

## Client Authentication Certificate

| **Field**                         | **Critical Extension** | **Content** |
| --- | -- | ------ |
| Subject                           |                        | Must contain countryName, localityName organizationName and commonName |
| Extension: subjectKeyIdentifier   | Not critical           | 160-bit SHA-1 hash of subjectPublicKey per RFC 5280 |
| Extension: authorityKeyIdentifier | Not critical           | Matches subjectKeyIdentifier of signing certificate |
| Extension: certificatePolicies    | Not critical           | Must contain at least one set of policyInformation containing at least a policyIdentifier |
| Extension: basicConstraints       | Critical               | Empty or not present |
| Extension: subjectAltName         | Not critical           | Must contain at the commonName and all names must either be of type dNSName or iPAddress |
| Extension: keyUsage               | Critical               | digitalSignature and/or keyAgreement bit must be set, other bits should not be set |
| Extension: extKeyUsage            | Not critical           | Must include clientAuth other values must not be set |
| Extension: authorityInfoAccess    | Not critical           | Must contain one AccessDescription with an accessMethod of caIssuers and a Location of type uniformResourceIdentifier and one AccessDescription with an accessMethod of ocsp and a Location of type uniformResourceIdentifier |
| Extension: cRLDistributionPoints  | Not critical           | Must have at least one DistributionPoint containing a fullName of type uniformResourceIdentifier |

## Code Signing Certificate

| **Field**                         | **Critical Extension** | **Content** |
| --- | -- | ------ |
| Subject                           |                        | Must contain countryName, organizationName and commonName |
| Extension: subjectKeyIdentifier   | Not critical           | 160-bit SHA-1 hash of subjectPublicKey per RFC 5280 |
| Extension: authorityKeyIdentifier | Not critical           | Matches subjectKeyIdentifier of signing certificate |
| Extension: certificatePolicies    | Not critical           | Must contain at least one set of policyInformation containing reserved certificate policy identifier |
| Extension: basicConstraints       | Critical               | Empty or not present |
| Extension: keyUsage               | Critical               | digitalSignature bits must be set, other bits must not be set |
| Extension: extKeyUsage            | Not critical           | Must include codeSigning, other values must not be set |
| Extension: authorityInfoAccess    | Not critical           | Must contain one AccessDescription with an accessMethod of caIssuers and a Location of type uniformResourceIdentifier and one AccessDescription with an accessMethod of ocsp and a Location of type uniformResourceIdentifier |
| Extension: cRLDistributionPoints  | Not critical           | Must have at least one DistributionPoint containing a fullName of type uniformResourceIdentifier |

## EV Code Signing Certificate

| **Field**                         | **Critical Extension** | **Content** |
| --- | -- | ------ |
| Subject                           |                        | Must contain countryName, localityName jurisdiction country, organizationName business category, serial number of subscriber and commonName |
| Extension: subjectKeyIdentifier   | Not critical           | 160-bit SHA-1 hash of subjectPublicKey per RFC 5280 |
| Extension: authorityKeyIdentifier | Not critical           | Matches subjectKeyIdentifier of signing certificate |
| Extension: certificatePolicies    | Not critical           | Must contain at least one set of policyInformation containing reserved certificate policy identifier |
| Extension: basicConstraints       | Critical               | Empty or not present |
| Extension: keyUsage               | Critical               | digitalSignature bits must be set, other bits must not be set |
| Extension: extKeyUsage            | Not critical           | Must include codeSigning, other values must not be set |
| Extension: authorityInfoAccess    | Not critical           | Must contain one AccessDescription with an accessMethod of caIssuers and a Location of type uniformResourceIdentifier and one AccessDescription with an accessMethod of ocsp and a Location of type uniformResourceIdentifier |
| Extension: cRLDistributionPoints  | Not critical           | Must have at least one DistributionPoint containing a fullName of type uniformResourceIdentifier |

## S/MIME Class 1 Certificate

| **Field**                         | **Critical Extension** | **Content** |
| --- | -- | ------ |
| Subject                           |                        | Must include rfc822Name email address in the commonName and/or emailAddress fields |
| Extension: subjectKeyIdentifier   | Not critical           | 160-bit SHA-1 hash of subjectPublicKey per RFC 5280 |
| Extension: authorityKeyIdentifier | Not critical           | Matches subjectKeyIdentifier of signing certificate |
| Extension: certificatePolicies    | Not critical           | Must contain at least one set of policyInformation containing reserved certificate policy identifier |
| Extension: basicConstraints       | Critical               | Empty or not present |
| Extension: subjectAltName         | Not critical           | Must include rfc822Name email address |
| Extension: keyUsage               | Critical               | digitalSignature bit must be set, keyEncipherment may be set, other bits should not be set |
| Extension: extKeyUsage            | Not critical           | Must include emailProtection, may include clientAuth, other values will not be set |
| Extension: authorityInfoAccess    | Not critical           | Must contain one AccessDescription with an accessMethod of caIssuers and a Location of type uniformResourceIdentifier and one AccessDescription with an accessMethod of ocsp and a Location of type uniformResourceIdentifier |
| Extension: cRLDistributionPoints  | Not critical           | Must have at least one DistributionPoint containing a fullName of type uniformResourceIdentifier |

## S/MIME Class 2 Certificate

| **Field**                         | **Critical Extension** | **Content** |
| --- | -- | ------ |
| Subject                           |                        | Must contain countryName, localityName organizationName, commonName and emailAddress with rfc822Name<br><br>Effective 1 September 2023, must contain organizationIdentifier and may contain givenName and surname |
| Extension: subjectKeyIdentifier   | Not critical           | 160-bit SHA-1 hash of subjectPublicKey per RFC 5280 |
| Extension: authorityKeyIdentifier | Not critical           | Matches subjectKeyIdentifier of signing certificate |
| Extension: certificatePolicies    | Not critical           | Must contain at least one set of policyInformation containing reserved certificate policy identifier |
| Extension: basicConstraints       | Critical               | Empty or not present |
| Extension: subjectAltName         | Not critical           | Must include rfc822Name email address |
| Extension: keyUsage               | Critical               | digitalSignature bit must be set, keyEncipherment may be set, other bits should not be set |
| Extension: extKeyUsage            | Not critical           | Must include emailProtection, may include clientAuth, other values will not be set |
| Extension: authorityInfoAccess    | Not critical           | Must contain one AccessDescription with an accessMethod of caIssuers and a Location of type uniformResourceIdentifier and one AccessDescription with an accessMethod of ocsp and a Location of type uniformResourceIdentifier |
| Extension: cRLDistributionPoints  | Not critical           | Must have at least one DistributionPoint containing a fullName of type uniformResourceIdentifier |

## Document Signing Certificate

| **Field**                         | **Critical Extension** | **Content** |
| --- | -- | ------ |
| Subject                           |                        | Must contain countryName, organizationName, and commonName |
| Extension: subjectKeyIdentifier   | Not critical           | 160-bit SHA-1 hash of subjectPublicKey per RFC 5280 |
| Extension: authorityKeyIdentifier | Not critical           | Matches subjectKeyIdentifier of signing certificate |
| Extension: certificatePolicies    | Not critical           | Must contain at least one set of policyInformation containing at least a policyIdentifier |
| Extension: basicConstraints       | Critical               | Empty or not present |
| Extension: subjectAltName         | Not critical           | May contain rfc822Name email address |
| Extension: keyUsage               | Critical               | digitalSignature bit must be set, keyEncipherment and nonRepudiation may be set, other bits should not be set |
| Extension: extKeyUsage            | Not critical           | Must include Document Signing (Entrust) and/or Document Signing (Microsoft), other values should not be set |
| Extension: authorityInfoAccess    | Not critical           | Must contain one AccessDescription with an accessMethod of caIssuers and a Location of type uniformResourceIdentifier and one AccessDescription with an accessMethod of ocsp and a Location of type uniformResourceIdentifier |
| Extension: cRLDistributionPoints  | Not critical           | Must have at least one DistributionPoint containing a fullName of type uniformResourceIdentifier |
| Extension: timeStamping           | Not critical           | Must have at least one accessLocation containing a fullName of type uniformResourceIdentifier |
| Extension: Archive Rev Info       | Not critical           | May be provided |

## Time-Stamp Certificate

| **Field**                         | **Critical Extension** | **Content** |
| --- | -- | ------ |
| Subject                           |                        | Must contain countryName, organizationName and commonName |
| Extension: subjectKeyIdentifier   | Not critical           | 160-bit SHA-1 hash of subjectPublicKey per RFC 5280 |
| Extension: authorityKeyIdentifier | Not critical           | Matches subjectKeyIdentifier of signing certificate |
| Extension: certificatePolicies    | Not critical           | Must contain at least one set of policyInformation containing at least a policyIdentifier |
| Extension: basicConstraints       | Critical               | Empty or not present |
| Extension: keyUsage               | Critical               | digitalSignature bits must be set, other bits must not be set |
| Extension: extKeyUsage            | Critical               | Must include timeStamping, other values must not be set |
| Extension: authorityInfoAccess    | Not critical           | Must contain one AccessDescription with an accessMethod of caIssuers and a Location of type uniformResourceIdentifier and one AccessDescription with an accessMethod of ocsp and a Location of type uniformResourceIdentifier |
| Extension: cRLDistributionPoints  | Not critical           | Must have at least one DistributionPoint containing a fullName of type uniformResourceIdentifier |

## Verified Mark Certificate

| **Field**                           | **Critical Extension** | **Content** |
| --- | -- | ------ |
| Subject                             |                        | Must contain countryName, localityName, streetAddress, postalCode, trademark country or region name, trademark registration number, markType, jurisdiction country, organizationName, business category and serial number of subscriber |
| Extension: subjectKeyIdentifier     | Not critical           | 160-bit SHA-1 hash of subjectPublicKey per RFC 5280 |
| Extension: authorityKeyIdentifier   | Not critical           | Matches subjectKeyIdentifier of signing certificate |
| Extension: certificatePolicies      | Not critical           | Must contain at least one set of policyInformation containing reserved certificate policy identifier |
| Extension: basicConstraints         | Critical               | Empty or not present |
| Extension: subjectAltName           | Not critical           | Must contain at least one name and all names must either be of type dNSName |
| Extension: certificate transparency | Not critical           | Must include signed certificate timestamp(s) |
| Extension: subjectLogo              | Not critical           | Must contain subjectLogo per RFC 3709 |
| Extension: keyUsage                 | Critical               | digitalSignature bit may be set, other bits should not be set |
| Extension: extKeyUsage              | Not critical           | Must include `id-kp-BrandIndicatorforMessageIdentification` |
| Extension: authorityInfoAccess      | Not critical           | Must contain one AccessDescription with an accessMethod of caIssuers and a Location of type uniformResourceIdentifier and one AccessDescription with an accessMethod of ocsp and a Location of type uniformResourceIdentifier |
| Extension: cRLDistributionPoints    | Not critical           | Must have at least one DistributionPoint containing a fullName of type uniformResourceIdentifier |

## Government Mark Certificate

| **Field**                           | **Critical Extension** | **Content** |
| --- | -- | ------ |
| Subject                             |                        | Must contain countryName, localityName, streetAddress, postalCode, statuteLocalityName (if applicable), statuteStateOrProvinceName(If applicable), statueCountry, statuteCitation, statueURL (optional), markType, jurisdiction country, organizationName, business category and serial number of subscriber |
| Extension: subjectKeyIdentifier     | Not critical           | 160-bit SHA-1 hash of subjectPublicKey per RFC 5280 |
| Extension: authorityKeyIdentifier   | Not critical           | Matches subjectKeyIdentifier of signing certificate |
| Extension: certificatePolicies      | Not critical           | Must contain at least one set of policyInformation containing reserved certificate policy identifier |
| Extension: basicConstraints         | Critical               | Empty or not present |
| Extension: subjectAltName           | Not critical           | Must contain at least one name and all names must either be of type dNSName |
| Extension: certificate transparency | Not critical           | Must include signed certificate timestamp(s) |
| Extension: subjectLogo              | Not critical           | Must contain subjectLogo per RFC 3709 |
| Extension: keyUsage                 | Critical               | digitalSignature bit may be set, other bits should not be set |
| Extension: extKeyUsage              | Not critical           | Must include `id-kp-BrandIndicatorforMessageIdentification` |
| Extension: authorityInfoAccess      | Not critical           | Must contain one AccessDescription with an accessMethod of caIssuers and a Location of type uniformResourceIdentifier and one AccessDescription with an accessMethod of ocsp and a Location of type uniformResourceIdentifier |
| Extension: cRLDistributionPoints    | Not critical           | Must have at least one DistributionPoint containing a fullName of type uniformResourceIdentifier |

## Mark Certificate

| **Field**                                          | **Critical Extension** | **Content** |
| --- | -- | ------ |
| Subject                                            |                        | Modified Registration Mark  <br>Must contain countryName, localityName, streetAddress, postalCode, trademark country or region name, trademark registration number, markType jurisdiction country, organizationName, business category and serial number of subscriber<br><br>Prior Use Mark  <br>Must contain countryName, localityName, streetAddress, postalCode, markType, jurisdiction country, organizationName, business category and serial number of subscriber |
| Extension: subjectKeyIdentifier                    | Not critical           | 160-bit SHA-1 hash of subjectPublicKey per RFC 5280 |
| Extension: authorityKeyIdentifier                  | Not critical           | Matches subjectKeyIdentifier of signing certificate |
| Extension: certificatePolicies                     | Not critical           | Must contain at least one set of policyInformation containing reserved certificate policy identifier |
| Extension: basicConstraints                        | Critical               | Empty or not present |
| Extension: subjectAltName                          | Not critical           | Must contain at least one name and all names must either be of type dNSName |
| Extension: certificate transparency                | Not critical           | Must include signed certificate timestamp(s) |
| Extension: subjectLogo                             | Not critical           | Must contain subjectLogo per RFC 3709 |
| Extension: keyUsage                                | Critical               | digitalSignature bit may be set, other bits should not be set |
| Extension: extKeyUsage                             | Not critical           | Must include `id-kp-BrandIndicatorforMessageIdentification` |
| Extension: authorityInfoAccess                     | Not critical           | Must contain one AccessDescription with an accessMethod of caIssuers and a Location of type uniformResourceIdentifier and one AccessDescription with an accessMethod of ocsp and a Location of type uniformResourceIdentifier |
| Extension: cRLDistributionPoints                   | Not critical           | Must have at least one DistributionPoint containing a fullName of type uniformResourceIdentifier |
| Extension: pilotIdentifier (1.3.6.1.4.1.53087.4.1) | Critical               | UTF8String with value "Mark Certificate" |

# Appendix B - Subordinate CA Certificates

Entrust issues Subordinate CA Certificates to Entrust CAs and third party operated certification authorities.

**Subordinate CAs**

Entrust operated subordinate CAs are managed in accordance with this CPS or are operated in accordance with their own CP and/or CPS which meets the minimum requirements of this CPS.

**Third Party Subordinate CAs**

**Notification**

Before accepting an agreement to issue a Third Party Subordinate CA Certificate, the Entrust will notify the ASVs which distributes the associated Entrust Root CA Certificate.

**Registration**

Entrust specifies requirements to Third Party Subordinate CAs through written agreement. The Third Party Subordinate CAs must make use of a CP and/or CPS which meets the minimum requirements of this CPS.

The generation of the certificate authority Key Pair for the Third Party Subordinate CAs is to be witnessed by a third party security auditor.

A request for a Subordinate CA Certificate is started by the Third Party Subordinate CAs submitting a CSR. The CSR is authenticated by contacting the authorization contact for the Third Party Subordinate CAs.

**Certificate Renewal**

Subordinate CA Certificates issued to a third party may be renewed through mutual agreement. The Subordinate CA Certificate may be renewed using the original CSR which was submitted for the initial registration. If the renewal is performed with a new CSR, then the CSR is authenticated by contacting the authorization contact of the Third Party Subordinate CAs.

**Certificate Rekey**

Third Party Subordinate CA Certificates issued to a third party are rekeyed using a new CSR. The new CSR is authenticated by the authorization contact of the Third Party Subordinate CAs.

**Certificate Issuance**

The Subordinate CA Certificate issued to a third party is issued in accordance with the Subordinate CA Certificate profile defined in Appendix A.

**Certificate Distribution**

The Subordinate CA Certificate issued to a third party may be distributed in accordance with license set out in the written agreement between Entrust and the Subordinate Third Party CA.

**Certificate Revocation**

Entrust confirms Third Party Subordinate CA Certificate revocation requests by contacting the authorization contact of the Third Party Subordinate CAs.

In addition to §4.9.1.2, Entrust may also revoke any Subordinate CA Certificate in accordance with the agreement between Entrust and the Third Party Subordinate CA.

The revocation status will be provided by CRL and/or OCSP.

**CA Assessment**

Third Party Subordinate CAs are assessed to meet the requirements of the CP and/or CPS on an annual basis using one of the audit criteria specified in §8.4.

# Appendix C - VMC Terms of Use ("VMC Terms")

All Mark Asserting Entities (MAEs) are required, as a condition of being issued a Verified Mark Certificate, to agree to these VMC Terms. Any and all use, display, or reliance on any Verified Mark Certificate (and any Design Mark Representation and any other data or information therein) by Consuming Entities, Relying Parties, and any other person, is subject to and conditional upon acceptance of these VMC Terms.  The OID 1.3.6.1.4.1.53087.1.1 in the Verified Mark Certificate incorporates by reference these VMC Terms.  If any person does not agree to these VMC Terms, such person may not obtain, use, publish, or rely upon any Verified Mark Certificate or on any Design Mark Representation or any other data or information in a Verified Mark Certificate.

1. **Definitions.** Capitalized words will have meanings set out in Section 1.6 of the Verified Mark Certificate Requirements.
   
2. **Limited Right to Reproduce and Display.** The MAE hereby grants, subject to the terms, conditions and restrictions in the VMC Guidelines and these VMC Terms:
    1. to the Issuing CA, a limited, non-exclusive, worldwide license to issue a Verified Mark Certificate that contains the VMC Marks and to log said certificate in a limited number of Certificate Transparency Logs as required by the VMC Guidelines; and
    2. to Consuming Entities, a limited, non-exclusive, worldwide license to reproduce, display, and modify as permitted by section 3.1 the VMC Marks only in direct visual association with communications, correspondence, or services authored or provided by the MAE from or through one of the same domains included within the Verified Mark Certificate’s Subject Alternative Name field; and
    3. to certificate transparency log operators if different from the Issuing CA, a limited, non-exclusive, worldwide license to retain a copy of and to reproduce the Verified Mark Certificate to support a durable public record of those issued certificates, and for the purpose of permitting members of the public to audit the verification of Verified Mark Certificates.
 
3. **License Restrictions and Conditions.** Any Consuming Entity that incorporates or intends to incorporate the VMC Marks obtained through an issued and published Verified Mark Certificate into its products and services, agrees that its license to do so is subject to and conditional on the following:
    1. **Quality Control, Same Treatment.**  The Consuming Entity may not distort at display time any Design Mark Representation obtained from a published Verified Mark Certificate, change its colors or background, modify its transparency, or alter it in any way other than to adjust its size or scale, or to crop it in a manner consistent with cropping  performed on other Design Mark Representations displayed in the same context and where after such cropping the entire Design Mark remains visible. If a Consuming Entity displays a Word Mark obtained from a published Verified Mark Certificate, it must do so in a neutral manner applied consistently to all Word Marks from all Verified Mark Certificates that are shown in the same visual context. The Consuming Entity may display a Design Mark included in a Verified Mark Certificate without also displaying a Word Mark included in the same Verified Mark Certificate, but the Consuming Entity may not display a Word Mark included in a Verified Mark Certificate without also displaying the Design Mark included in the same Verified Mark Certificate.
    2. **No Partnership or Relationships implied.**  Subject to an express agreement to the contrary between the Consuming Entity and the MAE, neither the VMC Marks nor any other content of the Verified Mark Certificate may be used or displayed in any way that reasonably implies any relationship between the Consuming Entity and the MAE, beyond the bare licensor-licensee relationship created by these VMC Terms.
    3. **CRL or OCSP Checks.**  Consuming Entities must check the Certificate Revocation Lists maintained by the CA or perform an on-line revocation status check using OCSP to determine whether a Verified Mark Certificate has been revoked no less frequently than every 7 days.  
    4. **Lawful Use.**  Consuming Entities may only use the Design Mark Representation in a Verified Mark Certificate in accordance with applicable law.

4. **Sufficient Ownership or License.**  The MAE warrants that the VMC Marks published via a Verified Mark Certificate represent a Registered Design Mark (and Word Mark, if any) that the MAE owns or for which the MAE has obtained sufficient license to be able to grant the limited license in these VMC Terms, and that it will immediately revoke the Verified Mark Certificate if it no longer owns or has a sufficient license to the applicable Registered Design Mark (or Word Mark, if any).  The MAE will defend and will be liable for any intellectual property or other claims against any Consuming Entity, Relying Party or CA that arise from the content of the MAE’s application for a Verified Mark Certificate.

5. **No obligation to display.** The MAE acknowledges that Consuming Entities are under no obligation to display the VMC Marks in connection with content the MAE publishes that is associated with the domains the MAE owns or controls as a Domain Registrant, even if a communication or message is confirmed to be from the MAE and a suitable VMC Mark can be obtained and safely displayed from the applicable Verified Mark Certificate.  Instead, Consuming Entities may choose to display the VMC Marks in accordance with these VMC Terms, or not display them, at their option.

6. **Termination.** Immediately upon revocation or expiration of the Verified Mark Certificate, the MAE will cease publishing or using the Verified Mark Certificate, and the license granted to Consuming Entities in Section 2.2 above shall terminate.  The license to a Consuming Entity in Section 2.2 above also terminates automatically and immediately upon breach of any provision of these VMC Terms by the Consuming Entity.  Consuming Entities must immediately cease any and all use of the VMC Marks upon termination of the applicable license.

7. **Updates to VMC Guidelines and VMC Terms.**  The VMC Guidelines and VMC Terms may be updated from time to time.  All parties agree that the version of the VMC Guidelines and VMC Terms in effect at the time of issuance of a Verified Mark Certificate shall apply through the date of expiration or revocation of the Verified Mark Certificate (and, for those provisions that by their nature extend beyond the date of expiration or revocation, until the provisions no longer would apply by their terms). It is the responsibility of each entity who obtains, uses, publishes or relies upon a Verified Mark Certificate to review and familiarize itself from time to time with any updated versions of the VMC Guidelines and VMC Terms.
