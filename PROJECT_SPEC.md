# PROJECT SPECIFICATION: OtonomMCP-External-IdP

> [!NOTE]
> **Deterministic Specification Projection**  
> This document is a deterministic, human-readable projection aggregated from authoritative project-initiation stores. Existing authoritative artifacts remain the sole source of truth; if this file is deleted or lost, it can be faithfully reconstructed.

### Specification Metadata
| Property | Value |
| :--- | :--- |
| **Project ID** | `OtonomMCP-External-IdP` |
| **Specification Revision** | `rev-5` |
| **Projection Status** | **CURRENT** |
| **Generated At** | 2026-10-11T13:41:53.188Z |
| **Semantic Fingerprint** | `8fa9addac72ef25d7e08f2d4be0d4124ffe920cd53ed9375d30f57e805872371` |
| **Pending Human Decisions** | 0 of 0 |

## Table of Contents
1. [Project Identity & Purpose](#1-project-identity--purpose)
2. [Target Users & Actors](#2-target-users--actors)
3. [Scope Boundaries](#3-scope-boundaries)
4. [Functional Requirements](#4-functional-requirements)
5. [Non-Functional Requirements](#5-non-functional-requirements)
6. [Constraints & Assumptions](#6-constraints--assumptions)
7. [Open Questions](#7-open-questions)
8. [Architecture & System Topology](#8-architecture--system-topology)
9. [Technology Decisions & Candidates](#9-technology-decisions--candidates)
10. [Business Rules](#10-business-rules)
11. [Acceptance Criteria](#11-acceptance-criteria)
12. [Risks & Responses](#12-risks--responses)
13. [Human Decision Points](#13-human-decision-points)
14. [Traceability Matrix](#14-traceability-matrix)
15. [Authoritative Source Bindings](#15-authoritative-source-bindings)

## 1. Project Identity & Purpose
- **Project Name:** OtonomMCP-External-IdP
- **Core Purpose:** Develop OtonomMCP-External-IdP: a local self-hosted online web application in TypeScript for external identity provider and biometric WebAuthn approval. Local SQLite relational database for credentials storage. In-scope: Web application interface, WebAuthn Passkey authentication, OtonomMCP approval context inspection, and cryptographic JWT issuance. Performance: latency < 200ms round-trip. Reliability: 10s heartbeat interval. Availability: 99.9% uptime target. Security: 99% token verification rate. Deployment: local self-hosted deployment with < 5s healthcheck response.
- **Desired Outcome:** Functional, tested, production-ready OtonomMCP-External-IdP fulfilling product requirements.
- **Problem Statement:** Problem addressed by OtonomMCP-External-IdP: deliver develop otonommcp-external-idp: a local self-hosted online web application in typescript for external identity provider and biometric webauthn approval. local sqlite relational database for credentials storage. in-scope: web application interface, webauthn passkey authentication, otonommcp approval context inspection, and cryptographic jwt issuance. performance: latency < 200ms round-trip. reliability: 10s heartbeat interval. availability: 99.9% uptime target. security: 99% token verification rate. deployment: local self-hosted deployment with < 5s healthcheck response.
- **Measurable Objective:** Automated test suite passing with zero regressions

## 2. Target Users & Actors
### Primary Users
- End users
- End users and authenticated accounts
### System Actors
- System

## 3. Scope Boundaries
### In-Scope Capabilities & Workflows
**Capabilities:**
- Account Management
- Core Functionality
- Session Reconnection
- Web application interface
**Workflows:**
- Player Reconnection Flow
- User Registration and Authentication
**Platforms:**
- Web / Browser

### Explicit Exclusions (Out of Scope)

### Undecided Scope / Pending Decisions
_None. All scope items have been decided or confirmed._

## 4. Functional Requirements
| Requirement ID | Title | Priority | Status | Source | Description |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `FREQ-0ada55b643c3` | **Session Reconnection** | HIGH | CONFIRMED | PRODUCT_OWNER_DISCOVERY | Handling client disconnects, preserving game state, and re-attaching dropped players. |
| `FREQ-c42d8ee420fd` | **Account Management** | HIGH | CONFIRMED | PRODUCT_OWNER_DISCOVERY | User registration, authentication, profile management, and credential sessions. |
| `FREQ-da14abb226aa` | **Core Functionality** | HIGH | CONFIRMED | PRODUCT_OWNER_DISCOVERY | OtonomMCP harici kimlik sağlayıcısı ve gerçek insan onayı gereksinimlerini karşılamak üzere External IdP projesi. |

## 5. Non-Functional Requirements
### Performance
- Low-latency state synchronization (< 200ms round-trip)
- Low-latency state synchronization (< 200ms)
### Security
- Secure password hashing or OAuth token verification; protection against unauthorized access (99% token verification rate)
### Reliability
- Resilient connection handling with automated heartbeat ping/pong (10s heartbeat interval)
### Availability
- Graceful handling of dropped socket connections (99.9% uptime target)
### Operational Constraints
- Local / Self-Hosted (< 5s healthcheck response)

## 6. Constraints & Assumptions
### Constraints
**Technology Constraints:**
- TypeScript
**Platform Constraints:**
- Web / Browser
**Operational Constraints:**
- Authoritative server architecture with WebSocket or WebTransport real-time channels

### Assumptions
| ID | Statement | Validated | Rationale |
| :--- | :--- | :--- | :--- |
| `ASSUMP-2da159e35377` | Persistence storage expects SQLite relational database | NO | Derived from architecture discovery dataStorageExpectations |

## 7. Open Questions
_No open questions recorded._

## 8. Architecture & System Topology
### Architectural Style & Topology
- **Style:** modular-monolith
- **Application Topology:** modular application
- **Deployment Topology:** Local / Self-Hosted (< 5s healthcheck response)
- **Communication Model:** synchronous RPC / in-process dispatch

### Major System Components
| Component ID | Name | Owning Boundary | Responsibility | Status |
| :--- | :--- | :--- | :--- | :--- |
| `COMP-22EA6AAC` | **Account Component** | Domain Services | User registration, authentication, profile management, and credential sessions. | CONFIRMED |
| `COMP-5291B41E` | **Session Component** | Domain Services | Handling client disconnects, preserving game state, and re-attaching dropped players. | CONFIRMED |
| `COMP-7D854D8C` | **Data Persistence Service** | Persistence & Storage Subsystem | Manages entity persistence, state durability, and query access | CONFIRMED |
| `COMP-85C93D43` | **Core Application Domain** | Core Logic Subsystem | Executes core workflows: Player Reconnection Flow, User Registration and Authentication | CONFIRMED |
| `COMP-A314068B` | **Core Component** | Domain Services | OtonomMCP harici kimlik sağlayıcısı ve gerçek insan onayı gereksinimlerini karşılamak üzere External IdP projesi. | CONFIRMED |

### Data Architecture & Storage Strategy
- **Persistence Strategy:** Durable storage via SQLite relational database
- **Primary Data Store:** SQLite relational database

### API & Communication Architecture
- **HTTP/REST:** NO
- **GraphQL:** NO
- **WebSocket:** NO
- **Internal APIs:** In-process typed service interfaces

### Platform & Environment

### Security Architecture
- **Authentication Architecture:** Secure password hashing or OAuth token verification; protection against unauthorized access (99% token verification rate)
- **Secrets Handling:** Environment variable and secrets store isolation, Zero hardcoded credentials

### External Integrations
_No external integrations defined._

### Deployment Architecture
- **Deployment Model:** Local / Self-Hosted (< 5s healthcheck response)
- **Environments:** development, production, staging, test

## 9. Technology Decisions & Candidates
### Selected / Required Technologies
| Category | Technology | Status | Version | Rationale |
| :--- | :--- | :--- | :--- | :--- |
| PROGRAMMING_LANGUAGE | **TypeScript** | `REQUIRED` | - | Mandated by project technology constraints |

### Technology Candidates & Undecided Options
_No unresolved candidate technologies._

### Key Architecture Decisions
| Decision ID | Area | Status | Question | Selected / Outcome |
| :--- | :--- | :--- | :--- | :--- |
| `ARCH-DEC-001` | STYLE | DECIDED | **What architectural style and subsystem topology will govern the system?** | modular-monolith |
| `ARCH-DEC-002` | DATA | DECIDED | **What primary data storage technology and strategy should be selected?** | SQLite relational database |
| `ARCH-DEC-003` | API | NOT_APPLICABLE | **What communication protocol will expose external and internal interfaces?** | NOT_APPLICABLE |
| `ARCH-DEC-004` | TECH_STACK | CONSTRAINED | **What runtime and programming languages constrain this project?** | TypeScript, TypeScript |
| `ARCH-DEC-005` | PLATFORM | DECIDED | **What target platform and user interface type will this system provide?** | Web / Browser |

## 10. Business Rules
| Rule ID | Title | Category | Priority | Status | Statement |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `BR-369628EF` | **Core Functionality Rule** | DOMAIN_INVARIANT | HIGH | CONFIRMED | OtonomMCP harici kimlik sağlayıcısı ve gerçek insan onayı gereksinimlerini karşılamak üzere External IdP projesi. |
| `BR-48123303` | **Session Reconnection: State re-synchronization must be atomic** | STATE_TRANSITION_RULE | HIGH | CONFIRMED | State re-synchronization must be atomic |
| `BR-66844B72` | **Account Management: User identities must be unique** | DOMAIN_INVARIANT | HIGH | CONFIRMED | User identities must be unique |
| `BR-6F0BEE63` | **Session Reconnection: Disconnected player state must be preser...** | STATE_TRANSITION_RULE | HIGH | CONFIRMED | Disconnected player state must be preserved for defined grace window |
| `BR-A6B69083` | **Account Management: Sessions must be verified** | DOMAIN_INVARIANT | HIGH | CONFIRMED | Sessions must be verified |
| `BR-E9E38F9E` | **Operational Constraint: Authoritative server architect** | LIMIT_RULE | HIGH | CONSTRAINED | Authoritative server architecture with WebSocket or WebTransport real-time channels |

## 11. Acceptance Criteria
| Criterion ID | Title | Type | Priority | Method | Expected Result |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `AC-061590F0` | **OPERATIONALCONSTRAINTS: Measurable Conformance** | OPERATIONAL | HIGH | `AUTOMATED_TEST` | Measured operationalConstraints satisfies Local / Self-Hosted (< 5s healthcheck response) under specified test workload. |
| `AC-3224F567` | **Account Management: Sessions must be verified: Rule Enforcement** | BUSINESS_RULE | HIGH | `AUTOMATED_TEST` | Verification that Sessions must be verified |
| `AC-3815F5B9` | **Session Reconnection: Disconnected player state must be preser...: State Transition Enforcement** | STATE_TRANSITION | HIGH | `AUTOMATED_TEST` | Entity transitions only through approved states; illegal transitions are rejected without corruption. |
| `AC-581780C6` | **SECURITY: Measurable Conformance** | SECURITY | HIGH | `SECURITY_TEST` | Measured security satisfies Secure password hashing or OAuth token verification; protection against unauthorized access (99% token verification rate) under specified test workload. |
| `AC-59D72AD5` | **Operational Constraint: Authoritative server architect: Rule Enforcement** | SECURITY | HIGH | `AUTOMATED_TEST` | System limit enforcement verification for Authoritative server architecture with WebSocket or WebTransport real-time channels |
| `AC-648A5520` | **RELIABILITY: Measurable Conformance** | RELIABILITY | HIGH | `AUTOMATED_TEST` | Measured reliability satisfies Resilient connection handling with automated heartbeat ping/pong (10s heartbeat interval) under specified test workload. |
| `AC-7ED0AA8B` | **Core Functionality: Functional Verification** | FUNCTIONAL | HIGH | `AUTOMATED_TEST` | Observable execution succeeds without error and satisfies 'Core Functionality'. |
| `AC-8D6F007F` | **API: Boundary Verification** | COMPATIBILITY | HIGH | `AUTOMATED_TEST` | Product operates at its boundary as a typed in-process TypeScript module without external HTTP/REST servers or endpoints in conformance with architecture decision 'What communication protocol will expose external and internal interfaces?'. |
| `AC-9E377A57` | **Account Management: User identities must be unique** | FUNCTIONAL | HIGH | `AUTOMATED_TEST` | Observable compliance with requirement rule 'User identities must be unique'. |
| `AC-9F2B307D` | **PERFORMANCE: Measurable Conformance** | PERFORMANCE | HIGH | `PERFORMANCE_TEST` | Measured performance satisfies Low-latency state synchronization (< 200ms round-trip) under specified test workload. |
| `AC-B5FC64D8` | **Session Reconnection: Disconnected player state must be preser...** | STATE_TRANSITION | HIGH | `AUTOMATED_TEST` | Observable compliance with requirement rule 'Disconnected player state must be preserved for defined grace window'. |
| `AC-B9788EC0` | **PERFORMANCE: Measurable Conformance** | PERFORMANCE | HIGH | `PERFORMANCE_TEST` | Measured performance satisfies Low-latency state synchronization (< 200ms) under specified test workload. |
| `AC-C1E2D463` | **Session Reconnection: State re-synchronization must be atomic** | STATE_TRANSITION | HIGH | `AUTOMATED_TEST` | Observable compliance with requirement rule 'State re-synchronization must be atomic'. |
| `AC-C725C33A` | **DATA: Boundary Verification** | DATA | HIGH | `AUTOMATED_TEST` | Product operates at its boundary in conformance with architecture decision 'What primary data storage technology and strategy should be selected?'. |
| `AC-CD87FC51` | **Account Management: User identities must be unique: Rule Enforcement** | BUSINESS_RULE | HIGH | `AUTOMATED_TEST` | Verification that User identities must be unique |
| `AC-D45B8437` | **Core Functionality Rule: Rule Enforcement** | BUSINESS_RULE | HIGH | `AUTOMATED_TEST` | Verification that OtonomMCP harici kimlik sağlayıcısı ve gerçek insan onayı gereksinimlerini karşılamak üzere External IdP projesi. |
| `AC-E2EED789` | **Account Management: Sessions must be verified** | FUNCTIONAL | HIGH | `AUTOMATED_TEST` | Observable compliance with requirement rule 'Sessions must be verified'. |
| `AC-E497EABE` | **Account Management: Functional Verification** | FUNCTIONAL | HIGH | `AUTOMATED_TEST` | Observable execution succeeds without error and satisfies 'Account Management'. |
| `AC-E7AF4CA8` | **PLATFORM: Boundary Verification** | COMPATIBILITY | HIGH | `AUTOMATED_TEST` | Product operates at its boundary in conformance with architecture decision 'What target platform and user interface type will this system provide?'. |
| `AC-EBE718B0` | **Session Reconnection: State re-synchronization must be atomic: State Transition Enforcement** | STATE_TRANSITION | HIGH | `AUTOMATED_TEST` | Entity transitions only through approved states; illegal transitions are rejected without corruption. |
| `AC-F01FDE76` | **AVAILABILITY: Measurable Conformance** | AVAILABILITY | HIGH | `AUTOMATED_TEST` | Measured availability satisfies Graceful handling of dropped socket connections (99.9% uptime target) under specified test workload. |
| `AC-FDFD8BE8` | **Session Reconnection: Functional Verification** | FUNCTIONAL | HIGH | `AUTOMATED_TEST` | Observable execution succeeds without error and satisfies 'Session Reconnection'. |

## 12. Risks & Responses
### Risk Profile Summary
| Metric | Count |
| :--- | :--- |
| **Total Risks** | 3 |
| **Critical Severity** | 0 |
| **High Severity** | 2 |
| **Medium Severity** | 1 |
| **Low Severity** | 0 |
| **Pending Decision Responses** | 0 |

### Risk Register
| Risk ID | Title | Category | Probability | Impact | Severity | Response | Mitigation Strategy |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `RISK-DEPLOYMENT-E8AC023C35B0` | **Platform Constraint: Web / Browser** | DEPLOYMENT | MEDIUM | HIGH | **HIGH** | `MITIGATE` | Enforce platform target compliance checks in CI. |
| `RISK-SCOPE-F0C1F270807F` | **Scope Assumption: Persistence storage expects SQLite relational data** | SCOPE | MEDIUM | MEDIUM | **MEDIUM** | `MONITOR` | Validate assumption with stakeholders during initiation. |
| `RISK-TECHNICAL-5C43B74200E2` | **Discovery Risk: State drift or race conditions during rapid client** | TECHNICAL | MEDIUM | HIGH | **HIGH** | `MITIGATE` | Implement versioned state snapshot and server-authoritative event replay sequence |

## 13. Human Decision Points
> [!IMPORTANT]
> Human Decision Points represent explicit forks in product, technical, or risk direction that require **Product Owner / User** authority. The autonomous system preserves these points faithfully without choosing on the human's behalf.

_No human decision points recorded._

## 14. Traceability Matrix
| Requirement | Business Rules | Acceptance Criteria | Architecture Decisions | Components | Risks |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `FREQ-0ada55b643c3` (Session Reconnection) | BR-48123303, BR-6F0BEE63 | AC-3815F5B9, AC-8D6F007F, AC-B5FC64D8, AC-C1E2D463, AC-C725C33A, AC-E7AF4CA8, AC-EBE718B0, AC-FDFD8BE8 | ARCH-DEC-001, ARCH-DEC-002, ARCH-DEC-003, ARCH-DEC-004, ARCH-DEC-005 | COMP-5291B41E, COMP-85C93D43 | - |
| `FREQ-c42d8ee420fd` (Account Management) | BR-66844B72, BR-A6B69083 | AC-3224F567, AC-8D6F007F, AC-9E377A57, AC-C725C33A, AC-CD87FC51, AC-E2EED789, AC-E497EABE, AC-E7AF4CA8 | ARCH-DEC-001, ARCH-DEC-002, ARCH-DEC-003, ARCH-DEC-004, ARCH-DEC-005 | COMP-22EA6AAC, COMP-85C93D43 | - |
| `FREQ-da14abb226aa` (Core Functionality) | BR-369628EF | AC-7ED0AA8B, AC-8D6F007F, AC-C725C33A, AC-D45B8437, AC-E7AF4CA8 | ARCH-DEC-001, ARCH-DEC-002, ARCH-DEC-003, ARCH-DEC-004, ARCH-DEC-005 | COMP-85C93D43, COMP-A314068B | - |

## 15. Authoritative Source Bindings
The integrity and provenance of this specification projection are guaranteed by strict cryptographic bindings to the following authoritative upstream artifacts:

| Upstream Source | Revision | Cryptographic Fingerprint (SHA-256) |
| :--- | :--- | :--- |
| **Adaptive Discovery (P15-01)** | `rev-8` | `b3ef38e34f35117338b4ace692732eb4e17fbbfbd75886683ddc1a0be9c147f3` |
| **Requirements / Scope (P15-03)** | `rev-5` | `e3227fbba18b03936d4a408645c34dde6dc802bf439fb06679c0d1ddd442d64e` |
| **Architecture / Technology (P15-04)** | `rev-5` | `723ec8d074b24c3c46b12078a50be06f7176fc6bb8702100594c1c95ed869359` |
| **Business Rules (P15-05)** | `rev-5` | `f2ebf27f45471607600379b07b8400254cbf3b2a1b1ceb2c19725fb949123d68` |
| **Acceptance Criteria (P15-06)** | `rev-5` | `362f609529998925079911d781939469c8baeb577a760e8bb0fcecf25128ee8d` |
| **Risks & Human Decision Points (P15-07)** | `rev-5` | `1a617007d98df618a3db5971cfb45f0d165fb7f7d7ccc573873f298cf126e046` |

---
_This document was deterministically projected by AIDM OtonomMCP Project Specification Engine. Semantic Fingerprint: `8fa9addac72ef25d7e08f2d4be0d4124ffe920cd53ed9375d30f57e805872371`._
