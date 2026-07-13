from datetime import datetime, timedelta
import hashlib
import random

import pymongo
from pymongo import ASCENDING


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

ATLAS_URI = ""

DATABASE_NAME = "Policy"
COLLECTION_NAME = "chunks"

random.seed(42)


# ---------------------------------------------------------------------------
# MongoDB connection
# ---------------------------------------------------------------------------

client = pymongo.MongoClient(ATLAS_URI)

db = client[DATABASE_NAME]
collection = db[COLLECTION_NAME]


# ---------------------------------------------------------------------------
# Policy definitions
# ---------------------------------------------------------------------------

POLICIES = [
    {
        "policyId": "IAM-001",
        "title": "Identity and Access Management Policy",
        "domain": "Identity & Access Management",
        "owner": "Chief Information Security Officer",
        "businessUnit": "Enterprise IT",
        "jurisdiction": "Global",
        "regulations": ["ISO 27001", "NIST 800-53", "SOC 2"],
        "classification": "Internal",
        "status": "Active",
        "version": "4.2",
        "effectiveDate": datetime(2025, 1, 15),
        "sections": [
            (
                "User Access Provisioning",
                """
                Access to enterprise applications must be provisioned through an
                approved identity-management workflow. Requests must identify the
                user's business role, required permissions, approving manager, and
                application owner. Access may not be granted solely on the basis of
                an email or verbal request. New permissions must follow least-
                privilege principles and remain limited to the functions necessary
                for the user's assigned responsibilities. Provisioning records must
                be retained so that auditors can identify who requested, approved,
                and implemented each access change.
                """
            ),
            (
                "Privileged Access Reviews",
                """
                Privileged and administrative access must be reviewed every ninety
                days by the designated system owner. Each certification must confirm
                that elevated permissions remain appropriate for the individual's
                current duties. Dormant, excessive, shared, or unexplained privileges
                must be removed within five business days. Review evidence must
                include the account, assigned role, approving owner, review date, and
                disposition. Automated certification workflows should be used where
                supported, but the system owner remains accountable for the final
                decision.
                """
            ),
            (
                "Access Termination",
                """
                Access for terminated employees and contractors must be disabled no
                later than the effective time of separation. Human Resources or the
                sponsoring manager must notify the identity-management team through
                the approved termination workflow. Privileged accounts, remote-access
                credentials, application tokens, and physical access badges must be
                included in the termination process. Service accounts owned by the
                departing individual must be reassigned before separation. Completion
                evidence must be recorded and retained for audit purposes.
                """
            ),
            (
                "Segregation of Duties",
                """
                Access roles must be designed to prevent a single individual from
                initiating, approving, and completing a sensitive transaction.
                Conflicting permissions must be identified during provisioning and
                periodic certification. When a conflict cannot be removed because of
                staffing or operational constraints, the business owner must document
                a compensating control, obtain risk approval, and review the exception
                at least quarterly. Financial posting, vendor creation, payment
                approval, and security administration are considered high-risk
                activities requiring segregation.
                """
            ),
            (
                "Service Account Governance",
                """
                Service accounts must have a documented business purpose, technical
                owner, business owner, and defined expiration or review date.
                Interactive login must be disabled unless specifically required.
                Credentials must be stored in an approved secrets-management platform
                and rotated according to the account's risk classification. Service
                accounts may not be shared across unrelated applications. Ownership
                and continued necessity must be reviewed at least every six months.
                Accounts without an identifiable owner must be disabled pending
                investigation.
                """
            ),
        ],
    },

    {
        "policyId": "AUTH-002",
        "title": "Authentication and Password Standard",
        "domain": "Identity & Access Management",
        "owner": "Director of Cybersecurity",
        "businessUnit": "Enterprise IT",
        "jurisdiction": "Global",
        "regulations": ["NIST 800-63", "ISO 27001"],
        "classification": "Internal",
        "status": "Active",
        "version": "3.1",
        "effectiveDate": datetime(2025, 2, 1),
        "sections": [
            (
                "Multi-Factor Authentication",
                """
                Multi-factor authentication is required for privileged access,
                externally accessible applications, remote network connections, and
                systems containing Restricted information. Phishing-resistant
                authentication methods should be used whenever technically supported.
                SMS-based authentication may only be used when stronger factors are
                unavailable and the risk has been documented. Emergency bypasses
                must expire automatically and be reviewed by the security team.
                Authentication failures and repeated factor resets must be logged and
                monitored for suspicious activity.
                """
            ),
            (
                "Password Length and Composition",
                """
                User-created passwords must contain at least fourteen characters.
                Systems should permit long passphrases and must not require arbitrary
                composition rules that cause predictable substitutions. Passwords
                found in commonly breached credential lists must be rejected.
                Passwords may not contain the user's name, account identifier, or
                obvious company references. Applications unable to enforce the
                standard must document the limitation and implement an approved
                compensating control.
                """
            ),
            (
                "Credential Reuse",
                """
                Enterprise credentials must not be reused across personal accounts,
                external websites, development environments, or unrelated business
                applications. Password history controls must prevent reuse of the
                previous twenty-four passwords where technically supported. Default
                vendor credentials must be changed before a system is connected to
                the production network. Suspected credential reuse identified during
                an investigation requires immediate password reset and review of
                associated accounts.
                """
            ),
            (
                "Credential Reset",
                """
                Password and authentication-factor resets require verification of the
                requester's identity using an approved recovery process. Help-desk
                personnel may not rely solely on information that is publicly
                available or easily guessed. High-risk resets, including privileged
                accounts, require additional verification and must generate an alert
                to the account owner. Temporary credentials must expire promptly and
                require replacement at first use.
                """
            ),
            (
                "Authentication Logging",
                """
                Authentication systems must record successful logins, failed attempts,
                account lockouts, factor enrollment, credential resets, and unusual
                geographic or device activity. Logs must include the user identifier,
                timestamp, source address, target system, and outcome. Security
                monitoring must alert on excessive failures, impossible travel,
                repeated factor prompts, and access from blocked regions. Log records
                must be protected from alteration and retained according to the
                security logging standard.
                """
            ),
        ],
    },

    {
        "policyId": "IR-003",
        "title": "Security Incident Response Policy",
        "domain": "Incident Response",
        "owner": "Security Operations Director",
        "businessUnit": "Corporate Security",
        "jurisdiction": "Global",
        "regulations": ["NIST 800-61", "ISO 27001", "SOC 2"],
        "classification": "Internal",
        "status": "Active",
        "version": "5.0",
        "effectiveDate": datetime(2025, 3, 10),
        "sections": [
            (
                "Incident Reporting",
                """
                Employees and contractors must report suspected security incidents
                immediately to the Security Operations Center. Reports should include
                the affected system, observed behavior, approximate time, and any
                actions already taken. Users must not delete files, power off affected
                equipment, or conduct independent investigations unless instructed.
                High-severity incidents must be escalated to the incident commander
                within thirty minutes of confirmation.
                """
            ),
            (
                "Incident Classification",
                """
                Security incidents must be classified according to operational impact,
                data sensitivity, number of affected users, regulatory exposure, and
                likelihood of continued harm. Severity One incidents include active
                compromise of critical systems, confirmed exposure of Restricted data,
                ransomware affecting production, and material disruption of customer
                services. Classification must be reassessed as new evidence becomes
                available.
                """
            ),
            (
                "Containment and Eradication",
                """
                The incident commander is responsible for approving containment
                actions that may affect production services. Containment may include
                isolating endpoints, disabling credentials, blocking network traffic,
                revoking tokens, or suspending third-party integrations. Investigators
                must preserve evidence before destructive remediation whenever
                practical. Eradication activities must address the root cause and
                validate that malicious persistence has been removed.
                """
            ),
            (
                "Regulatory Notification",
                """
                Legal, Privacy, and Compliance teams must evaluate whether an incident
                triggers contractual, regulatory, customer, or government notification
                obligations. The evaluation must consider the type of information
                involved, affected jurisdictions, timing requirements, and evidence of
                misuse. External notifications may only be issued by authorized
                personnel. Decisions and supporting rationale must be documented in
                the incident record.
                """
            ),
            (
                "Post-Incident Review",
                """
                Severity One and Severity Two incidents require a documented
                post-incident review within ten business days of closure. The review
                must identify the root cause, control failures, response effectiveness,
                customer impact, and corrective actions. Each corrective action must
                have an accountable owner and target completion date. Lessons learned
                must be shared with relevant engineering, operations, and governance
                teams.
                """
            ),
        ],
    },

    {
        "policyId": "TPRM-004",
        "title": "Third-Party Risk Management Policy",
        "domain": "Vendor Risk",
        "owner": "Chief Risk Officer",
        "businessUnit": "Risk Management",
        "jurisdiction": "Global",
        "regulations": ["SOC 2", "ISO 27001", "HIPAA"],
        "classification": "Internal",
        "status": "Active",
        "version": "4.5",
        "effectiveDate": datetime(2025, 4, 1),
        "sections": [
            (
                "Vendor Risk Classification",
                """
                Third parties must be assigned a risk tier before contract execution.
                Classification must consider the sensitivity of information accessed,
                integration privileges, transaction volume, operational dependency,
                geographic location, and ability to affect customer services.
                Critical vendors require enhanced due diligence, executive ownership,
                annual reassessment, and documented contingency planning.
                """
            ),
            (
                "Security Due Diligence",
                """
                Vendors that store, process, transmit, or access Confidential or
                Restricted information must complete a security assessment before
                onboarding. Evidence may include a current SOC 2 report, penetration
                test summary, vulnerability-management process, encryption standards,
                incident-response procedures, and business-continuity capabilities.
                Material findings must be remediated or formally accepted before
                production access is approved.
                """
            ),
            (
                "Contractual Security Requirements",
                """
                Contracts with technology and data-processing vendors must define
                minimum security controls, breach-notification timelines, audit rights,
                data-return requirements, subcontractor obligations, and termination
                assistance. Vendors may not materially change the location or purpose
                of data processing without approval. Security terms must be reviewed
                by Legal and Information Security before signature.
                """
            ),
            (
                "Ongoing Vendor Monitoring",
                """
                Critical and high-risk vendors must be monitored throughout the
                relationship. Monitoring may include annual assessments, review of
                assurance reports, external risk signals, breach notifications,
                service-level performance, and remediation status. Significant changes
                in ownership, hosting model, subcontractors, or control environment
                require an out-of-cycle review.
                """
            ),
            (
                "Vendor Offboarding",
                """
                Vendor offboarding must include removal of logical and physical access,
                revocation of integration credentials, return or verified destruction
                of company information, and confirmation that subcontractors have
                completed equivalent actions. Business owners must verify that ongoing
                operational dependencies have been transferred. Evidence of completion
                must be retained with the vendor record.
                """
            ),
        ],
    },

    {
        "policyId": "BCP-005",
        "title": "Business Continuity Management Policy",
        "domain": "Business Continuity",
        "owner": "Chief Operating Officer",
        "businessUnit": "Operations",
        "jurisdiction": "Global",
        "regulations": ["ISO 22301", "SOC 2"],
        "classification": "Internal",
        "status": "Active",
        "version": "3.7",
        "effectiveDate": datetime(2025, 1, 20),
        "sections": [
            (
                "Business Impact Analysis",
                """
                Each critical business function must complete a business impact
                analysis at least annually. The analysis must identify essential
                processes, dependencies, staffing requirements, critical data,
                recovery priorities, maximum tolerable downtime, and financial or
                customer impact. Results must be approved by the responsible business
                leader and used to establish recovery objectives.
                """
            ),
            (
                "Continuity Plans",
                """
                Business units must maintain documented continuity plans for critical
                operations. Plans must define decision authority, alternate procedures,
                communication methods, required personnel, third-party dependencies,
                and minimum technology capabilities. Plans must be accessible during
                an outage and may not rely exclusively on systems likely to be affected
                by the same disruption.
                """
            ),
            (
                "Continuity Testing",
                """
                Critical business-continuity plans must be exercised at least once each
                year. Tests should include realistic scenarios such as facility loss,
                technology outage, workforce disruption, supplier failure, or regional
                emergency. Results must document participants, objectives, observed
                gaps, recovery performance, and corrective actions. Material findings
                must be tracked to closure.
                """
            ),
            (
                "Crisis Communications",
                """
                Crisis communication procedures must identify authorized spokespeople,
                employee notification channels, customer communication processes,
                regulatory contacts, and escalation thresholds. Messages must be
                accurate, coordinated, and approved according to the event's severity.
                Contact information and distribution lists must be reviewed quarterly.
                """
            ),
            (
                "Plan Maintenance",
                """
                Continuity plans must be reviewed whenever significant changes occur
                to systems, staffing, facilities, suppliers, or business processes.
                At minimum, each plan must be formally reviewed once per year. Plan
                owners are responsible for updating recovery procedures and verifying
                that referenced contacts, resources, and dependencies remain current.
                """
            ),
        ],
    },

    {
        "policyId": "DR-006",
        "title": "Disaster Recovery Standard",
        "domain": "Disaster Recovery",
        "owner": "Vice President of Infrastructure",
        "businessUnit": "Enterprise IT",
        "jurisdiction": "Global",
        "regulations": ["ISO 27001", "SOC 2", "NIST 800-34"],
        "classification": "Internal",
        "status": "Active",
        "version": "4.0",
        "effectiveDate": datetime(2025, 2, 15),
        "sections": [
            (
                "Recovery Objectives",
                """
                Production systems must have documented recovery time and recovery
                point objectives based on business impact. System owners and business
                owners must approve the objectives and ensure that architecture,
                backup frequency, replication, and staffing can support them. Recovery
                objectives must be reviewed when system criticality or dependency
                changes.
                """
            ),
            (
                "Recovery Testing",
                """
                Tier One applications must complete a full disaster-recovery exercise
                at least annually. Tier Two applications must test recovery procedures
                at least every eighteen months. Tests must validate restoration of
                application services, data consistency, authentication, integrations,
                monitoring, and user access. Results must include actual recovery time
                and recovery point performance.
                """
            ),
            (
                "Backup Validation",
                """
                Backup jobs must be monitored for completion and failures must be
                investigated promptly. Critical systems require periodic restoration
                tests to confirm that backup data is readable, complete, and usable.
                Successful job status alone is not sufficient evidence of recoverability.
                Restoration evidence must identify the source backup, target
                environment, test date, and validation results.
                """
            ),
            (
                "Alternate Processing",
                """
                Systems requiring high availability must maintain an alternate
                processing capability appropriate to their recovery objective. The
                alternate environment must have sufficient compute, storage, network,
                security controls, and operational access. Recovery procedures must
                define how traffic is redirected and how the primary environment is
                restored after the event.
                """
            ),
            (
                "Disaster Declaration",
                """
                The authority to declare a disaster must be documented and assigned to
                designated technology and business leaders. A declaration decision
                must consider outage duration, scope, customer impact, recovery
                estimates, safety, and dependency failures. Once declared, the
                recovery organization must use established command, communication,
                and escalation procedures.
                """
            ),
        ],
    },

    {
        "policyId": "DATA-007",
        "title": "Data Classification and Handling Policy",
        "domain": "Data Governance",
        "owner": "Chief Data Officer",
        "businessUnit": "Data Management",
        "jurisdiction": "Global",
        "regulations": ["ISO 27001", "GDPR", "HIPAA"],
        "classification": "Internal",
        "status": "Active",
        "version": "6.1",
        "effectiveDate": datetime(2025, 3, 1),
        "sections": [
            (
                "Classification Levels",
                """
                Information must be classified as Public, Internal, Confidential, or
                Restricted based on legal obligations, business sensitivity, and
                potential impact of unauthorized disclosure. Restricted information
                includes regulated health data, authentication secrets, payment-card
                data, and highly sensitive personal information. Data owners are
                responsible for assigning and maintaining classifications.
                """
            ),
            (
                "Handling Requirements",
                """
                Confidential and Restricted information must only be stored in approved
                systems and shared with authorized recipients for legitimate business
                purposes. Restricted information may not be transmitted through
                personal email, consumer file-sharing services, or unmanaged devices.
                Physical copies must be secured when unattended and disposed of using
                approved destruction methods.
                """
            ),
            (
                "Data Labeling",
                """
                Documents, reports, exports, and collaboration spaces containing
                sensitive information should display the applicable classification
                label where supported. Labels must remain attached when information is
                copied or exported. Applications that cannot display labels must use
                alternative controls such as access restrictions, banners, or
                documented handling instructions.
                """
            ),
            (
                "Data Ownership",
                """
                Each authoritative dataset must have an assigned data owner who
                determines classification, access requirements, retention, acceptable
                use, and quality expectations. Data stewards may perform operational
                management, but accountability remains with the owner. Ownership must
                be reviewed when organizational responsibilities or business processes
                change.
                """
            ),
            (
                "Data Disposal",
                """
                Information that has reached the end of its retention period must be
                deleted or destroyed using methods appropriate to its classification.
                Restricted data requires verified secure deletion or certified
                physical destruction. Disposal must be suspended when a legal hold,
                investigation, audit request, or regulatory preservation requirement
                applies.
                """
            ),
        ],
    },

    {
        "policyId": "ENC-008",
        "title": "Encryption and Key Management Standard",
        "domain": "Encryption",
        "owner": "Chief Information Security Officer",
        "businessUnit": "Enterprise IT",
        "jurisdiction": "Global",
        "regulations": ["NIST 800-57", "PCI DSS", "HIPAA"],
        "classification": "Internal",
        "status": "Active",
        "version": "3.8",
        "effectiveDate": datetime(2025, 4, 5),
        "sections": [
            (
                "Encryption in Transit",
                """
                Confidential and Restricted information must be encrypted during
                transmission across public networks and between systems with different
                trust levels. Approved versions of TLS must be used for web services,
                APIs, administrative access, and service-to-service communication.
                Deprecated protocols and weak cipher suites must be disabled.
                Certificate validation may not be bypassed in production.
                """
            ),
            (
                "Encryption at Rest",
                """
                Restricted information must be encrypted while stored in databases,
                object storage, backups, endpoint devices, and removable media.
                Confidential information must be encrypted at rest when required by
                regulation, contract, or risk assessment. Encryption must use approved
                enterprise services and keys must be managed separately from the
                protected data.
                """
            ),
            (
                "Key Rotation",
                """
                Cryptographic keys must be rotated according to their purpose,
                sensitivity, cryptoperiod, and exposure risk. Keys must be rotated
                immediately when compromise is suspected or when personnel with
                administrative access leave the organization. Rotation procedures
                must prevent data loss and maintain the ability to decrypt information
                retained under legal or business requirements.
                """
            ),
            (
                "Key Access",
                """
                Access to production cryptographic keys must be limited to authorized
                services and a small number of administrators with documented
                responsibilities. Key-management actions must require strong
                authentication and be logged. No individual may both approve and
                perform the creation or destruction of a high-value root key without
                an approved exception.
                """
            ),
            (
                "Certificate Management",
                """
                Digital certificates must have an identified owner, approved issuer,
                defined purpose, and monitored expiration date. Automated renewal
                should be used where available. Certificates may not use deprecated
                algorithms or exceed approved validity periods. Expired, compromised,
                or unused certificates must be revoked and removed promptly.
                """
            ),
        ],
    },

    {
        "policyId": "PRIV-009",
        "title": "Privacy and Personal Information Policy",
        "domain": "Data Privacy",
        "owner": "Chief Privacy Officer",
        "businessUnit": "Legal",
        "jurisdiction": "Global",
        "regulations": ["GDPR", "CCPA", "HIPAA"],
        "classification": "Internal",
        "status": "Active",
        "version": "5.4",
        "effectiveDate": datetime(2025, 1, 5),
        "sections": [
            (
                "Purpose Limitation",
                """
                Personal information may only be collected and processed for a
                documented, legitimate business purpose. New uses that are materially
                different from the original purpose require Privacy review and, where
                applicable, updated notice or consent. Personal information may not
                be retained merely because it might be useful in the future.
                """
            ),
            (
                "Data Minimization",
                """
                Applications and business processes must limit collection of personal
                information to the minimum data necessary to perform the approved
                function. Optional fields must be clearly identified. Sensitive
                identifiers should not be copied into logs, free-text fields, test
                environments, or analytics datasets unless specifically required and
                protected.
                """
            ),
            (
                "Individual Rights Requests",
                """
                Requests to access, correct, delete, restrict, or receive a copy of
                personal information must be routed to the Privacy Office. Identity
                must be verified before information is disclosed or changed. Business
                and technology teams must search relevant systems and respond within
                the timeframe established by applicable law.
                """
            ),
            (
                "Cross-Border Transfers",
                """
                Transfers of personal information across national boundaries require
                an approved legal mechanism and appropriate security safeguards.
                Business owners must identify processing locations, recipients, and
                subcontractors before transfer. Changes to hosting region or support
                location require Privacy and Legal review when regulated information
                is involved.
                """
            ),
            (
                "Privacy Impact Assessments",
                """
                A privacy impact assessment is required before launching a system or
                process that uses sensitive personal information, large-scale
                monitoring, automated decision-making, biometric data, or new data-
                sharing arrangements. The assessment must identify purpose, data
                flows, retention, access, risks, and mitigation measures.
                """
            ),
        ],
    },

    {
        "policyId": "AI-010",
        "title": "Artificial Intelligence Governance Policy",
        "domain": "AI Governance",
        "owner": "AI Governance Council",
        "businessUnit": "Enterprise Technology",
        "jurisdiction": "Global",
        "regulations": ["NIST AI RMF", "EU AI Act", "ISO 42001"],
        "classification": "Internal",
        "status": "Active",
        "version": "2.2",
        "effectiveDate": datetime(2025, 5, 1),
        "sections": [
            (
                "AI Use-Case Approval",
                """
                Artificial intelligence use cases must be registered and reviewed
                before production deployment. The review must identify the business
                purpose, model provider, data sources, users, decisions influenced,
                expected benefits, and potential harm. High-impact use cases require
                approval from Security, Privacy, Legal, Risk, and the accountable
                business executive.
                """
            ),
            (
                "Human Oversight",
                """
                AI-generated recommendations or content must not be treated as
                authoritative when they affect legal rights, employment, healthcare,
                safety, financial eligibility, or other material outcomes. Qualified
                personnel must be able to review, challenge, override, and document
                decisions influenced by an AI system. Users must understand the
                system's intended role and limitations.
                """
            ),
            (
                "Model Evaluation",
                """
                AI systems must be evaluated using representative data before
                production release. Evaluation must address accuracy, robustness,
                harmful output, bias, privacy leakage, prompt injection, and failure
                under unusual conditions. Acceptance criteria must be documented and
                approved by the accountable owner. Material model or data changes
                require reevaluation.
                """
            ),
            (
                "Generative AI Data Restrictions",
                """
                Restricted information, authentication secrets, source code, legal
                advice, and confidential customer information may not be submitted to
                unapproved generative AI services. Approved services must have
                contractual and technical controls preventing unauthorized retention
                or model training. Users must validate generated output before using
                it in business decisions or external communications.
                """
            ),
            (
                "AI Monitoring and Retirement",
                """
                Production AI systems must be monitored for performance degradation,
                unexpected behavior, changing data patterns, security events, and
                harmful outcomes. Owners must define thresholds for investigation,
                suspension, rollback, or retirement. Models that are no longer
                supported, understood, or aligned with their approved purpose must be
                removed from service.
                """
            ),
        ],
    },

    {
        "policyId": "SDLC-011",
        "title": "Secure Software Development Policy",
        "domain": "Application Security",
        "owner": "Chief Technology Officer",
        "businessUnit": "Software Engineering",
        "jurisdiction": "Global",
        "regulations": ["NIST SSDF", "OWASP", "SOC 2"],
        "classification": "Internal",
        "status": "Active",
        "version": "4.3",
        "effectiveDate": datetime(2025, 2, 20),
        "sections": [
            (
                "Security Requirements",
                """
                Application teams must identify security and privacy requirements
                during design. Requirements must address authentication, authorization,
                data protection, logging, input validation, availability, and abuse
                cases. Systems processing Confidential or Restricted information
                require a documented threat model before production approval.
                """
            ),
            (
                "Code Review",
                """
                Changes to production source code require peer review before merge.
                Reviewers must assess correctness, security impact, error handling,
                access control, secrets exposure, and test coverage. Authors may not
                approve their own changes. High-risk components require review by a
                developer with relevant security expertise.
                """
            ),
            (
                "Dependency Management",
                """
                Open-source and third-party software dependencies must be inventoried
                and scanned for known vulnerabilities. Applications may not introduce
                unsupported or prohibited components. Critical dependency
                vulnerabilities require immediate assessment and remediation according
                to the vulnerability-management standard. Lock files and approved
                package repositories should be used to improve build integrity.
                """
            ),
            (
                "Security Testing",
                """
                Applications must complete automated security testing appropriate to
                the technology, including static analysis, dependency scanning, secret
                detection, and dynamic testing where applicable. Internet-facing or
                high-risk applications require penetration testing before initial
                release and after material architectural changes.
                """
            ),
            (
                "Production Release",
                """
                Production releases must have documented approval, successful test
                results, rollback instructions, and confirmation that critical
                vulnerabilities are resolved or formally accepted. Security controls
                may not be disabled solely to meet a release date. Emergency releases
                require retrospective review within seventy-two hours.
                """
            ),
        ],
    },

    {
        "policyId": "CHG-012",
        "title": "Technology Change Management Policy",
        "domain": "Change Management",
        "owner": "Vice President of Technology Operations",
        "businessUnit": "Enterprise IT",
        "jurisdiction": "Global",
        "regulations": ["ITIL", "SOC 2", "ISO 27001"],
        "classification": "Internal",
        "status": "Active",
        "version": "3.9",
        "effectiveDate": datetime(2025, 3, 15),
        "sections": [
            (
                "Standard Changes",
                """
                Standard changes must use a documented, repeatable procedure that has
                been reviewed and approved in advance. The procedure must define scope,
                prerequisites, validation steps, rollback actions, and permitted
                implementation windows. Standard-change status must be reviewed
                periodically and withdrawn when the risk or implementation process
                materially changes.
                """
            ),
            (
                "Normal Changes",
                """
                Normal production changes require documented business justification,
                technical assessment, testing evidence, implementation steps, rollback
                planning, and approval before execution. The level of review must be
                proportionate to customer impact, complexity, security risk, and
                recoverability. Implementers may not approve their own high-risk
                changes.
                """
            ),
            (
                "Emergency Changes",
                """
                Emergency changes may be performed when delay would create unacceptable
                operational, security, safety, or compliance risk. The implementer must
                document the reason, obtain available authorization, and preserve
                evidence of testing when practical. Emergency changes require
                retrospective review within seventy-two hours.
                """
            ),
            (
                "Change Validation",
                """
                After implementation, the change owner must verify that the intended
                outcome was achieved and that no unexpected impact occurred.
                Validation should include service health, monitoring, data integrity,
                security controls, and dependent integrations. Failed validation
                requires rollback or formal incident management.
                """
            ),
            (
                "Change Segregation",
                """
                Production access and change responsibilities must be separated where
                practical. Developers should not directly modify production data or
                infrastructure outside approved deployment processes. When separation
                is not feasible, additional logging, peer approval, and post-change
                review must be implemented.
                """
            ),
        ],
    },

    {
        "policyId": "LOG-013",
        "title": "Security Logging and Monitoring Standard",
        "domain": "Security Monitoring",
        "owner": "Security Operations Director",
        "businessUnit": "Corporate Security",
        "jurisdiction": "Global",
        "regulations": ["NIST 800-53", "PCI DSS", "SOC 2"],
        "classification": "Internal",
        "status": "Active",
        "version": "4.1",
        "effectiveDate": datetime(2025, 1, 25),
        "sections": [
            (
                "Required Security Events",
                """
                Systems must log authentication activity, authorization failures,
                administrative actions, configuration changes, security-control
                changes, sensitive-data access, and material application errors.
                Logging must be sufficient to reconstruct significant activity without
                recording unnecessary sensitive content.
                """
            ),
            (
                "Log Content",
                """
                Security logs must include an accurate timestamp, actor or service
                identity, source, target resource, action performed, and outcome.
                Where relevant, logs should include request identifiers and affected
                record identifiers. Passwords, private keys, authentication tokens,
                and full regulated data values must not be written to logs.
                """
            ),
            (
                "Log Retention",
                """
                Security logs must be retained for at least thirteen months unless a
                longer period is required by regulation, contract, investigation, or
                system-specific risk assessment. At least ninety days of high-value
                security logs should remain readily searchable. Archived logs must
                remain protected from unauthorized alteration or deletion.
                """
            ),
            (
                "Alert Monitoring",
                """
                Security monitoring must identify suspicious authentication,
                privilege escalation, malware activity, unusual data movement,
                disabled controls, and access from prohibited sources. Alerts must be
                prioritized according to potential impact and reviewed within defined
                service levels. Repeated false positives must be tuned without
                suppressing legitimate risk.
                """
            ),
            (
                "Time Synchronization",
                """
                Systems generating security events must synchronize time with an
                approved enterprise source. Time-zone handling must be consistent and
                documented. Material clock drift must generate an operational alert
                because inaccurate timestamps can prevent reliable investigation and
                correlation across systems.
                """
            ),
        ],
    },

    {
        "policyId": "RET-014",
        "title": "Records Retention and Disposal Policy",
        "domain": "Records Management",
        "owner": "General Counsel",
        "businessUnit": "Legal",
        "jurisdiction": "United States",
        "regulations": ["SOX", "HIPAA", "Federal Records Requirements"],
        "classification": "Internal",
        "status": "Active",
        "version": "5.2",
        "effectiveDate": datetime(2025, 2, 10),
        "sections": [
            (
                "Retention Schedule",
                """
                Business records must be retained according to the approved enterprise
                retention schedule. Record categories must identify the responsible
                owner, triggering event, retention period, and approved disposition.
                Business units may not retain records indefinitely unless an approved
                legal, regulatory, or operational requirement exists.
                """
            ),
            (
                "Legal Holds",
                """
                Records subject to litigation, investigation, audit, subpoena, or
                regulatory inquiry must be preserved under a legal hold. Normal
                deletion and disposal processes must be suspended for affected
                information. Recipients of a legal-hold notice must acknowledge the
                instruction and preserve relevant records until formally released.
                """
            ),
            (
                "Electronic Records",
                """
                Electronic records must be maintained in approved systems that support
                access control, retention, search, export, and defensible deletion.
                Business records may not be maintained solely in personal mailboxes,
                local drives, or unapproved collaboration tools. Metadata necessary to
                establish authenticity and context must be preserved.
                """
            ),
            (
                "Secure Disposal",
                """
                Records approved for disposal must be destroyed in a manner that
                prevents reconstruction. Electronic information requires secure
                deletion appropriate to the storage technology and classification.
                Paper records containing sensitive information must be shredded or
                processed by an approved destruction provider.
                """
            ),
            (
                "Retention Exceptions",
                """
                Exceptions to the retention schedule require approval from Legal,
                Records Management, and the accountable business owner. Requests must
                identify the affected information, reason, duration, cost, and
                regulatory impact. Exceptions must have an expiration date and be
                reviewed before renewal.
                """
            ),
        ],
    },

    {
        "policyId": "REMOTE-015",
        "title": "Remote Access Security Standard",
        "domain": "Network Security",
        "owner": "Director of Network Security",
        "businessUnit": "Enterprise IT",
        "jurisdiction": "Global",
        "regulations": ["NIST 800-46", "ISO 27001"],
        "classification": "Internal",
        "status": "Active",
        "version": "3.4",
        "effectiveDate": datetime(2025, 4, 15),
        "sections": [
            (
                "Remote Access Authorization",
                """
                Remote access to internal systems must be approved based on business
                need and assigned through an authorized access role. Access must be
                reviewed periodically and removed when no longer required. Privileged
                remote access requires separate authorization and enhanced monitoring.
                """
            ),
            (
                "Managed Devices",
                """
                Remote access to Confidential or Restricted information must use a
                company-managed device unless an approved exception exists. Managed
                devices must have supported operating systems, endpoint protection,
                encryption, screen lock, and current security updates. Devices that
                fail compliance checks may be blocked automatically.
                """
            ),
            (
                "Secure Connections",
                """
                Remote connections must use approved encrypted access services.
                Direct exposure of administrative protocols to the public internet is
                prohibited. Split tunneling must be disabled for high-risk
                administrative sessions unless specifically approved. Session
                activity must be logged and available for security investigation.
                """
            ),
            (
                "Public Network Use",
                """
                Users must exercise caution when connecting from public or untrusted
                networks. Sensitive work should use the approved secure-access service
                and users must avoid unknown charging stations, shared devices, and
                visible display of confidential information. Suspected interception
                or device compromise must be reported immediately.
                """
            ),
            (
                "Remote Session Timeout",
                """
                Remote sessions must automatically lock or disconnect after a defined
                period of inactivity based on system risk. Privileged sessions require
                shorter inactivity limits and reauthentication before resumption.
                Persistent sessions may only be used by approved services with
                compensating monitoring and credential controls.
                """
            ),
        ],
    },

    {
        "policyId": "CLOUD-016",
        "title": "Cloud Security Policy",
        "domain": "Cloud Security",
        "owner": "Cloud Governance Council",
        "businessUnit": "Enterprise Technology",
        "jurisdiction": "Global",
        "regulations": ["CSA CCM", "ISO 27017", "SOC 2"],
        "classification": "Internal",
        "status": "Active",
        "version": "3.0",
        "effectiveDate": datetime(2025, 5, 12),
        "sections": [
            (
                "Approved Cloud Services",
                """
                Business information may only be stored or processed in cloud services
                approved through the enterprise technology and risk-review process.
                Approval must consider data classification, service architecture,
                contractual protections, identity integration, logging, encryption,
                resilience, and exit capability.
                """
            ),
            (
                "Cloud Account Governance",
                """
                Cloud accounts and subscriptions must be created through the approved
                enterprise provisioning process. Each account must have an owner,
                business purpose, billing assignment, environment classification, and
                security baseline. Personal or unmanaged cloud accounts may not be
                used for company workloads.
                """
            ),
            (
                "Cloud Configuration",
                """
                Cloud resources must follow approved configuration baselines.
                Internet exposure, public storage, unrestricted administrative access,
                and disabled logging are prohibited unless explicitly approved.
                Infrastructure-as-code and automated policy enforcement should be used
                to reduce configuration drift.
                """
            ),
            (
                "Cloud Data Protection",
                """
                Cloud-hosted information must be protected according to its
                classification. Restricted information requires encryption, approved
                regional placement, controlled administrative access, logging, backup,
                and documented recovery capabilities. Data may not be copied into
                lower environments without approved masking or de-identification.
                """
            ),
            (
                "Cloud Exit Planning",
                """
                Critical cloud services must have an exit or transition plan addressing
                data export, data deletion, replacement services, contractual
                termination, credential revocation, and operational continuity.
                Proprietary features that materially limit portability must be
                understood and accepted by the accountable business owner.
                """
            ),
        ],
    },

    {
        "policyId": "ENDPOINT-017",
        "title": "Endpoint Security Standard",
        "domain": "Endpoint Security",
        "owner": "Director of Workplace Technology",
        "businessUnit": "Enterprise IT",
        "jurisdiction": "Global",
        "regulations": ["CIS Controls", "NIST 800-53"],
        "classification": "Internal",
        "status": "Active",
        "version": "4.6",
        "effectiveDate": datetime(2025, 1, 30),
        "sections": [
            (
                "Endpoint Protection",
                """
                Company-managed endpoints must run approved anti-malware and endpoint
                detection software. Protection services must remain enabled, current,
                and centrally monitored. Users may not disable or alter endpoint
                controls without authorization. Devices reporting failed protection
                may be isolated from enterprise resources.
                """
            ),
            (
                "Disk Encryption",
                """
                Laptops and portable devices storing or accessing company information
                must use approved full-disk encryption. Recovery keys must be escrowed
                in an authorized management system. Devices lacking encryption may not
                access Restricted information and must be remediated before deployment.
                """
            ),
            (
                "Security Patching",
                """
                Endpoint operating systems and commonly exploited applications must
                receive security updates according to the vulnerability-management
                standard. Critical actively exploited vulnerabilities require
                accelerated remediation. Unsupported software must be removed,
                isolated, or covered by an approved exception.
                """
            ),
            (
                "Local Administrator Access",
                """
                Local administrator rights must be restricted to authorized personnel
                and approved technical use cases. Standard users should operate
                without persistent administrative privilege. Temporary elevation
                should be time-limited, logged, and attributable to an individual.
                Local administrator membership must be reviewed quarterly.
                """
            ),
            (
                "Lost or Stolen Devices",
                """
                Lost or stolen company devices must be reported immediately to the
                service desk and Security Operations Center. The organization may
                remotely lock or erase the device, revoke credentials, and review
                recent access. The user must provide information about location,
                timing, data sensitivity, and whether authentication credentials may
                have been exposed.
                """
            ),
        ],
    },

    {
        "policyId": "VULN-018",
        "title": "Vulnerability Management Policy",
        "domain": "Vulnerability Management",
        "owner": "Director of Cybersecurity",
        "businessUnit": "Corporate Security",
        "jurisdiction": "Global",
        "regulations": ["PCI DSS", "NIST 800-40", "SOC 2"],
        "classification": "Internal",
        "status": "Active",
        "version": "4.4",
        "effectiveDate": datetime(2025, 3, 25),
        "sections": [
            (
                "Vulnerability Scanning",
                """
                Production infrastructure, applications, containers, and cloud
                resources must be scanned for known vulnerabilities at a frequency
                appropriate to their exposure and criticality. Internet-facing assets
                require more frequent scanning. Scan coverage and failures must be
                monitored so unmanaged assets do not remain invisible.
                """
            ),
            (
                "Remediation Timeframes",
                """
                Critical vulnerabilities must be remediated within fifteen calendar
                days unless a shorter period is required because of active
                exploitation or severe exposure. High vulnerabilities must be
                remediated within thirty days, medium vulnerabilities within ninety
                days, and low vulnerabilities according to normal maintenance cycles.
                """
            ),
            (
                "Risk-Based Prioritization",
                """
                Remediation priority must consider exploitability, known active
                exploitation, asset criticality, internet exposure, data sensitivity,
                available compensating controls, and business impact. Severity score
                alone is not sufficient. Security may require accelerated remediation
                when threat intelligence indicates increased risk.
                """
            ),
            (
                "Vulnerability Exceptions",
                """
                Exceptions require a documented business justification, risk
                assessment, compensating controls, accountable owner, and expiration
                date. Critical and high-risk exceptions require Security approval.
                Exceptions must be reviewed before expiration and may be revoked when
                threat conditions materially change.
                """
            ),
            (
                "Penetration Testing",
                """
                Internet-facing and high-risk applications must undergo penetration
                testing before initial production release and after material
                architectural changes. Testing must be performed by qualified
                personnel independent of the development team. Findings must be
                tracked through the vulnerability-management process.
                """
            ),
        ],
    },

    {
        "policyId": "AUP-019",
        "title": "Acceptable Use Policy",
        "domain": "Acceptable Use",
        "owner": "Chief Human Resources Officer",
        "businessUnit": "Human Resources",
        "jurisdiction": "Global",
        "regulations": ["Company Code of Conduct"],
        "classification": "Internal",
        "status": "Active",
        "version": "2.9",
        "effectiveDate": datetime(2025, 1, 1),
        "sections": [
            (
                "Business Use",
                """
                Company systems and information resources are provided primarily for
                authorized business purposes. Limited personal use is permitted when
                it does not interfere with work, consume excessive resources, create
                security risk, or violate law or company policy. Users remain
                responsible for activity performed through their assigned accounts.
                """
            ),
            (
                "Prohibited Activity",
                """
                Users may not use company systems to harass others, conduct illegal
                activity, bypass security controls, introduce malicious software,
                access content without authorization, or operate an unrelated
                commercial enterprise. Attempts to conceal prohibited activity are
                themselves violations of policy.
                """
            ),
            (
                "Software Installation",
                """
                Software may only be installed when it is licensed, supported, and
                approved for business use. Users may not install unauthorized browser
                extensions, peer-to-peer tools, remote-access software, or applications
                that weaken device security. Requests for new software must follow the
                approved technology-review process.
                """
            ),
            (
                "Confidentiality",
                """
                Users must protect confidential company and customer information in
                conversations, screen displays, printed material, collaboration tools,
                and electronic communications. Sensitive information must not be
                discussed in public locations or disclosed to individuals without a
                legitimate need to know.
                """
            ),
            (
                "Monitoring Notice",
                """
                Company systems may be monitored, logged, reviewed, and investigated
                to protect security, ensure compliance, support operations, and meet
                legal obligations. Users should have no expectation that activity on
                company-owned systems is private, subject to applicable law and
                approved privacy controls.
                """
            ),
        ],
    },

    {
        "policyId": "AUDIT-020",
        "title": "Internal Audit and Compliance Policy",
        "domain": "Audit & Compliance",
        "owner": "Chief Audit Executive",
        "businessUnit": "Internal Audit",
        "jurisdiction": "Global",
        "regulations": ["SOX", "SOC 2", "ISO 27001"],
        "classification": "Internal",
        "status": "Active",
        "version": "3.3",
        "effectiveDate": datetime(2025, 4, 20),
        "sections": [
            (
                "Audit Independence",
                """
                Internal Audit must remain independent from the activities it evaluates.
                Auditors may not design, operate, or approve the controls they are
                assigned to assess. The Chief Audit Executive reports functionally to
                the Audit Committee and has unrestricted access to records, personnel,
                systems, and facilities necessary to perform approved work.
                """
            ),
            (
                "Audit Planning",
                """
                The annual audit plan must be risk-based and consider financial,
                operational, technology, regulatory, fraud, cybersecurity, and
                strategic risks. Significant changes in the risk environment may
                require adjustments during the year. The Audit Committee must review
                and approve the plan.
                """
            ),
            (
                "Evidence Retention",
                """
                Audit workpapers must contain sufficient evidence to support findings,
                conclusions, and recommendations. Evidence must be accurate, relevant,
                protected from unauthorized modification, and retained according to
                the audit retention schedule. Sensitive evidence must only be shared
                with authorized recipients.
                """
            ),
            (
                "Finding Management",
                """
                Audit findings must identify the condition, expected control, risk,
                root cause, responsible owner, corrective action, and target date.
                Management must respond within the required timeframe. Overdue or
                disputed high-risk findings must be escalated to executive leadership
                and the Audit Committee.
                """
            ),
            (
                "Compliance Assessments",
                """
                Business and technology owners must support periodic compliance
                assessments by providing complete and accurate evidence. Control
                failures must be evaluated for scope, duration, customer impact, and
                reporting obligations. Remediation plans must address both the
                immediate issue and underlying cause.
                """
            ),
        ],
    },

    # Draft policy included intentionally for metadata-filter demos.
    {
        "policyId": "QUANTUM-021",
        "title": "Post-Quantum Cryptography Readiness Standard",
        "domain": "Encryption",
        "owner": "Enterprise Cryptography Council",
        "businessUnit": "Enterprise Technology",
        "jurisdiction": "Global",
        "regulations": ["NIST Post-Quantum Standards"],
        "classification": "Internal",
        "status": "Draft",
        "version": "0.8",
        "effectiveDate": datetime(2026, 1, 1),
        "sections": [
            (
                "Cryptographic Inventory",
                """
                Technology teams must identify systems, protocols, certificates, keys,
                and data stores that rely on public-key cryptography. The inventory
                should record algorithm, key length, implementation, data sensitivity,
                owner, vendor dependency, and expected system lifetime. Priority must
                be given to information that requires long-term confidentiality.
                """
            ),
            (
                "Migration Prioritization",
                """
                Post-quantum migration planning must prioritize systems based on data
                sensitivity, exposure, cryptographic dependency, upgrade complexity,
                and risk of harvest-now-decrypt-later attacks. Long-lived systems and
                archives containing Restricted information require early assessment.
                """
            ),
            (
                "Algorithm Agility",
                """
                New systems should support cryptographic agility so algorithms and key
                parameters can be changed without redesigning the entire application.
                Protocols, libraries, and certificate processes should avoid hard-coded
                assumptions that prevent future migration to approved post-quantum
                algorithms.
                """
            ),
            (
                "Vendor Readiness",
                """
                Strategic technology vendors must provide information about their
                post-quantum roadmap, supported algorithms, upgrade approach, backward
                compatibility, and expected availability. Vendor commitments must be
                considered during procurement and renewal decisions for long-lived
                platforms.
                """
            ),
            (
                "Transition Testing",
                """
                Post-quantum and hybrid cryptographic approaches must be tested for
                interoperability, performance, key size, certificate size, operational
                support, and failure handling before production use. Testing must not
                weaken current production cryptographic protections.
                """
            ),
        ],
    },
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def clean_text(text: str) -> str:
    return " ".join(text.split())


def make_chunk_id(policy_id: str, section_number: int) -> str:
    return f"{policy_id}-{section_number:03d}"


def make_source_filename(title: str, version: str) -> str:
    cleaned = (
        title.replace("&", "and")
        .replace("/", "_")
        .replace(" ", "_")
    )

    return f"{cleaned}_v{version}.pdf"


def deterministic_page(policy_id: str, section_number: int) -> int:
    digest = hashlib.sha256(
        f"{policy_id}-{section_number}".encode("utf-8")
    ).hexdigest()

    return 3 + (int(digest[:4], 16) % 42)


def create_document(
    policy: dict,
    section_number: int,
    section_name: str,
    section_text: str,
) -> dict:
    effective_date = policy["effectiveDate"]

    return {
        "policyId": policy["policyId"],
        "policyTitle": policy["title"],
        "chunkId": make_chunk_id(
            policy["policyId"],
            section_number
        ),
        "chunkText": clean_text(section_text),
        "metadata": {
            "policyDomain": policy["domain"],
            "policyOwner": policy["owner"],
            "businessUnit": policy["businessUnit"],
            "status": policy["status"],
            "jurisdiction": policy["jurisdiction"],
            "regulation": policy["regulations"],
            "classification": policy["classification"],
            "effectiveDate": effective_date,
            "reviewDate": effective_date + timedelta(days=365),
            "version": policy["version"],
            "section": section_name,
            "sectionNumber": section_number,
            "pageNumber": deterministic_page(
                policy["policyId"],
                section_number
            ),
            "sourceDocument": make_source_filename(
                policy["title"],
                policy["version"]
            ),
        },

        # voyageCranker.py will replace this with a 1024-dimensional vector.
        "embedding": [],
    }


# ---------------------------------------------------------------------------
# Build dataset
# ---------------------------------------------------------------------------

def build_documents() -> list[dict]:
    documents = []

    for policy in POLICIES:
        for section_number, section in enumerate(
            policy["sections"],
            start=1
        ):
            section_name, section_text = section

            documents.append(
                create_document(
                    policy=policy,
                    section_number=section_number,
                    section_name=section_name,
                    section_text=section_text,
                )
            )

    return documents


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def validate_documents(documents: list[dict]) -> None:
    chunk_ids = [document["chunkId"] for document in documents]
    chunk_texts = [document["chunkText"] for document in documents]

    if len(chunk_ids) != len(set(chunk_ids)):
        raise ValueError("Duplicate chunk IDs were generated.")

    if len(chunk_texts) != len(set(chunk_texts)):
        raise ValueError("Duplicate chunk text was generated.")

    for document in documents:
        if not document["chunkText"]:
            raise ValueError(
                f"Empty chunk text: {document['chunkId']}"
            )

        if len(document["chunkText"]) < 150:
            raise ValueError(
                f"Chunk is unexpectedly short: {document['chunkId']}"
            )

        if document["metadata"]["policyDomain"] == "":
            raise ValueError(
                f"Missing policy domain: {document['chunkId']}"
            )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    client.admin.command("ping")

    documents = build_documents()
    validate_documents(documents)

    print(
        f"Deleting existing documents from "
        f"{DATABASE_NAME}.{COLLECTION_NAME}..."
    )

    delete_result = collection.delete_many({})

    print(
        f"Deleted {delete_result.deleted_count} existing documents."
    )

    insert_result = collection.insert_many(
        documents,
        ordered=True
    )

    print(f"Inserted {len(insert_result.inserted_ids)} policy chunks.")

    collection.create_index(
        [("policyId", ASCENDING)],
        name="policy_id_idx"
    )

    collection.create_index(
        [("chunkId", ASCENDING)],
        unique=True,
        name="chunk_id_unique_idx"
    )

    collection.create_index(
        [
            ("metadata.status", ASCENDING),
            ("metadata.policyDomain", ASCENDING),
        ],
        name="status_domain_idx"
    )

    active_count = collection.count_documents({
        "metadata.status": "Active"
    })

    draft_count = collection.count_documents({
        "metadata.status": "Draft"
    })

    distinct_policies = len(
        collection.distinct("policyId")
    )

    distinct_chunks = len(
        collection.distinct("chunkText")
    )

    print()
    print("=" * 72)
    print("POLICY DATASET CREATED")
    print("=" * 72)
    print(f"Policies:               {distinct_policies}")
    print(f"Policy chunks:          {len(documents)}")
    print(f"Distinct chunk text:    {distinct_chunks}")
    print(f"Active chunks:          {active_count}")
    print(f"Draft chunks:           {draft_count}")
    print(f"Database:                {DATABASE_NAME}")
    print(f"Collection:              {COLLECTION_NAME}")
    print("=" * 72)
    print()
    print("Next step:")
    print("  python3 voyageCranker.py")
    print()
    print(
        "The Atlas Vector Search index can remain in place. "
        "Atlas will re-index the replacement documents."
    )


if __name__ == "__main__":
    try:
        main()
    finally:
        client.close()
