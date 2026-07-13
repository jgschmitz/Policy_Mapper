# 🧭 Policy Mapper

> An AI-native Governance, Risk & Compliance (GRC) knowledge platform built on **MongoDB Atlas Vector Search**, **Atlas Native Reranking**, and **Voyage AI**.

Policy Mapper demonstrates how to transform traditional governance documentation into a semantic knowledge base capable of answering natural-language policy questions with traceable evidence.

---

## 🚀 Overview

Organizations often have thousands of pages of governance documentation spread across PDF files, SharePoint sites, Confluence, Word documents, and GRC platforms.

Policy Mapper converts those documents into semantically searchable policy chunks stored directly in MongoDB Atlas.

Instead of keyword searches, users can ask questions like:

> *How often should privileged access be reviewed?*

> *Can I upload customer information into ChatGPT?*

> *What evidence is required before onboarding a critical vendor?*

Policy Mapper retrieves the most relevant governance controls using **Atlas Vector Search**, then improves ranking using **Atlas Native Reranking**.

---

# Architecture

```text
                    Governance Documents
                 (PDF, Word, SharePoint, GRC)
                             │
                             ▼
                  Chunking & Metadata Extraction
                             │
                             ▼
                  Voyage AI Embedding Model
                    voyage-4-large (1024)
                             │
                             ▼
                  MongoDB Atlas Collection
        ┌────────────────────────────────────────┐
        │ chunkText                              │
        │ metadata                               │
        │ embedding                              │
        └────────────────────────────────────────┘
                             │
                    Atlas Vector Search
                             │
                 Top Semantic Candidates
                             │
                 Atlas Native Reranking
                             │
                             ▼
                  Ranked Policy Evidence
```

---

# Features

✅ MongoDB Atlas Vector Search

✅ Atlas Native Reranking

✅ Voyage AI Embeddings

✅ Rich Policy Metadata

✅ Interactive CLI

✅ Semantic Search

✅ Natural Language Questions

✅ Traceable Source Documents

---

# Example Question

```text
How often should privileged access be reviewed?
Who approves new application access?
What happens when an employee leaves the company?
How do we enforce least privilege?
Can service accounts be shared across applications?
```

Output

```text
Identity and Access Management Policy

Section:
Privileged Access Reviews

Privileged and administrative access must be reviewed every ninety days...
```

---

# Repository Structure

```text
POLICY_MAPPER/

├── buildPolicyDataset.py
│      Creates a synthetic enterprise governance corpus
│
├── voyageCranker.py
│      Generates Voyage AI embeddings
│
├── policySearch.py
│      Atlas Vector Search CLI
│
├── policySearch3.py
│      Atlas Vector Search + Native Reranking
│
└── README.md
```

---

# Data Model

Each policy chunk is stored as a single MongoDB document.

```javascript
{
    policyId,
    policyTitle,
    chunkId,

    chunkText,

    metadata: {

        policyDomain,
        businessUnit,
        jurisdiction,

        section,
        version,

        effectiveDate,

        sourceDocument,

        pageNumber,

        status

    },

    embedding: [1024 floats]
}
```

This allows structured metadata filtering and semantic retrieval to operate against the same document.

---

# Search Pipeline

```text
Natural Language Question
            │
            ▼
Voyage Query Embedding
            │
            ▼
MongoDB Atlas Vector Search
            │
            ▼
Top 20 Candidate Policy Chunks
            │
            ▼
Atlas Native Reranking
            │
            ▼
Top 5 Results
```

---

# Example Questions

Identity & Access Management

```
How often should privileged access be reviewed?

How do we enforce least privilege?

Who approves new application access?

What happens when an employee leaves the company?
```

AI Governance

```
Can I upload customer information into ChatGPT?

What approvals are required before deploying generative AI?

Can AI make decisions without human review?
```

Vendor Risk

```
What evidence is required before onboarding a critical vendor?

How often are vendors reassessed?
```

Incident Response

```
What should an employee do if they suspect ransomware?

When are regulators notified?
```

Privacy

```
When is a Privacy Impact Assessment required?

How long can personal information be retained?
```

---

# Running the Demo

## 1. Create the policy corpus

```bash
python3 buildPolicyDataset.py
```

---

## 2. Generate embeddings

```bash
python3 voyageCranker.py
```

---

## 3. Start Policy Mapper

```bash
python3 policySearch3.py
```

---

## 4. Ask questions

```text
Policy question >

How often should privileged access be reviewed?

Can I upload confidential customer information into ChatGPT?

What controls apply before onboarding a vendor?
```

---

# Technology Stack

| Component | Technology |
|------------|------------|
| Database | MongoDB Atlas |
| Semantic Search | Atlas Vector Search |
| Relevance | Atlas Native Reranking |
| Embeddings | Voyage AI (`voyage-4-large`) |
| Language | Python |
| Driver | PyMongo |

---

# Why MongoDB?

Traditional governance systems typically separate operational metadata from AI retrieval pipelines.

Policy Mapper demonstrates a unified architecture where:

- structured metadata
- unstructured policy text
- semantic embeddings
- AI retrieval

all reside inside MongoDB Atlas.

This enables hybrid search, traceable evidence, and AI-native applications without maintaining a separate vector database.

---

# Future Enhancements

- PDF ingestion pipeline
- SharePoint connector
- Confluence connector
- Microsoft Purview integration
- Archer / ServiceNow integration
- Atlas Search hybrid lexical + semantic retrieval
- Agentic policy workflows
- MCP Server
- Atlas Stream Processing for policy updates

---

# License

MIT
