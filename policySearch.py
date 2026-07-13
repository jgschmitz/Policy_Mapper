import sys
import time
from typing import Any

import pymongo
import voyageai
from pymongo.collection import Collection
from pymongo.errors import (
    ConfigurationError,
    ConnectionFailure,
    OperationFailure,
    PyMongoError,
)


# ===========================================================================
# Configuration
# ===========================================================================

ATLAS_URI = ""
VOYAGE_API_KEY = ""

DATABASE_NAME = "Policy"
COLLECTION_NAME = "chunks"

VECTOR_INDEX_NAME = "vector_index"

EMBEDDING_MODEL = "voyage-4-large"
EMBEDDING_DIMENSIONS = 1024

RERANK_MODEL = "rerank-2.5"

# Vector Search retrieves this many documents for reranking.
CANDIDATE_LIMIT = 20
NUM_CANDIDATES = 75

# Reranker returns this many final results to the CLI.
FINAL_LIMIT = 5

# Leave False initially because unfiltered Vector Search is already working.
ACTIVE_ONLY = False


# ===========================================================================
# Clients
# ===========================================================================

mongo_client = pymongo.MongoClient(
    ATLAS_URI,
    serverSelectionTimeoutMS=10_000,
)

database = mongo_client[DATABASE_NAME]
collection: Collection = database[COLLECTION_NAME]

voyage_client = voyageai.Client(
    api_key=VOYAGE_API_KEY
)


# ===========================================================================
# Query embedding
# ===========================================================================

def create_query_embedding(
    question: str
) -> tuple[list[float], float]:
    """
    Convert a natural-language question into a Voyage query embedding.

    Returns:
        query embedding
        Voyage API wall-clock time in milliseconds
    """

    started_at = time.perf_counter()

    response = voyage_client.embed(
        texts=[question],
        model=EMBEDDING_MODEL,
        input_type="query",
        output_dimension=EMBEDDING_DIMENSIONS,
    )

    elapsed_ms = (
        time.perf_counter() - started_at
    ) * 1000

    if not response.embeddings:
        raise RuntimeError(
            "Voyage returned no query embedding."
        )

    embedding = response.embeddings[0]

    if len(embedding) != EMBEDDING_DIMENSIONS:
        raise RuntimeError(
            f"Expected {EMBEDDING_DIMENSIONS} dimensions, "
            f"but Voyage returned {len(embedding)}."
        )

    return embedding, elapsed_ms


# ===========================================================================
# Atlas Vector Search + Native Reranking
# ===========================================================================

def search_and_rerank(
    question: str,
    candidate_limit: int = CANDIDATE_LIMIT,
    final_limit: int = FINAL_LIMIT,
    num_candidates: int = NUM_CANDIDATES,
    active_only: bool = ACTIVE_ONLY,
) -> tuple[list[dict[str, Any]], dict[str, float]]:
    """
    Run Atlas Vector Search followed by native Atlas reranking.
    """

    query_vector, embedding_ms = create_query_embedding(
        question
    )

    vector_search: dict[str, Any] = {
        "index": VECTOR_INDEX_NAME,
        "path": "embedding",
        "queryVector": query_vector,
        "numCandidates": num_candidates,
        "limit": candidate_limit,
    }

    if active_only:
        vector_search["filter"] = {
            "metadata.status": "Active"
        }

    pipeline = [
        # ---------------------------------------------------------------
        # Stage 1: Retrieve high-recall semantic candidates.
        # ---------------------------------------------------------------
        {
            "$vectorSearch": vector_search
        },

        # ---------------------------------------------------------------
        # Stage 2: Preserve the original Vector Search score before
        # $rerank replaces the active score metadata.
        # ---------------------------------------------------------------
        {
            "$addFields": {
                "vectorScore": {
                    "$meta": "vectorSearchScore"
                }
            }
        },

        # ---------------------------------------------------------------
        # Stage 3: Ensure the reranked text field exists and is a string.
        # ---------------------------------------------------------------
        {
            "$match": {
                "chunkText": {
                    "$exists": True,
                    "$type": "string"
                }
            }
        },

        # ---------------------------------------------------------------
        # Stage 4: Rerank the Vector Search candidates.
        # ---------------------------------------------------------------
        {
            "$rerank": {
                "model": RERANK_MODEL,
                "query": {
                    "text": question
                },
                "path": "chunkText",
                "numDocsToRerank": candidate_limit,
            }
        },

        # ---------------------------------------------------------------
        # Stage 5: Capture the reranker score.
        # ---------------------------------------------------------------
        {
            "$addFields": {
                "rerankScore": {
                    "$meta": "score"
                }
            }
        },

        # ---------------------------------------------------------------
        # Stage 6: Return only the highest-ranked final results.
        # ---------------------------------------------------------------
        {
            "$limit": final_limit
        },

        # ---------------------------------------------------------------
        # Stage 7: Exclude the 1024-dimensional vectors from output.
        # ---------------------------------------------------------------
        {
            "$project": {
                "_id": 0,
                "policyId": 1,
                "policyTitle": 1,
                "chunkId": 1,
                "chunkText": 1,
                "metadata": 1,
                "vectorScore": 1,
                "rerankScore": 1,
            }
        },
    ]

    started_at = time.perf_counter()

    results = list(
        collection.aggregate(
            pipeline,
            maxTimeMS=30_000,
        )
    )

    database_round_trip_ms = (
        time.perf_counter() - started_at
    ) * 1000

    timings = {
        "embedding_ms": embedding_ms,
        "database_round_trip_ms": database_round_trip_ms,
        "application_total_ms": (
            embedding_ms + database_round_trip_ms
        ),
    }

    return results, timings


# ===========================================================================
# Optional raw Vector Search mode
# ===========================================================================

def vector_search_only(
    question: str,
    limit: int = FINAL_LIMIT,
    num_candidates: int = NUM_CANDIDATES,
    active_only: bool = ACTIVE_ONLY,
) -> tuple[list[dict[str, Any]], dict[str, float]]:
    """
    Run Vector Search without reranking.

    This is useful for comparing the original vector order against
    the reranked order without modifying any data.
    """

    query_vector, embedding_ms = create_query_embedding(
        question
    )

    vector_search: dict[str, Any] = {
        "index": VECTOR_INDEX_NAME,
        "path": "embedding",
        "queryVector": query_vector,
        "numCandidates": num_candidates,
        "limit": limit,
    }

    if active_only:
        vector_search["filter"] = {
            "metadata.status": "Active"
        }

    pipeline = [
        {
            "$vectorSearch": vector_search
        },
        {
            "$project": {
                "_id": 0,
                "policyId": 1,
                "policyTitle": 1,
                "chunkId": 1,
                "chunkText": 1,
                "metadata": 1,
                "vectorScore": {
                    "$meta": "vectorSearchScore"
                },
            }
        },
    ]

    started_at = time.perf_counter()

    results = list(
        collection.aggregate(
            pipeline,
            maxTimeMS=30_000,
        )
    )

    database_round_trip_ms = (
        time.perf_counter() - started_at
    ) * 1000

    timings = {
        "embedding_ms": embedding_ms,
        "database_round_trip_ms": database_round_trip_ms,
        "application_total_ms": (
            embedding_ms + database_round_trip_ms
        ),
    }

    return results, timings


# ===========================================================================
# Formatting helpers
# ===========================================================================

def format_date(value: Any) -> str:
    if value is None:
        return "N/A"

    if hasattr(value, "strftime"):
        return value.strftime("%Y-%m-%d")

    return str(value)


def shorten(
    text: str,
    maximum_length: int = 600
) -> str:
    clean_text = " ".join(text.split())

    if len(clean_text) <= maximum_length:
        return clean_text

    return (
        clean_text[:maximum_length].rstrip()
        + "..."
    )


def score_change_label(
    vector_rank: Any
) -> str:
    if vector_rank is None:
        return "N/A"

    return str(vector_rank)


# ===========================================================================
# Result display
# ===========================================================================

def print_reranked_results(
    question: str,
    results: list[dict[str, Any]],
    timings: dict[str, float],
) -> None:
    print()
    print("=" * 92)
    print("POLICY MAPPER — ATLAS VECTOR SEARCH + NATIVE RERANKING")
    print("=" * 92)
    print(f"Question:                  {question}")
    print(
        f"Voyage embedding API:      "
        f"{timings['embedding_ms']:.2f} ms"
    )
    print(
        f"MongoDB round trip:        "
        f"{timings['database_round_trip_ms']:.2f} ms"
    )
    print(
        f"Application total:         "
        f"{timings['application_total_ms']:.2f} ms"
    )
    print(f"Vector candidates:         {CANDIDATE_LIMIT}")
    print(f"Final reranked results:    {len(results)}")
    print(f"Reranker model:            {RERANK_MODEL}")
    print("=" * 92)

    if not results:
        print()
        print(
            "No results returned. Confirm Native Reranking is enabled "
            "for the Atlas project and the cluster supports $rerank."
        )
        print()
        return

    for rank, result in enumerate(
        results,
        start=1
    ):
        metadata = result.get("metadata", {})

        vector_score = result.get(
            "vectorScore",
            0.0
        )

        rerank_score = result.get(
            "rerankScore",
            0.0
        )

        print()
        print(
            f"{rank}. "
            f"{result.get('policyTitle', 'Untitled Policy')}"
        )
        print("-" * 92)
        print(f"Vector score:      {vector_score:.6f}")
        print(f"Rerank score:      {rerank_score:.6f}")
        print(
            f"Policy ID:         "
            f"{result.get('policyId', 'N/A')}"
        )
        print(
            f"Chunk ID:          "
            f"{result.get('chunkId', 'N/A')}"
        )
        print(
            f"Section:           "
            f"{metadata.get('section', 'N/A')}"
        )
        print(
            f"Domain:            "
            f"{metadata.get('policyDomain', 'N/A')}"
        )
        print(
            f"Business unit:     "
            f"{metadata.get('businessUnit', 'N/A')}"
        )
        print(
            f"Jurisdiction:      "
            f"{metadata.get('jurisdiction', 'N/A')}"
        )
        print(
            f"Status:            "
            f"{metadata.get('status', 'N/A')}"
        )
        print(
            f"Version:           "
            f"{metadata.get('version', 'N/A')}"
        )
        print(
            f"Effective date:    "
            f"{format_date(metadata.get('effectiveDate'))}"
        )
        print(
            f"Source:            "
            f"{metadata.get('sourceDocument', 'N/A')}, "
            f"page {metadata.get('pageNumber', 'N/A')}"
        )
        print()
        print(
            shorten(
                result.get("chunkText", "")
            )
        )

    print()
    print("=" * 92)


def print_vector_results(
    question: str,
    results: list[dict[str, Any]],
    timings: dict[str, float],
) -> None:
    print()
    print("=" * 92)
    print("POLICY MAPPER — RAW ATLAS VECTOR SEARCH")
    print("=" * 92)
    print(f"Question:                  {question}")
    print(
        f"Voyage embedding API:      "
        f"{timings['embedding_ms']:.2f} ms"
    )
    print(
        f"MongoDB round trip:        "
        f"{timings['database_round_trip_ms']:.2f} ms"
    )
    print(
        f"Application total:         "
        f"{timings['application_total_ms']:.2f} ms"
    )
    print(f"Results:                   {len(results)}")
    print("=" * 92)

    if not results:
        print("\nNo Vector Search results returned.\n")
        return

    for rank, result in enumerate(
        results,
        start=1
    ):
        metadata = result.get("metadata", {})
        vector_score = result.get(
            "vectorScore",
            0.0
        )

        print()
        print(
            f"{rank}. "
            f"{result.get('policyTitle', 'Untitled Policy')}"
        )
        print("-" * 92)
        print(f"Vector score:      {vector_score:.6f}")
        print(
            f"Policy ID:         "
            f"{result.get('policyId', 'N/A')}"
        )
        print(
            f"Section:           "
            f"{metadata.get('section', 'N/A')}"
        )
        print(
            f"Domain:            "
            f"{metadata.get('policyDomain', 'N/A')}"
        )
        print()
        print(
            shorten(
                result.get("chunkText", "")
            )
        )

    print()
    print("=" * 92)


# ===========================================================================
# CLI commands
# ===========================================================================

def print_help() -> None:
    print(
        """
Commands:

  Type a question
      Runs Vector Search followed by Atlas native reranking.

  /vector <question>
      Runs raw Vector Search without reranking.

  /count
      Displays collection and embedding counts.

  /help
      Displays this help.

  /quit
      Exits Policy Mapper.

Examples:

  How often should privileged access be reviewed?

  /vector How often should privileged access be reviewed?

  What evidence must a critical vendor provide before onboarding?

  When is a privacy impact assessment required?

  What controls apply before deploying generative AI?

  How quickly must critical vulnerabilities be remediated?
"""
    )


def print_collection_counts() -> None:
    total = collection.count_documents({})

    embedded = collection.count_documents({
        "embedding.1023": {
            "$exists": True
        }
    })

    active = collection.count_documents({
        "metadata.status": "Active"
    })

    draft = collection.count_documents({
        "metadata.status": "Draft"
    })

    print()
    print(f"Total policy chunks:       {total}")
    print(f"Chunks with 1024 vectors:  {embedded}")
    print(f"Active policy chunks:      {active}")
    print(f"Draft policy chunks:       {draft}")
    print()


# ===========================================================================
# Startup verification
# ===========================================================================

def verify_connections() -> None:
    mongo_client.admin.command("ping")

    document_count = collection.count_documents({})

    if document_count == 0:
        raise RuntimeError(
            f"{DATABASE_NAME}.{COLLECTION_NAME} "
            "contains no documents."
        )

    embedded_count = collection.count_documents({
        "embedding.1023": {
            "$exists": True
        }
    })

    if embedded_count == 0:
        raise RuntimeError(
            "The collection contains no 1024-dimensional embeddings."
        )


# ===========================================================================
# Interactive CLI
# ===========================================================================

def run_interactive_cli() -> None:
    print()
    print("=" * 92)
    print("POLICY MAPPER V3")
    print("MongoDB Atlas Vector Search + Native Reranking + Voyage AI")
    print("=" * 92)
    print(
        f"Collection: {DATABASE_NAME}.{COLLECTION_NAME} | "
        f"Index: {VECTOR_INDEX_NAME}"
    )
    print(
        f"Embedding: {EMBEDDING_MODEL} "
        f"({EMBEDDING_DIMENSIONS} dimensions) | "
        f"Reranker: {RERANK_MODEL}"
    )
    print(
        f"Candidates: {CANDIDATE_LIMIT} | "
        f"Final results: {FINAL_LIMIT}"
    )
    print("Enter /help for commands or /quit to exit.")
    print()

    while True:
        try:
            user_input = input(
                "Policy question > "
            ).strip()

        except (EOFError, KeyboardInterrupt):
            print("\nExiting Policy Mapper.")
            break

        if not user_input:
            continue

        command = user_input.lower()

        if command in {
            "/quit",
            "/exit",
            "quit",
            "exit",
        }:
            print("Exiting Policy Mapper.")
            break

        if command == "/help":
            print_help()
            continue

        if command == "/count":
            print_collection_counts()
            continue

        try:
            if command.startswith("/vector "):
                question = user_input[
                    len("/vector "):
                ].strip()

                if not question:
                    print(
                        "\nEnter a question after /vector.\n"
                    )
                    continue

                results, timings = vector_search_only(
                    question=question
                )

                print_vector_results(
                    question=question,
                    results=results,
                    timings=timings,
                )

            else:
                question = user_input

                results, timings = search_and_rerank(
                    question=question
                )

                print_reranked_results(
                    question=question,
                    results=results,
                    timings=timings,
                )

        except OperationFailure as exc:
            print()
            print("Atlas rejected the query.")
            print(f"Error: {exc}")
            print()

            error_text = str(exc).lower()

            if "rerank" in error_text:
                print(
                    "Confirm the cluster is running MongoDB 8.3+ "
                    "and Native Reranking is enabled in Atlas "
                    "Project Settings."
                )
            elif "index" in error_text:
                print(
                    f"Confirm that '{VECTOR_INDEX_NAME}' exists "
                    "and is active on Policy.chunks."
                )

            print()

        except Exception as exc:
            print()
            print(f"Search failed: {exc}")
            print()


# ===========================================================================
# Main
# ===========================================================================

def main() -> None:
    if not ATLAS_URI:
        print("Add your Atlas URI to ATLAS_URI.")
        sys.exit(1)

    if not VOYAGE_API_KEY:
        print(
            "Add your Voyage API key to VOYAGE_API_KEY."
        )
        sys.exit(1)

    try:
        verify_connections()
        run_interactive_cli()

    except (
        ConnectionFailure,
        ConfigurationError,
    ) as exc:
        print(
            f"Could not connect to MongoDB Atlas: {exc}"
        )
        sys.exit(1)

    except PyMongoError as exc:
        print(f"MongoDB error: {exc}")
        sys.exit(1)

    except RuntimeError as exc:
        print(f"Startup validation failed: {exc}")
        sys.exit(1)

    finally:
        mongo_client.close()


if __name__ == "__main__":
    main()
