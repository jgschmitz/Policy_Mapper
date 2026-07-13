import pymongo
import voyageai
from pymongo import UpdateOne

client = pymongo.MongoClient(
    ""
)

db = client["Policy"]
collection = db["chunks"]

voyage_client = voyageai.Client(
    api_key=""
)

MODEL = "voyage-4-large"
DIMENSIONS = 1024
BATCH_SIZE = 64


def embed_policy_chunks():
    documents = list(
        collection.find(
            {},
            {
                "_id": 1,
                "chunkText": 1
            }
        )
    )

    print(f"Found {len(documents)} policy chunks.")

    total_updated = 0

    for start in range(0, len(documents), BATCH_SIZE):
        batch = documents[start:start + BATCH_SIZE]

        texts = [
            document["chunkText"]
            for document in batch
        ]

        response = voyage_client.embed(
            texts=texts,
            model=MODEL,
            input_type="document",
            output_dimension=DIMENSIONS
        )

        updates = []

        for document, embedding in zip(batch, response.embeddings):
            updates.append(
                UpdateOne(
                    {"_id": document["_id"]},
                    {
                        "$set": {
                            "embedding": embedding,
                            "embeddingMetadata": {
                                "model": MODEL,
                                "dimensions": DIMENSIONS,
                                "inputType": "document"
                            }
                        }
                    }
                )
            )

        result = collection.bulk_write(updates)

        total_updated += result.modified_count

        print(
            f"Embedded {min(start + BATCH_SIZE, len(documents))}"
            f"/{len(documents)} chunks."
        )

    print(f"Finished. Updated {total_updated} policy chunks.")


if __name__ == "__main__":
    embed_policy_chunks()
