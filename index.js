{
  "fields": [
    {
      "type": "vector",
      "path": "embedding",
      "numDimensions": 1024,
      "similarity": "cosine"
    },
    {
      "type": "filter",
      "path": "metadata.status"
    },
    {
      "type": "filter",
      "path": "metadata.policyDomain"
    },
    {
      "type": "filter",
      "path": "metadata.businessUnit"
    },
    {
      "type": "filter",
      "path": "metadata.jurisdiction"
    }
  ]
}
