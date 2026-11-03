"""Upload the results to Azure Blob Storage.

Run from the project folder (after src/model.py and src/validate.py):  python src/upload.py

The connection string is NOT in the code. It is read from the environment variable
AZURE_STORAGE_CONNECTION_STRING, so it never ends up on GitHub.
"""
import os
from pathlib import Path

from azure.storage.blob import BlobServiceClient

CONTAINER_NAME = "results"
FILES_TO_UPLOAD = ["data/results.csv", "data/validation.csv"]


def get_connection_string():
    """Read the secret connection string from the environment, or stop with a clear message."""
    connection_string = os.environ.get("AZURE_STORAGE_CONNECTION_STRING")
    if not connection_string:
        raise SystemExit("Missing AZURE_STORAGE_CONNECTION_STRING. "
                         "Run: export AZURE_STORAGE_CONNECTION_STRING=\"...\"")
    return connection_string


def upload_file(service, path):
    """Upload one local file to the container. An existing file with the same name is replaced."""
    blob = service.get_blob_client(container=CONTAINER_NAME, blob=Path(path).name)
    with open(path, "rb") as f:   # "rb" = read the file as raw bytes
        blob.upload_blob(f, overwrite=True)
    print(f"Uploaded {path} -> container '{CONTAINER_NAME}'")


def main():
    service = BlobServiceClient.from_connection_string(get_connection_string())
    for path in FILES_TO_UPLOAD:
        upload_file(service, path)


if __name__ == "__main__":
    main()
