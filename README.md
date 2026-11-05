# python-ai-intrusion-detector

Python application that uses Isolation Forest to find suspicious IP addresses in SSH and firewall (UFW) logs, and uploads the results to Azure Blob Storage.

Exam project in *Programmering og AI*, IT-teknolog 3rd semester, Zealand (2026).

## Setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install scikit-learn pandas pytest azure-storage-blob
```

## Run

```bash
python src/generate_logs.py   # create test logs
python src/model.py           # find suspicious IPs
python src/validate.py        # precision and recall
python src/upload.py          # upload to Azure (needs AZURE_STORAGE_CONNECTION_STRING)
```

Real logs: `python src/model.py <ssh-log> [firewall-log]`

## Tests

```bash
pytest
```
