# AWS Security Checks
Basic Python scripts for auditing AWS security configurations using boto3.

## Current Checks

- S3 Public Access Block
- S3 Default Encryption
- S3 Versioning

## Usage

aws sso login --profile my-sso
export AWS_PROFILE=my-sso
python3 s3_basic_check.py

Results are exported to s3_report.csv