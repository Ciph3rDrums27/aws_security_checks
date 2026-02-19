import boto3
import csv
from botocore.exceptions import ClientError

s3 = boto3.client("s3")

print("\n=== S3 Security Check ===\n")

results = []

try:
    buckets = s3.list_buckets()["Buckets"]
except ClientError as e:
    print(f"Error listing buckets: {e}")
    exit(1)

for bucket in buckets:
    name = bucket["Name"]
    print(f"\nBucket: {name}")

    # Public Access Block
    try:
        pab = s3.get_public_access_block(Bucket=name)
        config = pab["PublicAccessBlockConfiguration"]
        public_access = "PASS" if all(config.values()) else "FAIL"
    except ClientError:
        public_access = "NOT CONFIGURED"

    print(f"  Public Access Block: {public_access}")

    # Encryption
    try:
        s3.get_bucket_encryption(Bucket=name)
        encryption = "ENABLED"
    except ClientError:
        encryption = "NOT ENABLED"

    print(f"  Encryption: {encryption}")

    # Versioning
    try:
        versioning_status = s3.get_bucket_versioning(Bucket=name).get("Status")
        versioning = "ENABLED" if versioning_status == "Enabled" else "NOT ENABLED"
    except ClientError:
        versioning = "ERROR"

    print(f"  Versioning: {versioning}")

    results.append([name, public_access, encryption, versioning])

# Write to CSV
with open("s3_report.csv", "w", newline="") as file:
    writer = csv.writer(file)
    writer.writerow(["Bucket Name", "Public Access Block", "Encryption", "Versioning"])
    writer.writerows(results)

print("\nResults exported to s3_report.csv\n")