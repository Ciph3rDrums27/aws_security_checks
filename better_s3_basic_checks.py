import boto3
import csv
import sys
from botocore.exceptions import ClientError, NoCredentialsError

OUTPUT_FILE = "s3_report.csv"


def get_account_identity():
    try:
        sts = boto3.client("sts")
        identity = sts.get_caller_identity()
        return identity["Account"], identity["Arn"]
    except (ClientError, NoCredentialsError):
        print("ERROR: Unable to verify AWS identity. Check credentials or SSO login.")
        sys.exit(1)


def check_public_access_block(s3, bucket_name):
    try:
        pab = s3.get_public_access_block(Bucket=bucket_name)
        config = pab["PublicAccessBlockConfiguration"]
        return "PASS" if all(config.values()) else "FAIL"
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
            return "NOT CONFIGURED"
        return "ERROR"


def check_encryption(s3, bucket_name):
    try:
        s3.get_bucket_encryption(Bucket=bucket_name)
        return "ENABLED"
    except ClientError as e:
        if e.response["Error"]["Code"] == "ServerSideEncryptionConfigurationNotFoundError":
            return "NOT ENABLED"
        return "ERROR"


def check_versioning(s3, bucket_name):
    try:
        versioning = s3.get_bucket_versioning(Bucket=bucket_name)
        return "ENABLED" if versioning.get("Status") == "Enabled" else "NOT ENABLED"
    except ClientError:
        return "ERROR"


def main():
    print("\n=== S3 Security Check ===\n")

    account_id, arn = get_account_identity()
    print(f"Running as: {arn}")
    print(f"AWS Account: {account_id}\n")

    s3 = boto3.client("s3")

    try:
        buckets = s3.list_buckets()["Buckets"]
    except (ClientError, NoCredentialsError):
        print("ERROR: Unable to list S3 buckets.")
        sys.exit(1)

    results = []

    for bucket in buckets:
        name = bucket["Name"]
        print(f"Bucket: {name}")

        public_access = check_public_access_block(s3, name)
        encryption = check_encryption(s3, name)
        versioning = check_versioning(s3, name)

        print(f"  Public Access Block: {public_access}")
        print(f"  Encryption: {encryption}")
        print(f"  Versioning: {versioning}\n")

        results.append([name, public_access, encryption, versioning])

    try:
        with open(OUTPUT_FILE, "w", newline="") as file:
            writer = csv.writer(file)
            writer.writerow(
                ["Bucket Name", "Public Access Block", "Encryption", "Versioning"]
            )
            writer.writerows(results)
    except IOError:
        print("ERROR: Unable to write CSV output.")
        sys.exit(1)

    print(f"Results exported to {OUTPUT_FILE}\n")


if __name__ == "__main__":
    main()