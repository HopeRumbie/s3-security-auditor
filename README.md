# S3 Bucket Security Auditor

A Python CLI tool that audits AWS S3 buckets for security misconfigurations and generates a compliance report.

## What It Does
- Checks if public access block is enabled on all buckets
- Scans bucket ACLs for public or unauthorized access
- Detects missing or misconfigured bucket policies
- Generates a timestamped compliance report

## Technologies Used
- Python
- boto3 (AWS SDK)
- AWS S3 & IAM

## How to Run
1. Clone the repo
2. Install dependencies: `pip install boto3`
3. Configure AWS credentials: `aws configure`
4. Run the auditor: `python auditor.py`

## Security Motivation
Built to enforce least-privilege access principles across AWS S3 infrastructure,
complementing IAM role configurations used in CI/CD pipelines.
