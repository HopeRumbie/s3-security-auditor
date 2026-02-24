import boto3
import json
from datetime import datetime

s3 = boto3.client('s3')

def get_all_buckets():
    response = s3.list_buckets()
    return [b['Name'] for b in response['Buckets']]

def check_public_access_block(bucket):
    try:
        response = s3.get_public_access_block(Bucket=bucket)
        config = response['PublicAccessBlockConfiguration']
        all_blocked = all([
            config.get('BlockPublicAcls', False),
            config.get('IgnorePublicAcls', False),
            config.get('BlockPublicPolicy', False),
            config.get('RestrictPublicBuckets', False),
        ])
        return {"status": "PASS" if all_blocked else "FAIL", "details": config}
    except s3.exceptions.NoSuchPublicAccessBlockConfiguration:
        return {"status": "FAIL", "details": "No public access block configured"}
    except Exception as e:
        return {"status": "ERROR", "details": str(e)}

def check_bucket_acl(bucket):
    try:
        response = s3.get_bucket_acl(Bucket=bucket)
        risky_grantees = [
            "http://acs.amazonaws.com/groups/global/AllUsers",
            "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"
        ]
        violations = []
        for grant in response['Grants']:
            grantee = grant.get('Grantee', {})
            uri = grantee.get('URI', '')
            if uri in risky_grantees:
                violations.append(f"{uri} has {grant['Permission']}")
        return {"status": "FAIL" if violations else "PASS", "details": violations or "ACL is private"}
    except Exception as e:
        return {"status": "ERROR", "details": str(e)}

def check_bucket_policy(bucket):
    try:
        s3.get_bucket_policy(Bucket=bucket)
        return {"status": "INFO", "details": "Bucket policy exists — review manually"}
    except s3.exceptions.from_code('NoSuchBucketPolicy'):
        return {"status": "INFO", "details": "No bucket policy attached"}
    except Exception as e:
        return {"status": "ERROR", "details": str(e)}

def audit_bucket(bucket):
    print(f"  Scanning: {bucket}")
    return {
        "bucket": bucket,
        "public_access_block": check_public_access_block(bucket),
        "acl_check": check_bucket_acl(bucket),
        "bucket_policy": check_bucket_policy(bucket),
    }

def generate_report(results):
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filename = f"s3_audit_report_{timestamp}.txt"

    with open(filename, 'w') as f:
        f.write("=" * 60 + "\n")
        f.write("       S3 BUCKET SECURITY AUDIT REPORT\n")
        f.write(f"       Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("=" * 60 + "\n\n")

        pass_count = 0
        fail_count = 0

        for r in results:
            f.write(f"Bucket: {r['bucket']}\n")
            f.write("-" * 40 + "\n")

            for check_name, check in [
                ("Public Access Block", r['public_access_block']),
                ("ACL Check", r['acl_check']),
                ("Bucket Policy", r['bucket_policy']),
            ]:
                status = check['status']
                details = check['details']
                f.write(f"  [{status}] {check_name}: {details}\n")
                if status == "PASS":
                    pass_count += 1
                elif status == "FAIL":
                    fail_count += 1
            f.write("\n")

        f.write("=" * 60 + "\n")
        f.write(f"SUMMARY: {pass_count} checks passed | {fail_count} checks failed\n")
        f.write("=" * 60 + "\n")

    return filename

def main():
    print("\n🔍 S3 Bucket Security Auditor")
    print("================================")
    buckets = get_all_buckets()

    if not buckets:
        print("No buckets found in this AWS account.")
        return

    print(f"Found {len(buckets)} bucket(s). Starting audit...\n")
    results = [audit_bucket(b) for b in buckets]

    report_file = generate_report(results)
    print(f"\n✅ Audit complete! Report saved to: {report_file}")

    # Print summary to terminal
    fails = sum(
        1 for r in results
        for check in [r['public_access_block'], r['acl_check']]
        if check['status'] == "FAIL"
    )
    print(f"⚠️  {fails} potential issue(s) found across {len(buckets)} bucket(s).\n")

if __name__ == "__main__":
    main()