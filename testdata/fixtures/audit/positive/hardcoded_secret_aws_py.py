# seeded defect: AWS access key ID hardcoded (value is fake)
AWS_ACCESS_KEY_ID = "AKIAFAKEFAKEFAKEFAKE"


def build_client():
    import boto3

    return boto3.client("s3", aws_access_key_id=AWS_ACCESS_KEY_ID)
