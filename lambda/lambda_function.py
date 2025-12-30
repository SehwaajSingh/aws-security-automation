import json
import boto3
import logging
from botocore.exceptions import ClientError

# Initialize clients
s3 = boto3.client('s3')
sns = boto3.client('sns')
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Replace with your SNS topic ARN for notifications
SNS_TOPIC_ARN = 'arn:aws:sns:region:account-id:security-alerts-topic'

def lambda_handler(event, context):
    """
    Lambda to auto-remediate public S3 buckets and objects.
    Triggered by CloudWatch Alarm (metric filter for public S3 changes).
    """
    logger.info(f"Received event: {json.dumps(event)}")
    
    # Extract bucket name from CloudTrail event
    try:
        detail = event.get('detail', {})
        event_name = detail.get('eventName')
        bucket_name = None

        if 'requestParameters' in detail:
            bucket_name = detail['requestParameters'].get('bucketName')

        if not bucket_name:
            logger.warning("Bucket name not found in event. Exiting.")
            return {"status": "no bucket found"}

        remediation_actions = []

        # Step 1: Block public access at bucket level
        try:
            s3.put_public_access_block(
                Bucket=bucket_name,
                PublicAccessBlockConfiguration={
                    'BlockPublicAcls': True,
                    'IgnorePublicAcls': True,
                    'BlockPublicPolicy': True,
                    'RestrictPublicBuckets': True
                }
            )
            remediation_actions.append("Public access blocked at bucket level")
            logger.info(f"Public access blocked for bucket: {bucket_name}")
        except ClientError as e:
            logger.error(f"Error blocking public access for {bucket_name}: {e}")

        # Step 2: Check objects ACLs & remove public access
        try:
            objects = s3.list_objects_v2(Bucket=bucket_name)
            if 'Contents' in objects:
                for obj in objects['Contents']:
                    key = obj['Key']
                    acl = s3.get_object_acl(Bucket=bucket_name, Key=key)
                    grants = acl.get('Grants', [])
                    public_grants = [g for g in grants if g['Grantee'].get('URI') in [
                        'http://acs.amazonaws.com/groups/global/AllUsers',
                        'http://acs.amazonaws.com/groups/global/AuthenticatedUsers'
                    ]]
                    if public_grants:
                        # Remove all grants (except owner)
                        owner = acl['Owner']
                        s3.put_object_acl(
                            Bucket=bucket_name,
                            Key=key,
                            AccessControlPolicy={
                                'Owner': owner,
                                'Grants': [
                                    {'Grantee': owner, 'Permission': 'FULL_CONTROL'}
                                ]
                            }
                        )
                        remediation_actions.append(f"Removed public ACLs from object: {key}")
                        logger.info(f"Removed public ACLs from object: {key}")
        except ClientError as e:
            logger.error(f"Error checking object ACLs for {bucket_name}: {e}")

        # Send SNS Notification
        message = f"Auto-remediation executed for S3 bucket: {bucket_name}\nActions:\n" + "\n".join(remediation_actions)
        sns.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject=f"S3 Auto-Remediation: {bucket_name}",
            Message=message
        )

        logger.info("SNS notification sent.")
        return {"status": "remediation done", "bucket": bucket_name, "actions": remediation_actions}

    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        sns.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject="S3 Auto-Remediation Failed",
            Message=f"Error processing event: {json.dumps(event)}\nException: {str(e)}"
        )
        return {"status": "error", "error": str(e)}
