#!/usr/bin/env bash
set -euo pipefail

# One-time AWS infrastructure setup for hop releases.
# Creates an S3 bucket + CloudFront distribution with OAC.

BUCKET="hop-releases"
REGION="us-east-1"

echo "==> Creating S3 bucket: ${BUCKET} in ${REGION}"
aws s3api create-bucket \
  --bucket "${BUCKET}" \
  --region "${REGION}"

echo "==> Blocking public access on bucket"
aws s3api put-public-access-block \
  --bucket "${BUCKET}" \
  --public-access-block-configuration \
    BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true

echo "==> Creating CloudFront Origin Access Control"
OAC_ID=$(aws cloudfront create-origin-access-control \
  --origin-access-control-config \
    "Name=hop-releases-oac,Description=OAC for hop-releases bucket,SigningProtocol=sigv4,SigningBehavior=always,OriginAccessControlOriginType=s3" \
  --query 'OriginAccessControl.Id' --output text)

echo "    OAC ID: ${OAC_ID}"

echo "==> Creating CloudFront distribution"
CALLER_REF="hop-releases-$(date +%s)"
DIST_CONFIG=$(cat <<EOF
{
  "CallerReference": "${CALLER_REF}",
  "Comment": "hop releases CDN",
  "Enabled": true,
  "DefaultCacheBehavior": {
    "TargetOriginId": "hop-s3",
    "ViewerProtocolPolicy": "redirect-to-https",
    "AllowedMethods": {
      "Quantity": 2,
      "Items": ["GET","HEAD"],
      "CachedMethods": { "Quantity": 2, "Items": ["GET","HEAD"] }
    },
    "ForwardedValues": { "QueryString": false, "Cookies": { "Forward": "none" } },
    "MinTTL": 0,
    "DefaultTTL": 86400,
    "MaxTTL": 31536000,
    "Compress": true
  },
  "Origins": {
    "Quantity": 1,
    "Items": [
      {
        "Id": "hop-s3",
        "DomainName": "${BUCKET}.s3.${REGION}.amazonaws.com",
        "OriginAccessControlId": "${OAC_ID}",
        "S3OriginConfig": { "OriginAccessIdentity": "" }
      }
    ]
  },
  "DefaultRootObject": "",
  "PriceClass": "PriceClass_100"
}
EOF
)

DIST_OUTPUT=$(aws cloudfront create-distribution \
  --distribution-config "${DIST_CONFIG}" \
  --query 'Distribution.{Id:Id,Domain:DomainName}' --output json)

DIST_ID=$(echo "${DIST_OUTPUT}" | python3 -c "import sys,json; print(json.load(sys.stdin)['Id'])")
DIST_DOMAIN=$(echo "${DIST_OUTPUT}" | python3 -c "import sys,json; print(json.load(sys.stdin)['Domain'])")

echo "==> Applying bucket policy (grant CloudFront read access)"
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

POLICY=$(cat <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowCloudFrontServicePrincipalReadOnly",
      "Effect": "Allow",
      "Principal": { "Service": "cloudfront.amazonaws.com" },
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::${BUCKET}/*",
      "Condition": {
        "StringEquals": {
          "AWS:SourceArn": "arn:aws:cloudfront::${ACCOUNT_ID}:distribution/${DIST_ID}"
        }
      }
    }
  ]
}
EOF
)

aws s3api put-bucket-policy --bucket "${BUCKET}" --policy "${POLICY}"

echo ""
echo "============================================"
echo " Setup complete!"
echo " CloudFront domain : ${DIST_DOMAIN}"
echo " Distribution ID   : ${DIST_ID}"
echo "============================================"
echo ""
echo "Export these for release.sh:"
echo "  export HOP_CDN_DOMAIN=\"${DIST_DOMAIN}\""
echo "  export HOP_CF_DISTRIBUTION_ID=\"${DIST_ID}\""
