import re
from typing import List, Set

class CloudFinder:
    # Regex untuk mencari S3 Buckets dan Google Storage
    S3_REGEX = r'[a-z0-9.-]+\.s3(?:-external-1)?\.amazonaws\.com'
    S3_URI_REGEX = r's3://[a-z0-9.-]+'
    GCP_REGEX = r'storage\.googleapis\.com/[a-z0-9.-]+'

    @staticmethod
    def find_buckets(content: str) -> Set[str]:
        buckets = set()
        buckets.update(re.findall(CloudFinder.S3_REGEX, content))
        buckets.update(re.findall(CloudFinder.S3_URI_REGEX, content))
        buckets.update(re.findall(CloudFinder.GCP_REGEX, content))
        return buckets

