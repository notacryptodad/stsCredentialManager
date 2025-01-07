import requests
import json
import os
import time
from datetime import datetime, timezone
import logging
from typing import Dict, Optional

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class STSTokenManager:
    def __init__(self, cache_file: str = ".sts_cache.json"):
        """
        Initialize the STS Token Manager
        
        Args:
            cache_file (str): Path to the cache file
        """
        self.cache_file = cache_file
        self.metadata_url = "http://169.254.169.254"
        self.token_ttl = 21600  # 6 hours in seconds
        self.cache = self._load_cache()

    def _load_cache(self) -> Dict:
        """Load cached credentials from file"""
        try:
            if os.path.exists(self.cache_file):
                with open(self.cache_file, 'r') as f:
                    return json.load(f)
        except Exception as e:
            logger.warning(f"Failed to load cache: {e}")
        return {}

    def _save_cache(self, credentials: Dict) -> None:
        """Save credentials to cache file"""
        try:
            with open(self.cache_file, 'w') as f:
                json.dump(credentials, f)
        except Exception as e:
            logger.warning(f"Failed to save cache: {e}")

    def _get_imdsv2_token(self) -> str:
        """Get IMDSv2 token"""
        try:
            response = requests.put(
                f"{self.metadata_url}/latest/api/token",
                headers={"X-aws-ec2-metadata-token-ttl-seconds": str(self.token_ttl)},
                timeout=2
            )
            response.raise_for_status()
            return response.text
        except Exception as e:
            logger.error(f"Failed to get IMDSv2 token: {e}")
            raise

    def _get_role_name(self, token: str) -> str:
        """Get IAM role name from instance metadata"""
        try:
            response = requests.get(
                f"{self.metadata_url}/latest/meta-data/iam/security-credentials/",
                headers={"X-aws-ec2-metadata-token": token},
                timeout=2
            )
            response.raise_for_status()
            return response.text
        except Exception as e:
            logger.error(f"Failed to get role name: {e}")
            raise

    def _get_credentials(self, token: str, role_name: str) -> Dict:
        """Get credentials from instance metadata"""
        try:
            response = requests.get(
                f"{self.metadata_url}/latest/meta-data/iam/security-credentials/{role_name}",
                headers={"X-aws-ec2-metadata-token": token},
                timeout=2
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"Failed to get credentials: {e}")
            raise

    def _are_credentials_valid(self, credentials: Dict) -> bool:
        """Check if cached credentials are still valid"""
        if not credentials:
            return False
        
        try:
            expiration = datetime.strptime(
                credentials['Expiration'],
                '%Y-%m-%dT%H:%M:%SZ'
            ).replace(tzinfo=timezone.utc)
            
            # Add some buffer time (15 minutes) before expiration
            buffer_time = 900  # 15 minutes in seconds
            return datetime.now(timezone.utc).timestamp() + buffer_time < expiration.timestamp()
        except Exception as e:
            logger.warning(f"Failed to check credentials validity: {e}")
            return False

    def get_credentials(self) -> Dict:
        """
        Get STS credentials, using cache if available and valid
        
        Returns:
            Dict containing credentials with keys:
            - AccessKeyId
            - SecretAccessKey
            - Token
            - Expiration
        """
        # Check if we have valid cached credentials
        if self._are_credentials_valid(self.cache):
            logger.info("Using cached credentials")
            return self.cache

        try:
            # Get new credentials
            token = self._get_imdsv2_token()
            role_name = self._get_role_name(token)
            credentials = self._get_credentials(token, role_name)

            # Cache the credentials
            self._save_cache(credentials)
            self.cache = credentials

            return credentials
        except Exception as e:
            logger.error(f"Failed to get new credentials: {e}")
            raise

    def get_environment_vars(self) -> Dict[str, str]:
        """
        Get credentials formatted as environment variables
        
        Returns:
            Dict containing environment variable names and values
        """
        credentials = self.get_credentials()
        return {
            'AWS_ACCESS_KEY_ID': credentials['AccessKeyId'],
            'AWS_SECRET_ACCESS_KEY': credentials['SecretAccessKey'],
            'AWS_SESSION_TOKEN': credentials['Token']
        }

def set_environment_variables(credentials: Dict[str, str]) -> None:
    """Set AWS credentials as environment variables"""
    for key, value in credentials.items():
        os.environ[key] = value

def main():
    # Example usage
    try:
        # Initialize token manager
        sts_manager = STSTokenManager()

        # Get credentials
        credentials = sts_manager.get_credentials()
        logger.info("Retrieved credentials:")
        logger.info(f"Access Key ID: {credentials['AccessKeyId']}")
        logger.info(f"Expiration: {credentials['Expiration']}")

        # Set environment variables
        env_vars = sts_manager.get_environment_vars()
        set_environment_variables(env_vars)
        logger.info("Environment variables set successfully")

        # Verify environment variables
        logger.info(f"AWS_ACCESS_KEY_ID: {os.environ.get('AWS_ACCESS_KEY_ID')}")
        logger.info(f"AWS_SECRET_ACCESS_KEY: {'*' * len(os.environ.get('AWS_SECRET_ACCESS_KEY', ''))}")
        logger.info(f"AWS_SESSION_TOKEN: {'*' * len(os.environ.get('AWS_SESSION_TOKEN', ''))}")

    except Exception as e:
        logger.error(f"Error in main: {e}")
        raise

if __name__ == "__main__":
    main()