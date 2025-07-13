"""
Mock implementation of certbot operations for testing certificate lifecycle management.

This module provides mock functions that simulate certbot CLI behavior without actually
interacting with the Let's Encrypt service or making system changes.
"""

import logging
import random
import time
from datetime import datetime, timedelta, timezone
from typing import Dict, Optional, Tuple

logger = logging.getLogger(__name__)

class CertbotMock:
    """
    Mock implementation of certbot operations.
    
    This class simulates the behavior of certbot CLI commands for testing purposes,
    without making actual API calls to Let's Encrypt or modifying the system.
    """
    
    def __init__(self, success_rate: float = 0.9, delay: float = 1.0):
        """
        Initialize the certbot mock.
        
        Args:
            success_rate (float, optional): Probability of successful operations. Defaults to 0.9.
            delay (float, optional): Simulated processing delay in seconds. Defaults to 1.0.
        """
        self.success_rate = success_rate
        self.delay = delay
        self.certs: Dict[str, Dict] = {}
        
    def issue_certificate(self, domain: str) -> Tuple[bool, Optional[str], Optional[datetime]]:
        """
        Simulate issuing a new certificate for a domain.
        
        Args:
            domain (str): The domain to issue a certificate for.
            
        Returns:
            Tuple[bool, Optional[str], Optional[datetime]]: 
                - Success status
                - Error message (if any)
                - Expiration date (if successful)
        """
        logger.info(f"Mock: Issuing certificate for {domain}")
        # Simulate processing time
        time.sleep(self.delay)
        
        # Simulate success/failure based on probability
        if random.random() < self.success_rate:
            # Certificate issued successfully
            expiry = datetime.now(timezone.utc) + timedelta(days=90)
            self.certs[domain] = {
                "status": "issued",
                "expires_at": expiry,
                "issued_at": datetime.now(timezone.utc)
            }
            logger.info(f"Mock: Certificate issued for {domain}, expires {expiry}")
            return True, None, expiry
        else:
            # Failed to issue certificate
            error_msg = f"Mock: Failed to complete challenge for {domain}"
            logger.error(error_msg)
            return False, error_msg, None
    
    def renew_certificate(self, domain: str) -> Tuple[bool, Optional[str], Optional[datetime]]:
        """
        Simulate renewing an existing certificate.
        
        Args:
            domain (str): The domain to renew the certificate for.
            
        Returns:
            Tuple[bool, Optional[str], Optional[datetime]]: 
                - Success status
                - Error message (if any)
                - New expiration date (if successful)
        """
        logger.info(f"Mock: Renewing certificate for {domain}")
        
        # Check if certificate exists
        if domain not in self.certs:
            return False, f"Mock: No certificate found for {domain}", None
        
        # Simulate processing time
        time.sleep(self.delay)
        
        # Simulate success/failure based on probability
        if random.random() < self.success_rate:
            # Certificate renewed successfully
            current_expiry = self.certs[domain]["expires_at"]
            new_expiry = current_expiry + timedelta(days=90)
            self.certs[domain]["expires_at"] = new_expiry
            self.certs[domain]["renewed_at"] = datetime.now(timezone.utc)
            logger.info(f"Mock: Certificate renewed for {domain}, new expiry {new_expiry}")
            return True, None, new_expiry
        else:
            # Failed to renew certificate
            error_msg = f"Mock: Failed to renew certificate for {domain}"
            logger.error(error_msg)
            return False, error_msg, None
    
    def revoke_certificate(self, domain: str) -> Tuple[bool, Optional[str]]:
        """
        Simulate revoking a certificate.
        
        Args:
            domain (str): The domain to revoke the certificate for.
            
        Returns:
            Tuple[bool, Optional[str]]: 
                - Success status
                - Error message (if any)
        """
        logger.info(f"Mock: Revoking certificate for {domain}")
        
        # Check if certificate exists
        if domain not in self.certs:
            return False, f"Mock: No certificate found for {domain}"
        
        # Simulate processing time
        time.sleep(self.delay)
        
        # Simulate success/failure based on probability
        if random.random() < self.success_rate:
            # Certificate revoked successfully
            self.certs[domain]["status"] = "revoked"
            self.certs[domain]["revoked_at"] = datetime.now(timezone.utc)
            logger.info(f"Mock: Certificate revoked for {domain}")
            return True, None
        else:
            # Failed to revoke certificate
            error_msg = f"Mock: Failed to revoke certificate for {domain}"
            logger.error(error_msg)
            return False, error_msg
    
    def check_certificate(self, domain: str) -> Tuple[bool, str, Optional[datetime]]:
        """
        Check the status of a certificate.
        
        Args:
            domain (str): The domain to check.
            
        Returns:
            Tuple[bool, str, Optional[datetime]]: 
                - Whether a valid certificate exists
                - Status string
                - Expiration date (if any)
        """
        logger.info(f"Mock: Checking certificate status for {domain}")
        
        if domain not in self.certs:
            return False, "not_found", None
        
        cert = self.certs[domain]
        if cert["status"] == "revoked":
            return False, "revoked", None
        
        expires_at = cert["expires_at"]
        if expires_at < datetime.now(timezone.utc):
            return False, "expired", expires_at
        
        # Check if certificate is close to expiry (within 30 days)
        if expires_at < datetime.now(timezone.utc) + timedelta(days=30):
            return True, "expiring_soon", expires_at
        
        return True, "valid", expires_at
