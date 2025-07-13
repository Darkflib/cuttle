from sqlalchemy import Column, Integer, String, Boolean, DateTime, func
from sqlalchemy.orm import declarative_base
from datetime import datetime, timezone
from typing import Optional

Base = declarative_base()

class CertDomain(Base):
    __tablename__ = "certdomain"
    
    id = Column(Integer, primary_key=True)
    domain = Column(String, index=True, unique=True, nullable=False)
    enabled = Column(Boolean, default=True, nullable=False)
    state = Column(String, default='unissued', nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(DateTime(timezone=True), 
                        default=lambda: datetime.now(timezone.utc), 
                        onupdate=lambda: datetime.now(timezone.utc),
                        nullable=False)
    last_checked = Column(DateTime(timezone=True), nullable=True)
    last_error = Column(String, nullable=True)

    def __repr__(self):
        return f"<CertDomain(domain={self.domain}, state={self.state}, expires_at={self.expires_at})>"
    
    def is_expired(self) -> bool:
        """
        Check if the certificate is expired.
        
        Returns:
            bool: True if the certificate is expired, False otherwise.
        """
        if self.expires_at:
            return self.expires_at < datetime.now(timezone.utc)
        return False
    
    def is_revoked(self) -> bool:
        """
        Check if the certificate is revoked.
        
        Returns:
            bool: True if the certificate is revoked, False otherwise.
        """
        return self.state == 'revoked'
    
    def is_valid(self) -> bool:
        """
        Check if the certificate is valid.
        
        Returns:
            bool: True if the certificate is valid, False otherwise.
        """
        return self.state == 'issued' and not self.is_expired() and not self.is_revoked()
    
    