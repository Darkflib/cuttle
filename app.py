"""
Certificate Lifecycle Management API using FastAPI and Finite State Machine.

This module implements a REST API for managing SSL/TLS certificates through their 
lifecycle using a finite state machine (FSM) approach. It tracks certificate states 
such as unissued, requesting, validating, issued, and handles transitions between states.

The API uses FastAPI for the web framework and SQLAlchemy for database interactions.
"""

import logging
from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks
from datetime import datetime, timezone
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.future import select
from transitions import Machine
from models import CertDomain  # Assuming models.py is in the same directory
from certbot_mock import CertbotMock

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

app = FastAPI(title="CertFSM Dashboard")
engine = create_engine("sqlite:///certfsm.db")

# Initialize certbot mock for testing
certbot = CertbotMock(success_rate=0.9, delay=1.0)

def init_db():
    """
    Initialize the database by creating all tables defined in the models.
    
    This function creates the database schema based on the SQLAlchemy models.
    """
    CertDomain.metadata.create_all(engine)


SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def get_session():
    """
    Create a new database session for dependency injection.
    
    Yields:
        Session: SQLAlchemy database session that will be automatically closed after use.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# FSM states
FSM_STATES = ['unissued', 'requesting', 'validating', 'issued', 'renewing', 'renewed', 'failed', 'expired', 'revoked', 'invalid']
FSM_TRANSITIONS = [
    {"trigger": "request_cert", "source": "unissued", "dest": "requesting"},
    {"trigger": "validate_ok", "source": "validating", "dest": "issued"},
    {"trigger": "request_renewal", "source": "issued", "dest": "renewing"},
    {"trigger": "renew_success", "source": "renewing", "dest": "renewed"},
    {"trigger": "expired_detected", "source": "issued", "dest": "expired"},
    {"trigger": "manual_revoke", "source": "*", "dest": "revoked"},
    {"trigger": "invalidate", "source": "*", "dest": "invalid"},
    {"trigger": "continue_cycle", "source": "renewed", "dest": "issued"}
]

# Certbot operation helper functions
async def perform_certificate_issuance(domain: str, background_tasks: BackgroundTasks, session: Session):
    """
    Perform certificate issuance operation using certbot mock.
    
    Args:
        domain (str): Domain name to issue certificate for
        background_tasks (BackgroundTasks): FastAPI background tasks object
        session (Session): Database session
    """
    logger.info(f"Starting certificate issuance process for {domain}")
    
    # Get domain record
    entry = session.execute(select(CertDomain).where(CertDomain.domain == domain)).scalar_one_or_none()
    if not entry:
        logger.error(f"Domain {domain} not found in database")
        return
    
    # Update state to requesting
    setattr(entry, "state", "requesting")
    setattr(entry, "updated_at", datetime.now(timezone.utc))
    session.add(entry)
    session.commit()
    
    # Perform mock certbot operation
    success, error_msg, expires_at = certbot.issue_certificate(domain)
    
    # Update database based on result
    if success:
        setattr(entry, "state", "issued")
        setattr(entry, "expires_at", expires_at)
        setattr(entry, "last_error", None)
    else:
        setattr(entry, "state", "failed")
        setattr(entry, "last_error", error_msg)
    
    setattr(entry, "last_checked", datetime.now(timezone.utc))
    setattr(entry, "updated_at", datetime.now(timezone.utc))
    session.add(entry)
    session.commit()
    logger.info(f"Certificate issuance for {domain} completed with status: {entry.state}")


async def perform_certificate_renewal(domain: str, background_tasks: BackgroundTasks, session: Session):
    """
    Perform certificate renewal operation using certbot mock.
    
    Args:
        domain (str): Domain name to renew certificate for
        background_tasks (BackgroundTasks): FastAPI background tasks object
        session (Session): Database session
    """
    logger.info(f"Starting certificate renewal process for {domain}")
    
    # Get domain record
    entry = session.execute(select(CertDomain).where(CertDomain.domain == domain)).scalar_one_or_none()
    if not entry:
        logger.error(f"Domain {domain} not found in database")
        return
    
    # Update state to renewing
    setattr(entry, "state", "renewing")
    setattr(entry, "updated_at", datetime.now(timezone.utc))
    session.add(entry)
    session.commit()
    
    # Perform mock certbot operation
    success, error_msg, expires_at = certbot.renew_certificate(domain)
    
    # Update database based on result
    if success:
        setattr(entry, "state", "renewed")
        setattr(entry, "expires_at", expires_at)
        setattr(entry, "last_error", None)
    else:
        setattr(entry, "state", "failed")
        setattr(entry, "last_error", error_msg)
    
    setattr(entry, "last_checked", datetime.now(timezone.utc))
    setattr(entry, "updated_at", datetime.now(timezone.utc))
    session.add(entry)
    session.commit()
    logger.info(f"Certificate renewal for {domain} completed with status: {entry.state}")


async def perform_certificate_revocation(domain: str, background_tasks: BackgroundTasks, session: Session):
    """
    Perform certificate revocation operation using certbot mock.
    
    Args:
        domain (str): Domain name to revoke certificate for
        background_tasks (BackgroundTasks): FastAPI background tasks object
        session (Session): Database session
    """
    logger.info(f"Starting certificate revocation process for {domain}")
    
    # Get domain record
    entry = session.execute(select(CertDomain).where(CertDomain.domain == domain)).scalar_one_or_none()
    if not entry:
        logger.error(f"Domain {domain} not found in database")
        return
    
    # Perform mock certbot operation
    success, error_msg = certbot.revoke_certificate(domain)
    
    # Update database based on result
    if success:
        setattr(entry, "state", "revoked")
        setattr(entry, "last_error", None)
    else:
        setattr(entry, "state", "failed")
        setattr(entry, "last_error", error_msg)
    
    setattr(entry, "last_checked", datetime.now(timezone.utc))
    setattr(entry, "updated_at", datetime.now(timezone.utc))
    session.add(entry)
    session.commit()
    logger.info(f"Certificate revocation for {domain} completed with status: {entry.state}")


async def check_certificate_status(domain: str, session: Session):
    """
    Check certificate status using certbot mock.
    
    Args:
        domain (str): Domain name to check certificate for
        session (Session): Database session
    
    Returns:
        dict: Status information about the certificate
    """
    logger.info(f"Checking certificate status for {domain}")
    
    # Get domain record
    entry = session.execute(select(CertDomain).where(CertDomain.domain == domain)).scalar_one_or_none()
    if not entry:
        logger.error(f"Domain {domain} not found in database")
        return {"status": "error", "message": "Domain not found"}
    
    # Perform mock certbot check
    is_valid, status, expires_at = certbot.check_certificate(domain)
    
    # Update database based on result
    setattr(entry, "last_checked", datetime.now(timezone.utc))
    
    if status == "expired" and str(entry.state) != "expired":
        setattr(entry, "state", "expired")
        setattr(entry, "updated_at", datetime.now(timezone.utc))
    
    if expires_at:
        setattr(entry, "expires_at", expires_at)
    
    session.add(entry)
    session.commit()
    
    return {
        "domain": domain,
        "is_valid": is_valid,
        "status": status,
        "expires_at": expires_at.isoformat() if expires_at else None,
        "state": entry.state
    }

# Root route
@app.get("/")
def root():
    """
    Root endpoint that provides basic API information.
    
    Returns:
        dict: Basic information about the API including version and status.
    """
    return {"message": "Welcome to the CertFSM Dashboard", "version": "1.0.0", "status": "running", "documentation": "/docs"}

# Health check endpoint
@app.get("/health")
def health_check():
    """
    Health check endpoint for monitoring and readiness probes.
    
    Returns:
        dict: Status information for service health monitoring.
    """
    return {"status": "ok"}

# Get FSM states
@app.get("/fsm/states")
def get_fsm_states():
    """
    Get all possible states for the certificate lifecycle FSM.
    
    This endpoint returns all possible states a domain certificate can be in,
    which is useful for frontend UI components like dropdowns or status displays.
    
    Returns:
        dict: Dictionary containing the list of all possible states.
    """
    return {"states": FSM_STATES}

# Get FSM transitions
@app.get("/fsm/transitions")
def get_fsm_transitions():
    """
    Get all possible transitions for the certificate lifecycle FSM.
    
    This endpoint returns all possible transitions between states in the FSM,
    which is useful for frontend logic to determine available actions.
    
    Returns:
        dict: Dictionary containing the list of all possible transitions.
    """
    return {"transitions": FSM_TRANSITIONS}

# Get FSM transitions available from a specific state
@app.get("/fsm/transitions/{state}")
def get_state_transitions(state: str):
    """
    Get all possible transitions from a specific state.
    
    This endpoint returns all transitions that are possible from the given state,
    which helps the frontend determine which actions are available for a domain.
    
    Args:
        state (str): The current state to find transitions from.
    
    Returns:
        dict: Dictionary containing the list of available transitions from the state.
    """
    if state not in FSM_STATES:
        raise HTTPException(status_code=404, detail=f"State '{state}' not found")
        
    # Filter transitions that can be triggered from the given state
    available_transitions = []
    for transition in FSM_TRANSITIONS:
        # Check if this transition can be triggered from the current state
        # Either the source matches exactly or it's a wildcard "*"
        if transition["source"] == state or transition["source"] == "*":
            available_transitions.append({
                "trigger": transition["trigger"],
                "dest": transition["dest"],
                "description": get_transition_description(transition["trigger"])
            })
    
    return {
        "state": state,
        "available_transitions": available_transitions
    }

def get_transition_description(trigger: str) -> str:
    """
    Get a human-readable description for a transition trigger.
    
    Args:
        trigger (str): The transition trigger name.
        
    Returns:
        str: A human-readable description of the transition.
    """
    descriptions = {
        "request_cert": "Request a new certificate",
        "validate_ok": "Validation completed successfully",
        "request_renewal": "Request certificate renewal",
        "renew_success": "Certificate renewed successfully",
        "expired_detected": "Certificate has expired",
        "manual_revoke": "Manually revoke certificate",
        "invalidate": "Mark certificate as invalid",
        "continue_cycle": "Continue to normal certificate lifecycle"
    }
    
    return descriptions.get(trigger, trigger.replace("_", " ").capitalize())

# Create a new domain entry
@app.post("/domains/", response_model=dict)
def add_domain(domain: str, session: Session = Depends(get_session)):
    """
    Create a new domain entry in the certificate management system.
    
    Args:
        domain (str): The domain name to add for certificate management.
        session (Session, optional): Database session. Defaults to Depends(get_session).
    
    Raises:
        HTTPException: 400 error if domain already exists.
    
    Returns:
        dict: Information about the newly created domain entry.
    """
    existing = session.execute(select(CertDomain).where(CertDomain.domain == domain)).scalar_one_or_none()
    if existing:
        raise HTTPException(status_code=400, detail="Domain already exists")

    entry = CertDomain(domain=domain, state="unissued")
    session.add(entry)
    session.commit()
    session.refresh(entry)
    return {"domain": entry.domain, "state": entry.state}


# List domains
@app.get("/domains/", response_model=list)
def list_domains(session: Session = Depends(get_session)):
    """
    List all domains currently registered in the certificate management system.
    
    Args:
        session (Session, optional): Database session. Defaults to Depends(get_session).
    
    Returns:
        list: List of dictionaries containing domain information.
    """
    domains = session.execute(select(CertDomain)).scalars().all()
    return [{"domain": domain.domain, "state": domain.state} for domain in domains]


# Trigger FSM transition
@app.post("/domains/{domain}/transition/{event}")
def transition_domain(domain: str, event: str, session: Session = Depends(get_session)):
    """
    Trigger a state transition for a domain in the certificate lifecycle.
    
    This function implements the finite state machine (FSM) for certificate lifecycle
    management, allowing domains to transition between different states based on events.
    
    Args:
        domain (str): The domain name to transition.
        event (str): The event trigger name (matching one of the defined transition triggers).
        session (Session, optional): Database session. Defaults to Depends(get_session).
    
    Raises:
        HTTPException: 404 error if domain not found, 400 error if transition is invalid.
    
    Returns:
        dict: Information about the domain and its new state after transition.
    """
    entry = session.execute(select(CertDomain).where(CertDomain.domain == domain)).scalar_one_or_none()
    if not entry:
        raise HTTPException(status_code=404, detail="Domain not found")

    # Bind FSM
    class FSMWrapper:
        """
        Wrapper class for the transitions state machine.
        
        This class provides a property interface for state management
        that the transitions library can use.
        
        Args:
            current_state (str): The initial state of the FSM.
        """
        def __init__(self, current_state: str):
            self._state = current_state
            
        @property
        def state(self):
            """Get the current state."""
            return self._state
            
        @state.setter
        def state(self, value):
            """Set the current state."""
            self._state = value

    # Create FSM model with current state
    current_state = str(entry.state)
    model = FSMWrapper(current_state)
    # Initialize machine with model and transitions
    Machine(
        model=model, 
        states=FSM_STATES, 
        transitions=FSM_TRANSITIONS, 
        initial=current_state
    )

    try:
        # Trigger the event
        getattr(model, event)()
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Transition failed: {str(e)}")
    # Get the new state after transition
    new_state = model.state
    
    # Update database entry - reuse the existing entry object
    setattr(entry, "state", new_state)
    setattr(entry, "last_checked", datetime.now(timezone.utc))
    setattr(entry, "updated_at", datetime.now(timezone.utc))
    session.add(entry)
    session.commit()

    return {"domain": domain, "new_state": new_state}


# Certbot mock integration endpoints

@app.post("/certbot/issue/{domain}")
async def issue_certificate(domain: str, background_tasks: BackgroundTasks, session: Session = Depends(get_session)):
    """
    Trigger certificate issuance for a domain using certbot mock.
    
    Args:
        domain (str): Domain to issue certificate for
        background_tasks (BackgroundTasks): FastAPI background tasks
        session (Session): Database session
        
    Returns:
        dict: Status of the operation
    """
    entry = session.execute(select(CertDomain).where(CertDomain.domain == domain)).scalar_one_or_none()
    if not entry:
        raise HTTPException(status_code=404, detail="Domain not found")
    
    if entry.state not in ["unissued", "failed", "expired"]:
        raise HTTPException(status_code=400, detail=f"Cannot issue certificate for domain in state: {entry.state}")
    
    # Trigger issuance in background
    background_tasks.add_task(perform_certificate_issuance, domain, background_tasks, session)
    
    return {"status": "started", "message": f"Certificate issuance started for {domain}", "previous_state": entry.state}


@app.post("/certbot/renew/{domain}")
async def renew_certificate(domain: str, background_tasks: BackgroundTasks, session: Session = Depends(get_session)):
    """
    Trigger certificate renewal for a domain using certbot mock.
    
    Args:
        domain (str): Domain to renew certificate for
        background_tasks (BackgroundTasks): FastAPI background tasks
        session (Session): Database session
        
    Returns:
        dict: Status of the operation
    """
    entry = session.execute(select(CertDomain).where(CertDomain.domain == domain)).scalar_one_or_none()
    if not entry:
        raise HTTPException(status_code=404, detail="Domain not found")
    
    if entry.state not in ["issued"]:
        raise HTTPException(status_code=400, detail=f"Cannot renew certificate for domain in state: {entry.state}")
    
    # Trigger renewal in background
    background_tasks.add_task(perform_certificate_renewal, domain, background_tasks, session)
    
    return {"status": "started", "message": f"Certificate renewal started for {domain}", "previous_state": entry.state}


@app.post("/certbot/revoke/{domain}")
async def revoke_certificate(domain: str, background_tasks: BackgroundTasks, session: Session = Depends(get_session)):
    """
    Trigger certificate revocation for a domain using certbot mock.
    
    Args:
        domain (str): Domain to revoke certificate for
        background_tasks (BackgroundTasks): FastAPI background tasks
        session (Session): Database session
        
    Returns:
        dict: Status of the operation
    """
    entry = session.execute(select(CertDomain).where(CertDomain.domain == domain)).scalar_one_or_none()
    if not entry:
        raise HTTPException(status_code=404, detail="Domain not found")
    
    if entry.state not in ["issued", "renewed"]:
        raise HTTPException(status_code=400, detail=f"Cannot revoke certificate for domain in state: {entry.state}")
    
    # Trigger revocation in background
    background_tasks.add_task(perform_certificate_revocation, domain, background_tasks, session)
    
    return {"status": "started", "message": f"Certificate revocation started for {domain}", "previous_state": entry.state}


@app.get("/certbot/status/{domain}")
async def get_certificate_status(domain: str, session: Session = Depends(get_session)):
    """
    Check certificate status for a domain using certbot mock.
    
    Args:
        domain (str): Domain to check certificate status for
        session (Session): Database session
        
    Returns:
        dict: Certificate status information
    """
    entry = session.execute(select(CertDomain).where(CertDomain.domain == domain)).scalar_one_or_none()
    if not entry:
        raise HTTPException(status_code=404, detail="Domain not found")
    
    # Check status
    status_info = await check_certificate_status(domain, session)
    
    return status_info

if __name__ == "__main__":
    """
    Main entry point for running the application directly.
    
    Initializes the database and starts the Uvicorn ASGI server with hot reload enabled.
    """
    init_db()
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=8000, log_level="info", reload=True)
    