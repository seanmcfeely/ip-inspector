"""All database functionality and interaction."""

import contextlib
import logging
from datetime import datetime

from typing import Union, List

from sqlalchemy import create_engine, Boolean, Column, ForeignKey, DateTime, Integer, String, or_
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.exc import IntegrityError
from sqlalchemy_utils import database_exists, create_database
from sqlalchemy.pool import NullPool

from ip_inspector.config import DATA_DIR, CONFIG

LOGGER = logging.getLogger("ip-inspector.database")

DATABASE_PATH = f"{DATA_DIR}/tracking_database.sqlite"
SQLALCHEMY_DATABASE_URL = f"sqlite:///{DATABASE_PATH}"


if CONFIG["database"]["postgres"]["enabled"]:
    db_user = CONFIG["database"]["postgres"]["user"]
    db_pass = CONFIG["database"]["postgres"]["pass"]
    db_host = CONFIG["database"]["postgres"]["host"]
    db_port = CONFIG["database"]["postgres"]["port"]
    db_name = CONFIG["database"]["postgres"]["db_name"]
    postgres_dsn = f"postgresql+pg8000://{db_user}:{db_pass}@{db_host}:{db_port}/{db_name}"
    engine_args = CONFIG["database"]["postgres"].get("engine_args", {})
    if not CONFIG["database"]["postgres"].get('connection_pooling', True):
        engine_args['poolclass'] = NullPool
    engine = create_engine(url=postgres_dsn, **engine_args)
else:
    engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})


Session = sessionmaker(autocommit=False, autoflush=True, bind=engine)

Base = declarative_base()

# Global default
DEFAULT_INFRASTRUCTURE_CONTEXT_ID = 1
DEFAULT_INFRASTRUCTURE_CONTEXT_NAME = "default"


class InfrastructureContext(Base):
    __tablename__ = "infrastructure_context"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    name = Column(String, unique=True, index=True)
    insert_date = Column(DateTime, default=datetime.utcnow)

    def __str__(self):
        return f"Infrastructure Context: ID={self.id}, Name={self.name}, Insert Date={self.insert_date}"


class BlacklistEntry(Base):
    __tablename__ = "blacklist_map"

    id = Column(Integer, index=True, primary_key=True)
    infrastructure_id = Column(Integer, ForeignKey("infrastructure_context.id"), index=True)
    org = Column(String, nullable=True)
    asn = Column(Integer, nullable=True)
    country = Column(String, nullable=True)
    insert_date = Column(DateTime, default=datetime.utcnow)
    reference = Column(String, nullable=True)

    def to_dict(self):
        """Return the BlacklistEntry as a dictionary."""
        return {
            "id": self.id,
            "entry_type": "blacklist",
            "infrastructure_context_id": self.infrastructure_id,
            "org": self.org,
            "asn": self.asn,
            "country": self.country,
            "insert_date": self.insert_date.isoformat(),
            "reference": self.reference,
        }

    @property
    def blacklisted_fields(self):
        """Return a list of all blacklisted fields."""
        _fields = []
        if self.org:
            _fields.append("ORG")
        if self.asn:
            _fields.append("ASN")
        if self.country:
            _fields.append("Country")
        return _fields

    def __str__(self):
        txt = f"Blacklist Entry #{self.id}: "
        for key, value in self.to_dict().items():
            if key == "id" or key == "entry_type":
                continue
            txt += f"{key}={value} "
        return txt


class WhitelistEntry(Base):
    __tablename__ = "whitelist_map"

    id = Column(Integer, index=True, primary_key=True)
    infrastructure_id = Column(Integer, ForeignKey("infrastructure_context.id"), index=True)
    org = Column(String, nullable=True)
    asn = Column(Integer, nullable=True)
    country = Column(String, nullable=True)
    insert_date = Column(DateTime, default=datetime.utcnow)
    reference = Column(String, nullable=True)

    def to_dict(self):
        """Return the WhitelistEntry as a dictionary."""
        return {
            "id": self.id,
            "entry_type": "whitelist",
            "infrastructure_context_id": self.infrastructure_id,
            "org": self.org,
            "asn": self.asn,
            "country": self.country,
            "insert_date": self.insert_date.isoformat(),
            "reference": self.reference,
        }

    @property
    def whitelisted_fields(self):
        """Return a list of all whitelisted fields."""
        _fields = []
        if self.org:
            _fields.append("ORG")
        if self.asn:
            _fields.append("ASN")
        if self.country:
            _fields.append("Country")
        return _fields

    def __str__(self):
        txt = f"Whitelist Entry #{self.id}: "
        for key, value in self.to_dict().items():
            if key == "id" or key == "entry_type":
                continue
            txt += f"{key}={value} "
        return txt


# Dependency
@contextlib.contextmanager
def get_db_session():
    """Get a database session."""
    db = Session()
    try:
        yield db
    finally:
        db.close()


## Infrastructure Context functions ##
def create_infrastructure_context(db: Session, context_name: str):
    """Create a new infrastructure context to track.

    Args:
        db: A database session.
        context_name: The name for the bew InfrastructureContext.
    Returns:
        The new InfrastructureContext or None.
    """
    icontext = get_infrastructure_context_by_name(db, context_name)
    if icontext:
        LOGGER.warning(f"Infrastructure context by name '{context_name}' already exists.")
        return None
    infrastructure = InfrastructureContext(name=context_name)
    db.add(infrastructure)
    db.commit()
    db.refresh(infrastructure)
    return infrastructure


def get_infrastructure_context_map(db: Session):
    """Create InfrastructureContext.name -> InfrastructureContext.id map."""
    context_map = {}
    for context in db.query(InfrastructureContext).all():
        context_map[context.name] = context.id
    return context_map


def get_all_infrastructure_context(db: Session):
    """Get all InfrastructureContext"""
    return db.query(InfrastructureContext).all()


def get_infrastructure_context_by_name(db: Session, context_name: str):
    """Get InfrastructureContext by name"""
    return db.query(InfrastructureContext).filter(InfrastructureContext.name == context_name).first()


def get_infrastructure_context_by_id(db: Session, context_id: int):
    """Get InfrastructureContext by ID"""
    return db.query(InfrastructureContext).filter(InfrastructureContext.id == context_id).first()


def delete_infrastructure_context(db: Session, context_id: int):
    """Delete an infrastructure tracking context.

    Args:
        db: A database session.
        context_id: The ID of the InfrastructureContext to delete..
    Returns:
        True on success.
    """
    if context_id == DEFAULT_INFRASTRUCTURE_CONTEXT_ID:
        LOGGER.error(f"Can not delete default context ID={DEFAULT_INFRASTRUCTURE_CONTEXT_ID}.")
        return None
    query = db.query(InfrastructureContext).filter(InfrastructureContext.id == context_id)
    if not query.count():
        LOGGER.warning(f"no infrastructure context found by id: {context_id}")
        return False
    LOGGER.warning(f"deleting: {query.one()}")
    query.delete()
    db.commit()
    return True


## Blacklist and Whitelist functions ##
def get_blacklists(db: Session):
    """Get all blacklists."""
    return db.query(BlacklistEntry).all()


def get_whitelists(db: Session):
    """Get all blacklists."""
    return db.query(WhitelistEntry).all()


def append_to_blacklist(
    db: Session,
    context: Union[str, int] = DEFAULT_INFRASTRUCTURE_CONTEXT_ID,
    org: str = None,
    asn: int = None,
    country: str = None,
    reference: str = None,
):
    """Add an entry to this context blacklist.

    Args:
        db: A database session.
        context: The name or ID of an InfrastructureContext.
        org: The Organization that reports to own the infrastructure.
        asn: The Autonomous System Number associated to the infrastructure reference.
        country: The name of the country associated to the infrastructure reference.
        reference: A reference to why this entry was added or from what (IP address) this entry was added.

    Returns:
       The BlacklistEntry that was created or None.
    """
    if org is None and asn is None and country is None:
        LOGGER.error("must pass at least one of [ORG, ASN, Country] for blacklisting.")
        return False
    context_id = context
    if context and isinstance(context, str):
        # assume name and lookup
        icontext = get_infrastructure_context_by_name(db, context)
        if not icontext:
            LOGGER.warning(f"no infrastructure by context by name '{context}")
            return None
        context_id = icontext.id
    bl_entry = BlacklistEntry(infrastructure_id=context_id, org=org, asn=asn, country=country, reference=reference)
    db.add(bl_entry)
    db.commit()
    db.refresh(bl_entry)
    LOGGER.debug(f"created {bl_entry}")
    return bl_entry


def append_to_whitelist(
    db: Session,
    context: Union[str, int] = DEFAULT_INFRASTRUCTURE_CONTEXT_ID,
    org: str = None,
    asn: int = None,
    country: str = None,
    reference: str = None,
):
    """Add an entry to this context whitelist.

    Args:
        db: A database session.
        context: The name or ID of an InfrastructureContext.
        org: The Organization that reports to own the infrastructure.
        asn: The Autonomous System Number associated to the infrastructure reference.
        country: The name of the country associated to the infrastructure reference.
        reference: A reference to why this entry was added or from what (IP address) this entry was added.

    Returns:
       The WhitelistEntry that was created or None.
    """
    if org is None and asn is None and country is None:
        LOGGER.error("must pass at least one of [ORG, ASN, Country] for blacklisting.")
        return False
    context_id = context
    if context and isinstance(context, str):
        # assume name and lookup
        icontext = get_infrastructure_context_by_name(db, context)
        if not icontext:
            LOGGER.warning(f"no infrastructure by context by name '{context}")
            return None
        context_id = icontext.id
    wl_entry = WhitelistEntry(infrastructure_id=context_id, org=org, asn=asn, country=country, reference=reference)
    db.add(wl_entry)
    db.commit()
    db.refresh(wl_entry)
    LOGGER.debug(f"created {wl_entry}")
    return wl_entry


def remove_from_blacklist(
    db: Session,
    context: Union[str, int] = DEFAULT_INFRASTRUCTURE_CONTEXT_ID,
    org: str = None,
    asn: int = None,
    country: str = None,
    reference: str = None,
):
    """Remove an entry to this context blacklist.

    Remove all entries that match *any* of the details for the respective context.

    Args:
        db: A database session.
        context: The name or ID of an InfrastructureContext.
        org: The Organization that reports to own the infrastructure.
        asn: The Autonomous System Number associated to the infrastructure reference.
        country: The name of the country associated to the infrastructure reference.
        reference: A reference to why this entry was added or from what (IP address) this entry was added.

    Returns:
       True on success.
    """
    if org is None and asn is None and country is None and reference is None:
        LOGGER.error("must pass at least one of [ORG, ASN, Country, reference] to remove.")
        return False
    context_id = context
    if context and isinstance(context, str):
        # assume name and lookup
        icontext = get_infrastructure_context_by_name(db, context)
        if not icontext:
            LOGGER.warning(f"no infrastructure by context by name '{context}")
            return False
        context_id = icontext.id
    bl_query = db.query(BlacklistEntry).filter(BlacklistEntry.infrastructure_id == context_id)
    criteria = []
    if org is not None:
        criteria.append(BlacklistEntry.org == org)
    if asn is not None:
        criteria.append(BlacklistEntry.asn == asn)
    if country is not None:
        criteria.append(BlacklistEntry.country == country)
    if reference is not None:
        criteria.append(BlacklistEntry.reference == reference)
    bl_query = bl_query.filter(or_(*criteria))
    # LOGGER.debug(f"query: {bl_query}")
    if not bl_query.count():
        LOGGER.debug(f"no blacklist entries found for deletion.")
        return None
    LOGGER.info(f"deleting {bl_query.count()} Blacklist entries")
    for bl_entry in bl_query:
        LOGGER.info(f"Deleting {bl_entry}.")
    bl_query.delete()
    db.commit()
    return True


def remove_from_whitelist(
    db: Session,
    context: Union[str, int] = DEFAULT_INFRASTRUCTURE_CONTEXT_ID,
    org: str = None,
    asn: int = None,
    country: str = None,
    reference: str = None,
):
    """Remove an entry from this context whitelist.

    Remove all entries that match *any* of the details for the respective context.

    Args:
        db: A database session.
        context: The name or ID of an InfrastructureContext.
        org: The Organization that reports to own the infrastructure.
        asn: The Autonomous System Number associated to the infrastructure reference.
        country: The name of the country associated to the infrastructure reference.
        reference: A reference to why this entry was added or from what (IP address) this entry was added.

    Returns:
       True on success.
    """
    if org is None and asn is None and country is None and reference is None:
        LOGGER.error("must pass at least one of [ORG, ASN, Country] to remove.")
        return False
    context_id = context
    if context and isinstance(context, str):
        # assume name and lookup
        icontext = get_infrastructure_context_by_name(db, context)
        if not icontext:
            LOGGER.warning(f"no infrastructure by context by name '{context}")
            return False
        context_id = icontext.id
    wl_query = db.query(WhitelistEntry).filter(WhitelistEntry.infrastructure_id == context_id)
    criteria = []
    if org is not None:
        criteria.append(WhitelistEntry.org == org)
    if asn is not None:
        criteria.append(WhitelistEntry.asn == asn)
    if country is not None:
        criteria.append(WhitelistEntry.country == country)
    if reference is not None:
        criteria.append(WhitelistEntry.reference == reference)
    wl_query = wl_query.filter(or_(*criteria))
    # LOGGER.debug(f"query: {wl_query}")
    if not wl_query.count():
        LOGGER.debug(f"no whitelist entries found for deletion.")
        return None
    LOGGER.info(f"deleting {wl_query.count()} Whitelist entries")
    for wl_entry in wl_query:
        LOGGER.info(f"Deleting {wl_entry}")
    wl_query.delete()
    db.commit()
    return True


def check_blacklist(
    db: Session, context: Union[str, int, None] = None, org: str = None, asn: int = None, country: str = None
) -> List[BlacklistEntry]:
    """Return any matching blacklist entries.

    At least one of `org`, `asn`, `country` is required.

    Args:
        db: A database session.
        context: An optional name or ID of an InfrastructureContext.
        org: The Organization that reports to own the infrastructure.
        asn: The Autonomous System Number associated to the infrastructure reference.
        country: The name of the country associated to the infrastructure reference.

    Returns:
       A list of BlacklistEntry objects or None.
    """
    if org is None and asn is None and country is None:
        LOGGER.info(
            "blacklist checking requires one of [ORG, ASN, Country]. Do a direct DB query if you need something special."
        )
        return []
    context_id = context
    if context and isinstance(context, str):
        # assume name and lookup
        icontext = get_infrastructure_context_by_name(db, context)
        if not icontext:
            LOGGER.warning(f"no infrastructure by context by name '{context}")
            return []
        context_id = icontext.id
    if context_id and isinstance(context_id, int):
        bl_query = db.query(BlacklistEntry).filter(BlacklistEntry.infrastructure_id == context_id)
    else:
        bl_query = db.query(BlacklistEntry)
    criteria = []
    if org is not None:
        criteria.append(BlacklistEntry.org == org)
    if asn is not None:
        criteria.append(BlacklistEntry.asn == asn)
    if country is not None:
        criteria.append(BlacklistEntry.country == country)
    bl_query = bl_query.filter(or_(*criteria))
    # LOGGER.debug(f"query: {bl_query}")
    return bl_query.all()


def check_whitelist(
    db: Session, context: Union[str, int, None] = None, org: str = None, asn: int = None, country: str = None
) -> List[WhitelistEntry]:
    """Return any matching whitelist entries.

    At least one of `org`, `asn`, `country` is required.

    Args:
        db: A database session.
        context: An optional name or ID of an InfrastructureContext.
        org: The Organization that reports to own the infrastructure.
        asn: The Autonomous System Number associated to the infrastructure reference.
        country: The name of the country associated to the infrastructure reference.

    Returns:
       A list of WhitelistEntry objects or None.
    """
    if org is None and asn is None and country is None:
        LOGGER.info(
            "whitelist checking requires one of [ORG, ASN, Country]. Do a direct DB query if you need something special."
        )
        return False
    context_id = context
    if isinstance(context, str):
        # assume name and lookup
        icontext = get_infrastructure_context_by_name(db, context)
        if not icontext:
            LOGGER.warning(f"no infrastructure by context by name '{context}")
            return None
        context_id = icontext.id
    if context_id and isinstance(context_id, int):
        wl_query = db.query(WhitelistEntry).filter(WhitelistEntry.infrastructure_id == context_id)
    else:
        wl_query = db.query(WhitelistEntry)
    criteria = []
    if org is not None:
        criteria.append(WhitelistEntry.org == org)
    if asn is not None:
        criteria.append(WhitelistEntry.asn == asn)
    if country is not None:
        criteria.append(WhitelistEntry.country == country)
    wl_query = wl_query.filter(or_(*criteria))
    # LOGGER.debug(f"query: {wl_query}")
    return wl_query.all()


## Hippo.
def create_tables():
    """Create the database tables."""
    Base.metadata.create_all(bind=engine)


if not database_exists(engine.url):
    create_database(engine.url)

create_tables()

# create default context
with get_db_session() as session:
    if not get_infrastructure_context_by_id(session, DEFAULT_INFRASTRUCTURE_CONTEXT_ID):
        create_infrastructure_context(session, DEFAULT_INFRASTRUCTURE_CONTEXT_NAME)
