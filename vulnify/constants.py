from enum import Enum


class Severity(str, Enum):
    """
    Severity model represents a severity.
    """
    NONE = "NONE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"
    UNKNOWN = "UNKNOWN"


class SourceTrust(str, Enum):
    """
    SourceTrust model represents a source trust.
    """
    VENDOR = "VENDOR"
    MITRE = "MITRE"
    NVD = "NVD"
    CISA = "CISA"
    RESEARCH = "RESEARCH"
    COMMUNITY = "COMMUNITY"


class ExploitMaturity(str, Enum):
    """
    ExploitMaturity model represents a exploit maturity.
    """
    NONE = "NONE"
    POC = "POC"
    FUNCTIONAL = "FUNCTIONAL"
    WEAPONIZED = "WEAPONIZED"
    IN_THE_WILD = "IN_THE_WILD"


class ProductType(str, Enum):
    """
    ProductType model represents a product type.
    """
    OS = "OS"
    APPLICATION = "APPLICATION"
    LIBRARY = "LIBRARY"
    APPLIANCE = "APPLIANCE"
    CLOUD = "CLOUD"
    FIRMWARE = "FIRMWARE"
    MOBILE = "MOBILE"
    UNKNOWN = "UNKNOWN"
