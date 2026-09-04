"""Static reference data for the seeder.

Indian-context names and cities, the twelve protected resources, the four roles
and the baseline policy set.  Kept separate from ``seed.py`` so the generation
logic stays readable.
"""

from __future__ import annotations

from typing import TypedDict

# --- People -----------------------------------------------------------------

FIRST_NAMES: list[str] = [
    "Aarthi", "Abhinav", "Aditya", "Anitha", "Arjun", "Aswin", "Bhavana",
    "Chandran", "Deepak", "Divya", "Gokul", "Harini", "Ishaan", "Janani",
    "Karthik", "Kavya", "Lakshmi", "Madhavan", "Meera", "Naveen", "Nithya",
    "Pradeep", "Priya", "Rahul", "Ramya", "Sandeep", "Sanjana", "Saravanan",
    "Shruti", "Sivabalan", "Sneha", "Sriram", "Swathi", "Tarun", "Vaishnavi",
    "Varun", "Vignesh", "Yamini",
]

LAST_NAMES: list[str] = [
    "Balakrishnan", "Chandrasekar", "Deshpande", "Ganesan", "Iyer", "Jayaraman",
    "Krishnan", "Kumar", "Lakshmanan", "Menon", "Murugan", "Nair", "Natarajan",
    "Pillai", "Raghavan", "Rajan", "Ramesh", "Reddy", "Sharma", "Srinivasan",
    "Subramanian", "Sundaram", "Thangavel", "Venkatesan", "Verma",
]

DEPARTMENTS: list[str] = [
    "Engineering", "Finance", "Human Resources", "Information Security",
    "Operations", "Sales", "Customer Support",
]


# --- Places -----------------------------------------------------------------

class City(TypedDict):
    name: str
    country: str
    latitude: float
    longitude: float
    isp: str
    asn: str
    ip_prefix: str


HOME_CITIES: list[City] = [
    {
        "name": "Coimbatore", "country": "IN",
        "latitude": 11.0168, "longitude": 76.9558,
        "isp": "Bharat Sanchar Nigam Ltd", "asn": "AS9829",
        "ip_prefix": "117.192",
    },
    {
        "name": "Chennai", "country": "IN",
        "latitude": 13.0827, "longitude": 80.2707,
        "isp": "Airtel Broadband", "asn": "AS24560",
        "ip_prefix": "106.51",
    },
    {
        "name": "Bangalore", "country": "IN",
        "latitude": 12.9716, "longitude": 77.5946,
        "isp": "ACT Fibernet", "asn": "AS24309",
        "ip_prefix": "49.207",
    },
]

#: Ordinary residential networks abroad. Used by the credential-theft
#: scenario, where the distinguishing signals are the unknown device and the
#: new country -- not a hostile network. Putting that attacker on a blocklisted
#: VPN would make the scenario indistinguishable from the others.
RESIDENTIAL_FOREIGN_CITIES: list[City] = [
    {
        "name": "Dubai", "country": "AE", "latitude": 25.2048, "longitude": 55.2708,
        "isp": "Etisalat", "asn": "AS5384", "ip_prefix": "5.32",
    },
    {
        "name": "Kuala Lumpur", "country": "MY", "latitude": 3.1390, "longitude": 101.6869,
        "isp": "TM Net", "asn": "AS4788", "ip_prefix": "175.139",
    },
]

#: Locations used only by the anomalous / attack events.
HOSTILE_CITIES: list[City] = [
    {
        "name": "Kyiv", "country": "UA", "latitude": 50.4501, "longitude": 30.5234,
        "isp": "Hosting Ukraine LLC", "asn": "AS200000", "ip_prefix": "185.234",
    },
    {
        "name": "Sao Paulo", "country": "BR", "latitude": -23.5505, "longitude": -46.6333,
        "isp": "Datacenter Brasil", "asn": "AS262287", "ip_prefix": "191.96",
    },
    {
        "name": "Lagos", "country": "NG", "latitude": 6.5244, "longitude": 3.3792,
        "isp": "Cloud Exit Node", "asn": "AS37282", "ip_prefix": "197.210",
    },
    {
        "name": "Amsterdam", "country": "NL", "latitude": 52.3676, "longitude": 4.9041,
        "isp": "M247 VPN", "asn": "AS9009", "ip_prefix": "45.83",
    },
    {
        "name": "Singapore", "country": "SG", "latitude": 1.3521, "longitude": 103.8198,
        "isp": "DigitalOcean", "asn": "AS14061", "ip_prefix": "159.89",
    },
]


# --- Devices ----------------------------------------------------------------

DEVICE_PROFILES: list[dict[str, str]] = [
    {
        "label": "Dell Latitude 5440",
        "os": "Windows 11", "browser": "Chrome 131", "platform": "Win32",
        "screen_resolution": "1920x1080", "language": "en-IN",
        "user_agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
        ),
    },
    {
        "label": "MacBook Air M2",
        "os": "macOS 15", "browser": "Safari 18", "platform": "MacIntel",
        "screen_resolution": "2560x1664", "language": "en-IN",
        "user_agent": (
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
            "(KHTML, like Gecko) Version/18.0 Safari/605.1.15"
        ),
    },
    {
        "label": "Lenovo ThinkPad E14",
        "os": "Ubuntu 24.04", "browser": "Firefox 133", "platform": "Linux x86_64",
        "screen_resolution": "1920x1200", "language": "en-IN",
        "user_agent": (
            "Mozilla/5.0 (X11; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0"
        ),
    },
    {
        "label": "Samsung Galaxy S23",
        "os": "Android 14", "browser": "Chrome Mobile 131", "platform": "Linux armv8l",
        "screen_resolution": "1080x2340", "language": "en-IN",
        "user_agent": (
            "Mozilla/5.0 (Linux; Android 14; SM-S911B) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36"
        ),
    },
    {
        "label": "iPhone 15",
        "os": "iOS 18", "browser": "Safari Mobile 18", "platform": "iPhone",
        "screen_resolution": "1179x2556", "language": "en-IN",
        "user_agent": (
            "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) "
            "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1"
        ),
    },
]

#: Used for the credential-theft / session-hijack scenarios.
ATTACKER_DEVICE_PROFILE: dict[str, str] = {
    "label": "Unknown workstation",
    "os": "Windows 10", "browser": "Chrome 108", "platform": "Win32",
    "screen_resolution": "1366x768", "language": "en-US",
    "user_agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36"
    ),
}


# --- Roles ------------------------------------------------------------------

class RoleSpec(TypedDict):
    name: str
    description: str
    is_admin: bool
    max_sensitivity_ordinal: int
    permissions: list[str]


ROLES: list[RoleSpec] = [
    {
        "name": "admin",
        "description": "Platform administrator: full management of users, devices, policies and sessions.",
        "is_admin": True,
        "max_sensitivity_ordinal": 3,   # RESTRICTED
        "permissions": [
            "users:read", "users:write", "devices:read", "devices:approve",
            "devices:revoke", "policies:read", "policies:write", "sessions:read",
            "sessions:revoke", "alerts:read", "alerts:write", "audit:read",
            "audit:verify", "resources:read", "resources:write",
        ],
    },
    {
        "name": "security_analyst",
        "description": "Monitors sessions and alerts; may revoke sessions but not change policy.",
        "is_admin": False,
        "max_sensitivity_ordinal": 2,   # CONFIDENTIAL
        "permissions": [
            "users:read", "devices:read", "policies:read", "sessions:read",
            "sessions:revoke", "alerts:read", "alerts:write", "audit:read",
            "audit:verify", "resources:read",
        ],
    },
    {
        "name": "employee",
        "description": "Standard internal user with access to internal business applications.",
        "is_admin": False,
        "max_sensitivity_ordinal": 2,   # CONFIDENTIAL
        "permissions": ["resources:read", "sessions:read_own", "devices:read_own"],
    },
    {
        "name": "contractor",
        "description": "External contributor limited to public and internal resources.",
        "is_admin": False,
        "max_sensitivity_ordinal": 1,   # INTERNAL
        "permissions": ["resources:read", "sessions:read_own", "devices:read_own"],
    },
]


# --- Protected resources ----------------------------------------------------

class ResourceSpec(TypedDict):
    slug: str
    name: str
    description: str
    category: str
    sensitivity: str
    owner: str


RESOURCES: list[ResourceSpec] = [
    {
        "slug": "public-docs", "name": "Public Documentation Portal",
        "description": "Externally published product documentation and policies.",
        "category": "website", "sensitivity": "PUBLIC", "owner": "Marketing",
    },
    {
        "slug": "company-intranet", "name": "Company Intranet",
        "description": "Announcements, holiday calendar and internal directory.",
        "category": "website", "sensitivity": "PUBLIC", "owner": "Human Resources",
    },
    {
        "slug": "hr-portal", "name": "HR Portal",
        "description": "Leave management, timesheets and appraisal records.",
        "category": "application", "sensitivity": "INTERNAL", "owner": "Human Resources",
    },
    {
        "slug": "ticketing-system", "name": "Support Ticketing System",
        "description": "Customer support queue and escalation workflow.",
        "category": "application", "sensitivity": "INTERNAL", "owner": "Customer Support",
    },
    {
        "slug": "wiki-engineering", "name": "Engineering Wiki",
        "description": "Design documents, runbooks and architecture decisions.",
        "category": "application", "sensitivity": "INTERNAL", "owner": "Engineering",
    },
    {
        "slug": "source-repo", "name": "Source Code Repository",
        "description": "Git server hosting all first-party application source.",
        "category": "repository", "sensitivity": "CONFIDENTIAL", "owner": "Engineering",
    },
    {
        "slug": "build-pipeline", "name": "CI/CD Build Pipeline",
        "description": "Build agents, deployment jobs and signing workflow.",
        "category": "service", "sensitivity": "CONFIDENTIAL", "owner": "Engineering",
    },
    {
        "slug": "crm-database", "name": "CRM Database",
        "description": "Sales pipeline, contracts and account owner records.",
        "category": "database", "sensitivity": "CONFIDENTIAL", "owner": "Sales",
    },
    {
        "slug": "finance-reports", "name": "Finance Reporting Warehouse",
        "description": "Quarterly ledgers, forecasts and audit worksheets.",
        "category": "database", "sensitivity": "CONFIDENTIAL", "owner": "Finance",
    },
    {
        "slug": "payroll-db", "name": "Payroll Database",
        "description": "Salary structure, bank details and tax declarations.",
        "category": "database", "sensitivity": "RESTRICTED", "owner": "Finance",
    },
    {
        "slug": "customer-pii-store", "name": "Customer PII Store",
        "description": "Identity documents and KYC records for customer accounts.",
        "category": "database", "sensitivity": "RESTRICTED", "owner": "Information Security",
    },
    {
        "slug": "prod-secrets-vault", "name": "Production Secrets Vault",
        "description": "Production credentials, signing keys and API tokens.",
        "category": "service", "sensitivity": "RESTRICTED", "owner": "Information Security",
    },
]
