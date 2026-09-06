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
    file_name: str
    content_type: str
    body: str


RESOURCES: list[ResourceSpec] = [
    {
        "slug": "public-docs", "name": "Public Documentation Portal",
        "description": "Externally published product documentation and policies.",
        "category": "website", "sensitivity": "PUBLIC", "owner": "Marketing",
        "file_name": "product-documentation.md",
        "content_type": "text/markdown",
        "body": (
            "# Product Documentation\n\n"
            "Publicly published guides, release notes and policy summaries.\n\n"
            "## Contents\n\n"
            "- Getting started\n- Release notes\n- Acceptable use policy\n"
        ),
    },
    {
        "slug": "company-intranet", "name": "Company Intranet",
        "description": "Announcements, holiday calendar and internal directory.",
        "category": "website", "sensitivity": "PUBLIC", "owner": "Human Resources",
        "file_name": "announcements.md",
        "content_type": "text/markdown",
        "body": (
            "# Company Intranet\n\n"
            "## This week\n\n"
            "- Quarterly all-hands on Friday\n"
            "- Holiday calendar published for the next quarter\n"
        ),
    },
    {
        "slug": "hr-portal", "name": "HR Portal",
        "description": "Leave management, timesheets and appraisal records.",
        "category": "application", "sensitivity": "INTERNAL", "owner": "Human Resources",
        "file_name": "leave-policy.md",
        "content_type": "text/markdown",
        "body": (
            "# Leave Policy\n\n"
            "## Entitlement\n\n"
            "- 18 days of paid annual leave, accrued monthly\n"
            "- 12 days of casual/sick leave per calendar year\n"
            "- Unused annual leave carries over up to 10 days\n\n"
            "## Requesting leave\n\n"
            "Submit requests through the HR Portal at least 3 working days "
            "in advance; your manager approves or rejects within 2 days.\n"
        ),
    },
    {
        "slug": "ticketing-system", "name": "Support Ticketing System",
        "description": "Customer support queue and escalation workflow.",
        "category": "application", "sensitivity": "INTERNAL", "owner": "Customer Support",
        "file_name": "open-tickets.csv",
        "content_type": "text/csv",
        "body": (
            "ticket_id,subject,priority,status,assignee\n"
            "TCK-1001,Login page returns 500,High,Open,Divya\n"
            "TCK-1002,Export button missing on reports,Low,Open,Karthik\n"
            "TCK-1003,Password reset email delayed,Medium,In Progress,Ramya\n"
            "TCK-1004,Mobile app crashes on upload,High,Open,Sandeep\n"
        ),
    },
    {
        "slug": "wiki-engineering", "name": "Engineering Wiki",
        "description": "Design documents, runbooks and architecture decisions.",
        "category": "application", "sensitivity": "INTERNAL", "owner": "Engineering",
        "file_name": "runbook-index.md",
        "content_type": "text/markdown",
        "body": (
            "# Runbook Index\n\n"
            "## On-call runbooks\n\n"
            "- Database failover procedure\n"
            "- API gateway rate-limit incident response\n"
            "- Cache eviction storm recovery\n\n"
            "## Architecture decisions\n\n"
            "- ADR-014: Move session storage to Redis\n"
            "- ADR-021: Adopt trust-score based access policies\n"
        ),
    },
    {
        "slug": "source-repo", "name": "Source Code Repository",
        "description": "Git server hosting all first-party application source.",
        "category": "repository", "sensitivity": "CONFIDENTIAL", "owner": "Engineering",
        "file_name": "repository-layout.md",
        "content_type": "text/markdown",
        "body": (
            "# Repository Layout\n\n"
            "```\n"
            "backend/   FastAPI service, ORM models, tests\n"
            "frontend/  React + Vite single-page application\n"
            "scripts/   Database seeding and maintenance scripts\n"
            "storage/   Uploaded resource files (gitignored)\n"
            "```\n\n"
            "Trunk-based development off `main`; feature branches are "
            "squash-merged after review.\n"
        ),
    },
    {
        "slug": "build-pipeline", "name": "CI/CD Build Pipeline",
        "description": "Build agents, deployment jobs and signing workflow.",
        "category": "service", "sensitivity": "CONFIDENTIAL", "owner": "Engineering",
        "file_name": "pipeline.json",
        "content_type": "application/json",
        "body": (
            "{\n"
            '  "pipeline": "backend-deploy",\n'
            '  "stages": ["lint", "test", "build", "sign", "deploy"],\n'
            '  "runners": ["linux-x64-1", "linux-x64-2"],\n'
            '  "signing_key_ref": "vault://ci/signing-key",\n'
            '  "deploy_targets": ["staging", "production"]\n'
            "}\n"
        ),
    },
    {
        "slug": "crm-database", "name": "CRM Database",
        "description": "Sales pipeline, contracts and account owner records.",
        "category": "database", "sensitivity": "CONFIDENTIAL", "owner": "Sales",
        "file_name": "accounts.csv",
        "content_type": "text/csv",
        "body": (
            "account_id,company,stage,owner,arr_usd\n"
            "ACC-2001,Northwind Traders,Negotiation,Priya,84000\n"
            "ACC-2002,Contoso Logistics,Closed Won,Arjun,152000\n"
            "ACC-2003,Fabrikam Retail,Prospecting,Meera,0\n"
            "ACC-2004,Globex Manufacturing,Closed Won,Priya,231000\n"
        ),
    },
    {
        "slug": "finance-reports", "name": "Finance Reporting Warehouse",
        "description": "Quarterly ledgers, forecasts and audit worksheets.",
        "category": "database", "sensitivity": "CONFIDENTIAL", "owner": "Finance",
        "file_name": "ledger-extract.csv",
        "content_type": "text/csv",
        "body": (
            "period,account,description,debit_usd,credit_usd\n"
            "Q1-2026,4000,Product revenue,0,410000\n"
            "Q1-2026,5100,Cloud infrastructure,62000,0\n"
            "Q1-2026,5200,Salaries and benefits,187000,0\n"
            "Q1-2026,5300,Office lease,15000,0\n"
        ),
    },
    {
        "slug": "payroll-db", "name": "Payroll Database",
        "description": "Salary structure, bank details and tax declarations.",
        "category": "database", "sensitivity": "RESTRICTED", "owner": "Finance",
        "file_name": "salary-register.csv",
        "content_type": "text/csv",
        "body": (
            "employee_id,full_name,department,monthly_salary_usd,tax_regime\n"
            "EMP-3001,Test Employee One,Engineering,6200,New\n"
            "EMP-3002,Test Employee Two,Finance,5400,Old\n"
            "EMP-3003,Test Employee Three,Sales,4800,New\n"
            "EMP-3004,Test Employee Four,Human Resources,5100,New\n"
        ),
    },
    {
        "slug": "customer-pii-store", "name": "Customer PII Store",
        "description": "Identity documents and KYC records for customer accounts.",
        "category": "database", "sensitivity": "RESTRICTED", "owner": "Information Security",
        "file_name": "kyc-records.csv",
        "content_type": "text/csv",
        "body": (
            "customer_id,full_name,id_type,id_number,country\n"
            "CUST-9001,Fictional Customer A,Passport,X0000001,Testland\n"
            "CUST-9002,Fictional Customer B,National ID,Y0000002,Testland\n"
            "CUST-9003,Fictional Customer C,Passport,X0000003,Sampleland\n"
        ),
    },
    {
        "slug": "prod-secrets-vault", "name": "Production Secrets Vault",
        "description": "Production credentials, signing keys and API tokens.",
        "category": "service", "sensitivity": "RESTRICTED", "owner": "Information Security",
        "file_name": "secrets-index.md",
        "content_type": "text/markdown",
        "body": (
            "# Secrets Index\n\n"
            "Names only — values are never stored outside the vault.\n\n"
            "- `db/production/password`\n"
            "- `ci/signing-key`\n"
            "- `payments/api-token`\n"
            "- `smtp/relay-credential`\n"
        ),
    },
]
