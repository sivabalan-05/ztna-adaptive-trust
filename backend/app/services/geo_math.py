"""Great-circle distance and travel-velocity helpers.

Used by the location trust factor, the impossible-travel check and the feature
pipeline.  Pure functions, no I/O, so they are cheap to unit-test.
"""

from __future__ import annotations

import math
from datetime import datetime

EARTH_RADIUS_KM = 6371.0088


def haversine_km(
    lat1: float, lon1: float, lat2: float, lon2: float
) -> float:
    """Great-circle distance between two WGS-84 points, in kilometres."""
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlambda = math.radians(lon2 - lon1)
    a = (
        math.sin(dphi / 2) ** 2
        + math.cos(phi1) * math.cos(phi2) * math.sin(dlambda / 2) ** 2
    )
    return 2 * EARTH_RADIUS_KM * math.asin(math.sqrt(min(1.0, a)))


def travel_velocity_kmh(
    distance_km: float, earlier: datetime, later: datetime
) -> float:
    """Implied speed between two logins.

    Returns 0.0 when the two events are effectively simultaneous, so that a
    same-second re-login from the same city does not read as infinite speed.
    A genuine same-second login from a *different* city is caught by the
    distance term instead.
    """
    seconds = (later - earlier).total_seconds()
    if seconds <= 1.0:
        return 0.0 if distance_km < 1.0 else float("inf")
    return distance_km / (seconds / 3600.0)
