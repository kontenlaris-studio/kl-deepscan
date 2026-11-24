"""KL-DeepScan check registry.

Importing this package imports every check module; each module's
@register decorator appends (check_id, title, fn) to _common.ALL_CHECKS.
CHECKS is that aggregated list, in module order.
"""
from . import _common  # noqa: F401
from . import headers  # noqa: F401
from . import tls  # noqa: F401
from . import cookies  # noqa: F401
from . import cors  # noqa: F401
from . import methods  # noqa: F401
from . import exposure  # noqa: F401
from . import probes  # noqa: F401
from . import jwt_auth  # noqa: F401
from . import misc  # noqa: F401

CHECKS = list(_common.ALL_CHECKS)

__all__ = ["CHECKS"]
