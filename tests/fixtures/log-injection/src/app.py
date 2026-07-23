import logging
from flask import request

logger = logging.getLogger(__name__)


def search():
    # VULN (log injection, CWE-117 — opt-in `scan --log-hygiene` only): the
    # untrusted querystring value flows into a log call with no CRLF/newline
    # stripping. The DEFAULT sink catalog has no logging callees, so this line
    # produces ZERO findings under the default (non-opt-in) pipeline.
    q = request.args.get("q")
    logger.info(q)
    return "ok"


def log_boot():
    # Benign — must NOT be flagged by either pass.
    logger.info("worker ready")
