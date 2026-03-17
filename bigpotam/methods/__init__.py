"""Coercion method trigger functions."""


def check_error(e, error_codes, error_strings):
    """Check if a DCE/RPC exception indicates coercion success.

    Args:
        e: The exception to check.
        error_codes: Set of numeric Win32/RPC error codes that mean success.
        error_strings: Tuple of string fragments to match in str(e) as fallback.
    """
    # Check numeric error_code first (impacket DCERPCException attribute)
    code = getattr(e, "error_code", None)
    if code is not None and code in error_codes:
        return True
    # Fallback: string match for custom exception classes or unknown formats
    err = str(e)
    return any(s in err for s in error_strings)
