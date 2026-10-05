import os

def get_nxtwave_rules_dir() -> str:
    """
    Resolve and return the absolute system path to the nxtwave_rules directory.
    This enables offline auditing capabilities by dynamically locating the bundled rules.
    """
    current_dir = os.path.dirname(os.path.abspath(__file__))
    rules_dir = os.path.join(current_dir, "nxtwave_rules")
    return rules_dir
