import importlib


def load(name):
    # An attacker-chosen module name resolves to whatever is importable.
    return importlib.import_module(name)
