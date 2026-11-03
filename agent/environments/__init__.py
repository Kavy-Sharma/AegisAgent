"""
AegisAgent Environments Module.
Provides pluggable environment tool definitions and runtime dispatch maps.
"""

from agent.environments.smart_home import build_environment, build_environment_meta

__all__ = ["build_environment", "build_environment_meta"]
