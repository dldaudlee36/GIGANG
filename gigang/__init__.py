"""
GIGANG Package
Zero Trust 기반 다기종 로그 상관분석 & 섀도우 AI 거버넌스 플랫폼
"""

__version__ = "2.0.0"

import sys
if "nexusguard" not in sys.modules:
    sys.modules["nexusguard"] = sys.modules[__name__]

