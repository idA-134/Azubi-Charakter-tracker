"""
Level / XP Hilfsfunktionen
"""

import math

def xp_to_level(xp: int) -> int:
    """
    Standard-Formel:
      level = floor(sqrt(xp / 100)) + 1

    Beispiele:
      0  -> 1
      100 -> 2
      400 -> 3
      900 -> 4
    """
    try:
        xp_val = int(xp)
    except Exception:
        xp_val = 0
    level = math.floor(math.sqrt(xp_val / 100)) + 1
    return max(1, level)

def ensure_level_consistent(character: dict) -> dict:
    """
    Setzt oder korrigiert das level-Feld anhand von xp.
    Gibt das geänderte character dict zurück (in-memory).
    """
    xp = character.get('xp', 0)
    computed = xp_to_level(xp)
    character['level'] = computed
    return character