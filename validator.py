import json
from jsonschema import validate, ValidationError
from jsonschema import Draft7Validator
import os
from datetime import datetime

# load schema file (should be placed next to this file)
SCHEMA_PATH = os.path.join(os.path.dirname(__file__), 'character_schema.json')
with open(SCHEMA_PATH, 'r', encoding='utf-8') as f:
    SCHEMA = json.load(f)

def validate_character(data):
    """
    Returns (valid: bool, errors: list[str])
    Performs JSON Schema validation + project specific checks:
      - Stats each 0-10 (schema enforces)
      - Sum of stats <= maxStatSum (from x-constraints)
      - Max start skills (if created recently) <= configured value
    """
    errors = []

    # Basic JSON Schema validation
    v = Draft7Validator(SCHEMA)
    schema_errors = sorted(v.iter_errors(data), key=lambda e: e.path)
    for e in schema_errors:
        errors.append(f"{'/'.join(map(str, e.path))}: {e.message}")

    # Project constraints from x-constraints
    constraints = SCHEMA.get('x-constraints', {})
    max_stat_sum = constraints.get('maxStatSum', 30)
    max_start_skills = constraints.get('maxStartSkills', 5)

    # Stats sum check
    stats = data.get('stats', {})
    if isinstance(stats, dict):
        total = sum([int(v) for v in stats.values() if isinstance(v, int) or (isinstance(v, str) and v.isdigit())])
        if total > max_stat_sum:
            errors.append(f"Summe der Stats ist {total} (max {max_stat_sum})")

    # Skills count check (if created recently consider start check)
    skills = data.get('skills', [])
    if isinstance(skills, list) and len(skills) > 0:
        if len(skills) > 50:
            errors.append("Zu viele skills (max 50)")
        # enforce individual skill levels within 1-5 (schema enforces)
        if len(skills) > max_start_skills:
            # allow, but report warning as error for MVP (per settings: reject)
            errors.append(f"Anzahl Skills {len(skills)} > maxStartSkills {max_start_skills}")

    # Required fields: handled by schema, but ensure present
    required = SCHEMA.get('required', [])
    for r in required:
        if r not in data:
            errors.append(f"Pflichtfeld fehlt: {r}")

    valid = len(errors) == 0
    return valid, errors