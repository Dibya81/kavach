"""
threat_mapper.py
KAVACH — Intelligent Threat Mapping Layer
Rule-based object → threat classification (no model training required).

Maps YOLO detected labels to:
  - threat_category
  - weapon_type
  - risk_score delta
  - threat_level
  - suspicious_activity

Called by crowd_sentinel/main.py after raw YOLO inference.
"""

from typing import Optional

# ── Weapon threat map ─────────────────────────────────────────────────────────
# Maps YOLO label strings → (weapon_type, risk_delta, threat_level)
WEAPON_THREAT_MAP: dict[str, tuple[str, int, str]] = {
    # Direct threat model outputs (yolo11n_threat_detection / legacy)
    "firearm":          ("firearm",      90, "CRITICAL"),
    "pistol":           ("pistol",       90, "CRITICAL"),
    "gun":              ("firearm",      90, "CRITICAL"),
    "rifle":            ("rifle",        90, "CRITICAL"),
    "knife":            ("knife",        85, "HIGH"),
    "ammo":             ("ammunition",   70, "HIGH"),
    "grenade":          ("grenade",      95, "CRITICAL"),
    "rocket":           ("rocket",       95, "CRITICAL"),

    # ── kavach_weapon_v1.pt new classes (50-epoch trained) ────────────────────
    "Gunting":          ("SCISSORS", 90, "CRITICAL"),    # Demo Priority
    "gunting":          ("SCISSORS", 90, "CRITICAL"),
    "scissors":         ("SCISSORS", 90, "CRITICAL"),
    "cutter":           ("Cutter/Blade", 70, "HIGH"),
    "lighter":          ("Fire Hazard", 55, "MEDIUM"),  # lighter / incendiary

    # Rule-based nail cutter / small sharp object logic
    "nail_cutter":              ("nail_cutter",   60, "MEDIUM"),
    "nail cutter":              ("nail_cutter",   60, "MEDIUM"),
    "small metallic object":    ("nail_cutter",   60, "MEDIUM"),
    "blade":                    ("blade",         70, "HIGH"),
    "razor":                    ("blade",         70, "HIGH"),
    "screwdriver":              ("sharp_object",  45, "MEDIUM"),
    "metallic object":          ("unknown_metal", 40, "MEDIUM"),
}

# ── Context object behavior map ───────────────────────────────────────────────
# Maps general YOLO COCO labels → (suspicious_activity, risk_delta, threat_level)
CONTEXT_BEHAVIOR_MAP: dict[str, tuple[str, int, str]] = {
    "laptop":    ("hardware_tampering",   60, "HIGH"),
    "backpack":  ("skimming_suspected",   50, "MEDIUM"),
    "cell phone":("pin_theft_risk",       25, "MEDIUM"),
    "handbag":   ("concealment_suspected",20, "LOW"),
    "suitcase":  ("suspicious_baggage",   30, "MEDIUM"),
    "bottle":    ("potential_acid",       40, "MEDIUM"),    # Increased for demo
    "mouse":     ("electronic_device",    15, "LOW"),      # Demo support
    "computer mouse": ("electronic_device", 15, "LOW"),
    "baseball bat":("blunt_weapon",       70, "HIGH"),
    "tennis racket":("blunt_object",      20, "LOW"),
    "umbrella":  ("concealment_device",   15, "LOW"),
    "bicycle":   ("getaway_vehicle",      20, "LOW"),
    "motorcycle":("getaway_vehicle",      25, "MEDIUM"),
    "car":       ("vehicle_threat",       15, "LOW"),
}

# ── Activity flags based on person count / behavior ──────────────────────────
def classify_activity(
    num_persons: int,
    loitering: bool = False,
    erratic: bool = False,
) -> tuple[Optional[str], int]:
    """
    Returns (suspicious_activity_label, risk_delta)
    """
    if loitering:
        return "loitering", 40
    if erratic:
        return "erratic_movement", 30
    if num_persons >= 2:
        return "shoulder_surfing", 25
    if num_persons >= 4:
        return "crowd_surge", 40
    return None, 0


# ── Main mapping function ─────────────────────────────────────────────────────

def map_detection_to_threat(
    raw_detections: list[dict],
    num_persons: int = 0,
    loitering: bool = False,
    erratic: bool = False,
) -> dict:
    """
    Input:  raw_detections from YOLO — list of
            {label, confidence, bbox, type}
    Output: structured threat assessment dict.
    """
    total_risk      = 0
    weapon_detected = False
    weapon_type     = None
    threat_category = "NORMAL"
    suspicious_activity = None
    detection_reasons = []
    nail_cutter_detected = False

    structured_objects = []

    for det in raw_detections:
        label     = det.get("label", "").lower().strip()
        confidence= det.get("confidence", 0.0)
        bbox      = det.get("bbox", [0, 0, 0, 0])
        det_type  = det.get("type", "context")  # "threat" | "context"

        obj_entry = {
            "label":       det.get("label"),
            "confidence":  round(confidence, 3),
            "bbox":        bbox,
            "type":        det_type,
            "threat_flag": False,
            "weapon_type": None,
        }

        # ── Check weapon threat map ───────────────────────────────────────────
        if label in WEAPON_THREAT_MAP or det_type == "threat":
            mapping = WEAPON_THREAT_MAP.get(label)
            if mapping:
                wtype, risk_delta, level = mapping
            else:
                # Unknown threat model label — still flag as weapon
                wtype      = label
                risk_delta = 75
                level      = "HIGH"

            total_risk += risk_delta
            weapon_detected = True
            weapon_type = wtype
            obj_entry["threat_flag"]  = True
            obj_entry["weapon_type"]  = wtype
            obj_entry["risk_delta"]   = risk_delta
            obj_entry["threat_level"] = level

            if "nail" in label or "cutter" in label or "metallic" in label:
                nail_cutter_detected = True
                threat_category = "SHARP_OBJECT"
                detection_reasons.append(
                    f"Potential nail cutter / sharp object detected: '{det.get('label')}' "
                    f"(conf={confidence:.0%})"
                )
            else:
                threat_category = "WEAPON"
                detection_reasons.append(
                    f"Weapon detected: {wtype} (conf={confidence:.0%})"
                )

        # ── Check context behavior map ────────────────────────────────────────
        elif label in CONTEXT_BEHAVIOR_MAP:
            activity, risk_delta, level = CONTEXT_BEHAVIOR_MAP[label]
            total_risk += risk_delta
            if suspicious_activity is None:
                suspicious_activity = activity
            if threat_category == "NORMAL":
                threat_category = "SUSPICIOUS"
            obj_entry["suspicious_flag"] = True
            obj_entry["activity"]        = activity
            obj_entry["risk_delta"]      = risk_delta
            detection_reasons.append(
                f"Context risk: {activity} via '{det.get('label')}' "
                f"(conf={confidence:.0%})"
            )

        structured_objects.append(obj_entry)

    # ── Behavior-based activity scoring ──────────────────────────────────────
    activity_label, activity_risk = classify_activity(
        num_persons, loitering, erratic
    )
    if activity_label:
        total_risk += activity_risk
        if suspicious_activity is None:
            suspicious_activity = activity_label
        if threat_category == "NORMAL":
            threat_category = "SUSPICIOUS"
        detection_reasons.append(
            f"Behavioral flag: {activity_label} "
            f"(persons={num_persons})"
        )

    # ── Cap and derive final threat level ─────────────────────────────────────
    total_risk = min(100, total_risk)

    if total_risk >= 80:
        threat_level = "CRITICAL"
    elif total_risk >= 60:
        threat_level = "HIGH"
    elif total_risk >= 30:
        threat_level = "MEDIUM"
    else:
        threat_level = "LOW"

    # ── FIR priority mapping ──────────────────────────────────────────────────
    if weapon_detected or total_risk >= 80:
        priority = "HIGH"
    elif suspicious_activity or total_risk >= 40:
        priority = "MEDIUM"
    else:
        priority = "LOW"

    return {
        "objects":              structured_objects,
        "weapon_detected":      weapon_detected,
        "weapon_type":          weapon_type,
        "threat_category":      threat_category,
        "suspicious_activity":  suspicious_activity,
        "risk_score":           total_risk,
        "threat_level":         threat_level,
        "priority":             priority,
        "detection_reason":     "; ".join(detection_reasons) if detection_reasons else "No threats detected",
        "nail_cutter_detected": nail_cutter_detected,
    }


# ── Structured output builder ─────────────────────────────────────────────────

def build_structured_output(
    raw_detections: list[dict],
    num_persons: int = 0,
    loitering: bool = False,
    erratic: bool = False,
    location: str = "CCTV-ATM-01",
) -> dict:
    """
    Final structured output format matching USER requirement:
    {
      "objects": [...],
      "suspicious_activity": "...",
      "risk_score": ...
    }
    """
    threat = map_detection_to_threat(raw_detections, num_persons, loitering, erratic)

    # Map to the exact structure requested by the user
    return {
        "objects": [
            {
                "label":       obj["label"],
                "confidence":  obj["confidence"],
                "bbox":        obj["bbox"]  # [x, y, w, h] normalized
            }
            for obj in threat["objects"]
        ],
        "suspicious_activity": threat["suspicious_activity"] or "none",
        "risk_score":          int(threat["risk_score"]),
        
        # Keep internal metadata for background processes (FIR/Blockchain)
        "_internal": {
            "status":               "success",
            "risk_level":           threat["threat_level"],
            "weapon_detected":      threat["weapon_detected"],
            "weapon_type":          threat["weapon_type"],
            "threat_category":      threat["threat_category"],
            "priority":             threat["priority"],
            "detection_reason":     threat["detection_reason"],
            "location":             location
        }
    }


# ── ThreatMapper class (wraps module-level functions for OOP usage) ───────────

class ThreatMapper:
    """
    Object-oriented wrapper around the threat mapping functions.
    Used by crowd_sentinel/main.py: `self.threat_mapper = ThreatMapper()`
    """

    def map_detections(self, raw_detections: list, num_persons: int = 0,
                       loitering: bool = False, erratic: bool = False) -> dict:
        """Map YOLO detections to threat assessment."""
        return map_detection_to_threat(raw_detections, num_persons, loitering, erratic)

    def build_structured_output(self, threat_report: dict, location: str = "CCTV-ATM-01") -> dict:
        """Build the final structured API response from a threat report dict."""
        # threat_report is already the output of map_detection_to_threat
        # Re-construct the structured output format
        return {
            "status": "success",
            "objects": [
                {
                    "label":      obj["label"],
                    "confidence": obj["confidence"],
                    "bbox":       obj["bbox"]
                }
                for obj in threat_report.get("objects", [])
            ],
            "suspicious_activity": threat_report.get("suspicious_activity") or "none",
            "risk_score":          int(threat_report.get("risk_score", 0)),
            "threat_detected":     threat_report.get("weapon_detected", False),
            "weapon_detected":     threat_report.get("weapon_detected", False),
            "weapon_type":         threat_report.get("weapon_type"),
            "risk_level":          threat_report.get("threat_level", "LOW"),
            "severity":            threat_report.get("threat_level", "LOW").lower(),
            "priority":            threat_report.get("priority", "LOW"),
            "detections":          [
                {
                    "label":      obj["label"],
                    "confidence": obj["confidence"],
                    "bbox":       obj["bbox"],
                    "type":       "threat" if obj.get("threat_flag") else "context"
                }
                for obj in threat_report.get("objects", [])
            ],
            "_internal": {
                "status":           "success",
                "risk_level":       threat_report.get("threat_level", "LOW"),
                "weapon_detected":  threat_report.get("weapon_detected", False),
                "weapon_type":      threat_report.get("weapon_type"),
                "threat_category":  threat_report.get("threat_category", "NORMAL"),
                "priority":         threat_report.get("priority", "LOW"),
                "detection_reason": threat_report.get("detection_reason", ""),
                "location":         "CCTV-ATM-01"
            }
        }
