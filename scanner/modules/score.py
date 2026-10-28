"""
Security score for a scan report.

Turns the list of findings into a single, explainable number from 0 to 100
and a letter grade (A-F), so a non-expert can see at a glance how a site is
doing and whether a change improved it.

How it works (deliberately simple, so it can be explained in the TR):

  - Every site starts at 100 points.
  - Each finding subtracts points according to how serious it is:
        high    -> -25
        medium  -> -10
        low     ->  -4
  - Each RAW (unescaped) reflected surface that is not already a confirmed
    vulnerability subtracts a small amount (-2), because it is a warning
    sign, not a confirmed hole.
  - The score never goes below 0.

  Grade bands:
        A: 90-100   molt bo
        B: 75-89    bo
        C: 60-74    acceptable, a millorar
        D: 40-59    deficient
        F:  0-39    greu

The point of the score is comparison: the same site scanned before and
after applying the fixes should move up, and the jump measures the
improvement in a single figure.
"""

PENALTY = {"high": 25, "medium": 10, "low": 4}
RAW_REFLECTED_PENALTY = 2

GRADE_BANDS = [
    (90, "A", "molt bo"),
    (75, "B", "bo"),
    (60, "C", "acceptable, a millorar"),
    (40, "D", "deficient"),
    (0,  "F", "greu"),
]


def _grade(score):
    for threshold, letter, label in GRADE_BANDS:
        if score >= threshold:
            return letter, label
    return "F", "greu"


def compute(findings, reflected_surfaces=None):
    """
    Return a structured, explainable security score for a scan.

        {score, grade, label, max, breakdown, penalties, explanation}
    """
    reflected_surfaces = reflected_surfaces or []

    counts = {"high": 0, "medium": 0, "low": 0}
    for f in findings:
        sev = (f.get("severity") or "low").lower()
        if sev not in counts:
            sev = "low"
        counts[sev] += 1

    raw_reflected = sum(1 for r in reflected_surfaces if not r.get("escaped"))

    penalties = []
    total = 0
    for sev in ("high", "medium", "low"):
        if counts[sev]:
            pts = counts[sev] * PENALTY[sev]
            total += pts
            penalties.append({
                "reason": f"{counts[sev]} finding(s) of severity '{sev}'",
                "each": PENALTY[sev],
                "count": counts[sev],
                "points": pts,
            })
    if raw_reflected:
        pts = raw_reflected * RAW_REFLECTED_PENALTY
        total += pts
        penalties.append({
            "reason": f"{raw_reflected} raw (unescaped) reflected surface(s)",
            "each": RAW_REFLECTED_PENALTY,
            "count": raw_reflected,
            "points": pts,
        })

    score = max(0, 100 - total)
    letter, label = _grade(score)

    explanation = (
        f"Es parteix de 100 punts i es resten {total} per les troballes "
        f"({counts['high']} altes x{PENALTY['high']}, "
        f"{counts['medium']} mitjanes x{PENALTY['medium']}, "
        f"{counts['low']} baixes x{PENALTY['low']}"
        + (f", {raw_reflected} superficies crues x{RAW_REFLECTED_PENALTY}" if raw_reflected else "")
        + f"). Puntuacio final: {score}/100 (nota {letter})."
    )

    return {
        "score": score,
        "max": 100,
        "grade": letter,
        "label": label,
        "breakdown": counts,
        "raw_reflected": raw_reflected,
        "penalties": penalties,
        "explanation": explanation,
    }
