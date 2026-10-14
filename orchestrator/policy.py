"""The table decides, not the AI. Rules set floors the AI can't go below."""
CONFIDENCE = ["low", "medium", "high"]
STAGE = ["probing", "trying", "inside"]

TABLE = {
    ("low", "probing"): "log_only",
    ("low", "trying"): "lift_redirect",
    ("low", "inside"): "lift_isolation",
    ("medium", "probing"): "watch_list",
    ("medium", "trying"): "keep_in_honeypot",
    ("medium", "inside"): "keep_isolated_disable_account",
    ("high", "probing"): "timed_block",
    ("high", "trying"): "timed_block",
    ("high", "inside"): "freeze_quarantine_disable_account",
}
AUTOMATIC = {"log_only", "watch_list", "keep_in_honeypot"}  # everything else needs approval

# Fixed mapping from recommendation to Wazuh script. Never built from the AI's text.
ACTION_SCRIPTS = {
    "timed_block": "firewall-drop",
    "lift_redirect": "release-redirect",
    "lift_isolation": "release-isolation",
    "keep_isolated_disable_account": "disable-account",
    "freeze_quarantine_disable_account": "freeze-process",
}


def apply_floors(confidence, stage, events):
    c, s = CONFIDENCE.index(confidence), STAGE.index(stage)
    if any(e.cowrie_event == "cowrie.session.file_download" for e in events):
        c = max(c, 1)  # a download attempt: at least medium
    if any("decoy_contact" in e.groups for e in events):
        c = 2  # touching a standalone decoy: high
    if any("real_login" in e.groups for e in events):
        s = 2  # a real login: Inside
    return CONFIDENCE[c], STAGE[s]


def recommend(confidence, stage, critical_asset=False):
    c = CONFIDENCE.index(confidence)
    if critical_asset:
        c = min(c + 1, 2)  # confidence counts one level higher on critical assets
    return TABLE[(CONFIDENCE[c], stage)]
