"""Slack notification service — uses incoming webhooks, no SDK required."""
import logging
from typing import TYPE_CHECKING

import httpx

if TYPE_CHECKING:
    from app.models.application import Application
    from app.models.finding import Finding
    from app.models.scan import Scan

logger = logging.getLogger(__name__)

_SEVERITY_COLOURS = {
    "critical": "#ff3333",
    "high": "#ff9f43",
    "medium": "#ff6b35",
    "low": "#54a0ff",
    "info": "#a29bfe",
}

_SEVERITY_EMOJI = {
    "critical": ":red_circle:",
    "high": ":orange_circle:",
    "medium": ":yellow_circle:",
    "low": ":blue_circle:",
    "info": ":white_circle:",
}


def _build_finding_blocks(finding: "Finding", application: "Application", base_url: str = "") -> list:
    severity = (finding.severity or "info").lower()
    emoji = _SEVERITY_EMOJI.get(severity, ":white_circle:")
    identifier = finding.cve_id or finding.rule_id or "—"
    findings_url = f"{base_url}/findings.html?severity={severity}&status=open" if base_url else "#"

    fields = [
        {"type": "mrkdwn", "text": f"*Severity:*\n{emoji} {severity.upper()}"},
        {"type": "mrkdwn", "text": f"*Application:*\n{application.name}"},
        {"type": "mrkdwn", "text": f"*Scanner:*\n{finding.scanner}"},
        {"type": "mrkdwn", "text": f"*Identifier:*\n`{identifier}`"},
    ]
    if finding.file_path:
        fields.append({"type": "mrkdwn", "text": f"*File:*\n`{finding.file_path}`"})
    if finding.package_name:
        fields.append({"type": "mrkdwn", "text": f"*Package:*\n{finding.package_name} {finding.package_version or ''}"})

    blocks = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": f"{emoji} Security Finding: {finding.title[:60]}"},
        },
        {"type": "section", "fields": fields[:6]},
    ]

    if finding.description:
        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"*Description:*\n{finding.description[:400]}"},
        })

    blocks.append({
        "type": "actions",
        "elements": [
            {
                "type": "button",
                "text": {"type": "plain_text", "text": "View in Snitch"},
                "url": findings_url,
                "style": "primary",
            }
        ],
    })
    blocks.append({"type": "divider"})
    return blocks


def send_finding_notification(
    webhook_url: str,
    finding: "Finding",
    application: "Application",
    base_url: str = "",
) -> bool:
    severity = (finding.severity or "info").lower()
    colour = _SEVERITY_COLOURS.get(severity, "#a29bfe")
    payload = {
        "attachments": [
            {
                "color": colour,
                "blocks": _build_finding_blocks(finding, application, base_url),
            }
        ],
        "text": f"New {severity.upper()} finding in {application.name}: {finding.title}",
    }
    return _post(webhook_url, payload)


def send_scan_summary(
    webhook_url: str,
    scan_type: str,
    application_name: str,
    counts: dict,
    base_url: str = "",
) -> bool:
    total = sum(counts.values())
    critical = counts.get("critical", 0)
    high = counts.get("high", 0)
    url = f"{base_url}/applications.html" if base_url else "#"
    payload = {
        "text": f"Scan complete for {application_name}: {total} findings",
        "blocks": [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": f":mag: Scan Complete — {application_name}"},
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Scan Type:*\n{scan_type}"},
                    {"type": "mrkdwn", "text": f"*Total Findings:*\n{total}"},
                    {"type": "mrkdwn", "text": f"*:red_circle: Critical:*\n{critical}"},
                    {"type": "mrkdwn", "text": f"*:orange_circle: High:*\n{high}"},
                    {"type": "mrkdwn", "text": f"*:yellow_circle: Medium:*\n{counts.get('medium', 0)}"},
                    {"type": "mrkdwn", "text": f"*:blue_circle: Low:*\n{counts.get('low', 0)}"},
                ],
            },
            {
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "View Application"},
                        "url": url,
                        "style": "primary" if (critical + high) > 0 else None,
                    }
                ],
            },
        ],
    }
    # Remove None style
    btn = payload["blocks"][2]["elements"][0]
    if btn.get("style") is None:
        del btn["style"]

    return _post(webhook_url, payload)


def test_webhook(webhook_url: str) -> tuple[bool, str]:
    payload = {
        "text": ":white_check_mark: Snitch integration test — connection successful!",
        "blocks": [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": ":white_check_mark: *Snitch AppSec Platform*\nThis is a test message. Your Slack integration is configured correctly.",
                },
            }
        ],
    }
    ok = _post(webhook_url, payload)
    return ok, ("Connection successful" if ok else "Failed to post to webhook URL")


def _post(webhook_url: str, payload: dict) -> bool:
    try:
        resp = httpx.post(webhook_url, json=payload, timeout=10)
        if resp.status_code == 200:
            return True
        logger.warning("Slack webhook returned %d: %s", resp.status_code, resp.text)
        return False
    except Exception as exc:
        logger.error("Slack webhook error: %s", exc)
        return False
