"""
Alert Service
=============
Sends alerts for critical scan findings via:
- AWS CloudWatch (always)
- AWS SNS (if configured)
"""

from app.models.schemas import ScanReport
from app.utils.aws_cloudwatch import CloudWatchLogger
from app.utils.logger import get_logger
from app.config import settings

logger = get_logger(__name__)


class AlertService:
    def __init__(self):
        self.cw = CloudWatchLogger()

    async def send_alert(self, report: ScanReport) -> None:
        """Trigger an alert for a scan with critical findings."""
        if not report.score:
            return

        alert_payload = {
            "scan_id": report.scan_id,
            "url": report.url,
            "score": str(report.score.total),
            "grade": report.score.grade,
            "critical_count": str(report.score.critical_count),
            "high_count": str(report.score.high_count),
            "alert_reason": "CRITICAL_VULNERABILITY_DETECTED",
        }

        # Always log to CloudWatch
        self.cw.log_event("SECURITY_ALERT", alert_payload)
        logger.warning(
            f"🚨 ALERT [{report.scan_id}] Critical issues found at {report.url} "
            f"(score={report.score.total}, critical={report.score.critical_count})"
        )

        # Optional: publish to SNS
        if settings.ALERT_SNS_TOPIC_ARN:
            await self._publish_sns(alert_payload)

    async def _publish_sns(self, payload: dict) -> None:
        """Publish alert to AWS SNS topic."""
        try:
            import boto3
            import json

            sns = boto3.client("sns", region_name=settings.AWS_REGION)
            sns.publish(
                TopicArn=settings.ALERT_SNS_TOPIC_ARN,
                Subject="[Cloud Security Scanner] Critical vulnerability detected",
                Message=json.dumps(payload, indent=2),
                MessageAttributes={
                    "AlertType": {"DataType": "String", "StringValue": "SECURITY_ALERT"},
                    "Grade": {"DataType": "String", "StringValue": payload.get("grade", "F")},
                },
            )
            logger.info(f"SNS alert published for scan {payload['scan_id']}")
        except Exception as exc:
            logger.error(f"SNS publish failed: {exc}", exc_info=True)
