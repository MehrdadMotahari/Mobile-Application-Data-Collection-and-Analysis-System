from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from typing import Any

from configs import FALLBACK_VERSION_LABEL


@dataclass(frozen=True)
class Review:
    """One Play Store review, translated from the raw scraper payload into the reviews-table shape."""

    review_id: str
    user_name: str | None
    score: int | None
    thumbs_up_count: int
    content: str
    review_at: str | None
    scraped_at: str

    @classmethod
    def from_scraped_payload(cls, payload: dict[str, Any], scraped_at: str) -> "Review | None":
        """Translate one raw review; a review without an id cannot be stored, so it yields None."""
        review_id = payload.get("reviewId")
        if not review_id:
            return None

        reviewed_at = payload.get("at")
        return cls(
            review_id=review_id,
            user_name=payload.get("userName"),
            score=payload.get("score"),
            thumbs_up_count=payload.get("thumbsUpCount") or 0,
            content=payload.get("content") or "",
            review_at=reviewed_at.isoformat() if isinstance(reviewed_at, datetime) else None,
            scraped_at=scraped_at,
        )

    def to_record(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class AppMetrics:
    """One app's store metrics, translated from the raw scraper payload into the app_metrics-table shape."""

    min_installs: int | None
    real_installs: int | None
    score: float
    ratings: int | None
    reviews_count: int | None
    version: str
    ad_supported: bool
    store_updated_at: str | None
    scraped_at: str

    @classmethod
    def from_scraped_payload(cls, payload: dict[str, Any], scraped_at: str) -> "AppMetrics":
        """Translate one raw app payload, applying the documented fallbacks for missing fields."""
        updated = payload.get("updated")
        store_updated_at = (
            datetime.fromtimestamp(updated, tz=UTC).isoformat()
            if isinstance(updated, (int, float))
            else None
        )
        return cls(
            min_installs=payload.get("minInstalls"),
            real_installs=payload.get("realInstalls"),
            score=round(payload.get("score") or 0.0, 2),
            ratings=payload.get("ratings"),
            reviews_count=payload.get("reviews"),
            version=payload.get("version") or FALLBACK_VERSION_LABEL,
            ad_supported=bool(payload.get("adSupported")),
            store_updated_at=store_updated_at,
            scraped_at=scraped_at,
        )

    def to_record(self) -> dict[str, Any]:
        return asdict(self)

    