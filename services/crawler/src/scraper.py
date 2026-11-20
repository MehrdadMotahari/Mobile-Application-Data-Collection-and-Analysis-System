import random
import time
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from configs import (
    AIMD_DECREASE_STEP,
    AIMD_INCREASE_FACTOR,
    BASE_BACKOFF,
    COUNTRY_CODE,
    INITIAL_ADAPTIVE_DELAY,
    LANG_CODE,
    MAX_ADAPTIVE_DELAY,
    MAX_BACKOFF,
    MAX_RETRIES,
    MIN_ADAPTIVE_DELAY,
    MIN_JITTER_SECONDS,
    RATE_LIMIT_MARKERS,
    TARGET_REVIEWS_COUNT,
    POLITE_JITTER_RANGE,
    REVIEW_LOCALES,
    REVIEWS_BATCH_SIZE,
)

from google_play_scraper import Sort, app, reviews
from google_play_scraper.exceptions import NotFoundError
from models import AppMetrics, Review

from utils.logging_setup import get_logger

logger = get_logger(__name__)


class PlayStoreScraper:
    """Fetches app metrics and reviews from the Play Store with retry/backoff."""

    def __init__(
        self,
        fetch_app_details: Callable[..., Any] = app,
        fetch_reviews_page: Callable[..., Any] = reviews,
    ) -> None:
        """Accept the Play Store calls as injectable dependencies; the defaults hit the real store."""
        self.fetch_app_details = fetch_app_details
        self.fetch_reviews_page = fetch_reviews_page

        self.max_retries = MAX_RETRIES
        self.base_backoff = BASE_BACKOFF
        self.max_backoff = MAX_BACKOFF

        self.adaptive_delay = INITIAL_ADAPTIVE_DELAY
        self.min_delay = MIN_ADAPTIVE_DELAY
        self.max_delay = MAX_ADAPTIVE_DELAY


    def get_app_metrics(self, package_name: str) -> AppMetrics | None:
        for attempt in range(1, self.max_retries + 1):
            try:
                raw = self.fetch_app_details(
                    package_name, lang=LANG_CODE, country=COUNTRY_CODE
                )
            except NotFoundError:
                logger.warning("App not found on Play Store: %s", package_name)
                return None
            except Exception as exc:
                is_rate_limited = any(m in str(exc) for m in RATE_LIMIT_MARKERS)
                if is_rate_limited:
                    self.adaptive_delay = min(
                        self.max_delay, self.adaptive_delay * AIMD_INCREASE_FACTOR
                    )
                if attempt == self.max_retries:
                    logger.error("Giving up on %s: %s", package_name, exc)
                    return None
                backoff = min(self.max_backoff, self.base_backoff ** attempt)
                backoff += random.uniform(MIN_JITTER_SECONDS, MIN_JITTER_SECONDS * 2)
                logger.warning(
                    "Attempt %d/%d failed for %s: %s; retrying in %.1fs",
                    attempt, self.max_retries, package_name, exc, backoff,
                )
                time.sleep(backoff)
                continue

            self.adaptive_delay = max(
                self.min_delay, self.adaptive_delay - AIMD_DECREASE_STEP
            )

            if not raw:
                logger.warning("Empty app payload for %s", package_name)
                return None
            
            return AppMetrics.from_scraped_payload(raw, datetime.now(UTC).isoformat())
        
        return None


    def get_latest_reviews(self, package_name: str, count: int = TARGET_REVIEWS_COUNT) -> list[dict[str, Any]]:
        """Newest reviews across the configured locales, deduplicated by review id, capped at count."""
        scraped_at = datetime.now(UTC).isoformat()
        collected: dict[str, Review] = {}

        for lang, country in REVIEW_LOCALES:
            for raw in self._collect_locale_reviews(package_name, lang, country, count):
                review = Review.from_scraped_payload(raw, scraped_at)
                if review is not None and review.review_id not in collected:
                    collected[review.review_id] = review

        newest_first = sorted(collected.values(), key=lambda r: r.review_at or "", reverse=True)
        return [review.to_record() for review in newest_first[:count]]

    def _collect_locale_reviews(self, package_name: str, lang: str, country: str, count: int) -> list[dict[str, Any]]:
        """Page through one locale's newest reviews until count is reached or pages run out."""
        results: list[dict[str, Any]] = []
        token = None
        while len(results) < count:
            page = self._fetch_reviews_page_with_retry(
                package_name,
                lang=lang,
                country=country,
                sort=Sort.NEWEST,
                count=min(REVIEWS_BATCH_SIZE, count - len(results)),
                continuation_token=token,
            )
            if page is None:
                break
            batch, token = page
            results.extend(batch)
            if not batch or token is None:
                break
            time.sleep(self.adaptive_delay + random.uniform(*POLITE_JITTER_RANGE))
        return results

    def _fetch_reviews_page_with_retry(self, package_name: str, **kwargs: Any):
        """One reviews request with backoff; None when the app is missing or retries are exhausted."""
        for attempt in range(1, self.max_retries + 1):
            try:
                page = self.fetch_reviews_page(package_name, **kwargs)
            except NotFoundError:
                logger.warning("App not found for reviews: %s", package_name)
                return None
            except Exception as exc:
                if any(m in str(exc) for m in RATE_LIMIT_MARKERS):
                    self.adaptive_delay = min(self.max_delay, self.adaptive_delay * AIMD_INCREASE_FACTOR)
                if attempt == self.max_retries:
                    logger.error("Giving up on reviews for %s: %s", package_name, exc)
                    return None
                backoff = min(self.max_backoff, self.base_backoff ** attempt)
                backoff += random.uniform(MIN_JITTER_SECONDS, MIN_JITTER_SECONDS * 2)
                logger.warning("Reviews attempt %d/%d failed for %s: %s; retrying in %.1fs",
                            attempt, self.max_retries, package_name, exc, backoff)
                time.sleep(backoff)
                continue
            self.adaptive_delay = max(self.min_delay, self.adaptive_delay - AIMD_DECREASE_STEP)
            return page
        return None
