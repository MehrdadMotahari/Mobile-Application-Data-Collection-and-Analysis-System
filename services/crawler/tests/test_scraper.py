from scraper import PlayStoreScraper

from tests.builders import StubPlayStore, raw_review, stub_scraper


def test_returns_at_most_the_requested_count():
    scraper = stub_scraper(StubPlayStore(review_count=5))

    assert len(scraper.get_latest_reviews("pkg", count=3)) == 3


def test_reviews_repeated_across_locales_are_deduplicated():
    scraper = stub_scraper(StubPlayStore(review_count=2))

    ids = [r["review_id"] for r in scraper.get_latest_reviews("pkg")]

    assert sorted(ids) == ["pkg-1", "pkg-2"]


def test_reviews_without_an_id_are_dropped():
    scraper = stub_scraper(StubPlayStore(raw_reviews=[raw_review("a"), {"userName": "x"}]))

    assert [r["review_id"] for r in scraper.get_latest_reviews("pkg")] == ["a"]


def test_follows_the_continuation_token_across_pages(monkeypatch):
    monkeypatch.setattr("scraper.time.sleep", lambda seconds: None)
    pages = {None: ([raw_review("r1"), raw_review("r2")], "t1"), "t1": ([raw_review("r3")], None)}

    def fetch_page(package_name, **kwargs):
        return pages[kwargs.get("continuation_token")]

    scraper = PlayStoreScraper(fetch_reviews_page=fetch_page)

    assert sorted(r["review_id"] for r in scraper.get_latest_reviews("pkg")) == ["r1", "r2", "r3"]