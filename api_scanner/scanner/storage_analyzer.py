"""
Storage analyzer for extracting browser storage data.

Provides the StorageAnalyzer class which extracts localStorage,
sessionStorage, and cookies from a Playwright page context.
"""

from typing import Any

from api_scanner.logger import setup_logger
from api_scanner.scanner.models import CookieData, StorageData


class StorageAnalyzer:
    """Extracts and analyzes browser storage data from a page.

    Extracts localStorage, sessionStorage, and cookies from a
    Playwright page and its browser context, returning typed
    StorageData instances.
    """

    def __init__(self) -> None:
        """Initialize the StorageAnalyzer with a logger."""
        self._logger = setup_logger(__name__)

    async def analyze(self, page: Any) -> StorageData:
        """Extract all storage data from a Playwright page.

        Retrieves localStorage, sessionStorage via JavaScript evaluation,
        and cookies from the browser context.

        Args:
            page: A Playwright Page object to extract storage from.

        Returns:
            StorageData instance containing all extracted storage information.
        """
        self._logger.info("Analyzing browser storage data")

        local_storage = await self._extract_local_storage(page)
        session_storage = await self._extract_session_storage(page)
        cookies = await self._extract_cookies(page)

        storage_data = StorageData(
            local_storage=local_storage,
            session_storage=session_storage,
            cookies=cookies,
        )

        self._logger.info(
            "Storage analysis complete: %d localStorage items, "
            "%d sessionStorage items, %d cookies",
            len(local_storage),
            len(session_storage),
            len(cookies),
        )

        return storage_data

    async def _extract_local_storage(self, page: Any) -> dict[str, str]:
        """Extract localStorage key-value pairs from the page.

        Args:
            page: A Playwright Page object.

        Returns:
            Dictionary of localStorage key-value pairs.
        """
        try:
            result = await page.evaluate("""() => {
                const items = {};
                try {
                    for (let i = 0; i < localStorage.length; i++) {
                        const key = localStorage.key(i);
                        if (key !== null) {
                            items[key] = localStorage.getItem(key) || '';
                        }
                    }
                } catch (e) {
                    // localStorage may not be accessible (e.g., sandboxed iframes)
                }
                return items;
            }""")
            return result if result else {}
        except Exception as e:
            self._logger.warning("Failed to extract localStorage: %s", str(e))
            return {}

    async def _extract_session_storage(self, page: Any) -> dict[str, str]:
        """Extract sessionStorage key-value pairs from the page.

        Args:
            page: A Playwright Page object.

        Returns:
            Dictionary of sessionStorage key-value pairs.
        """
        try:
            result = await page.evaluate("""() => {
                const items = {};
                try {
                    for (let i = 0; i < sessionStorage.length; i++) {
                        const key = sessionStorage.key(i);
                        if (key !== null) {
                            items[key] = sessionStorage.getItem(key) || '';
                        }
                    }
                } catch (e) {
                    // sessionStorage may not be accessible
                }
                return items;
            }""")
            return result if result else {}
        except Exception as e:
            self._logger.warning("Failed to extract sessionStorage: %s", str(e))
            return {}

    async def _extract_cookies(self, page: Any) -> list[CookieData]:
        """Extract cookies from the browser context.

        Args:
            page: A Playwright Page object (used to access the context).

        Returns:
            List of CookieData objects representing all cookies.
        """
        try:
            context = page.context
            raw_cookies = await context.cookies()

            cookies: list[CookieData] = []
            for cookie in raw_cookies:
                cookie_data = CookieData(
                    name=cookie.get("name", ""),
                    value=cookie.get("value", ""),
                    domain=cookie.get("domain", ""),
                    path=cookie.get("path", "/"),
                    secure=cookie.get("secure", False),
                    http_only=cookie.get("httpOnly", False),
                    expires=str(cookie.get("expires", "")) if cookie.get("expires") else None,
                )
                cookies.append(cookie_data)

            return cookies
        except Exception as e:
            self._logger.warning("Failed to extract cookies: %s", str(e))
            return []
