import asyncio
import os
import time
from pathlib import Path
from typing import Any

import httpx
from loguru import logger
from tqdm import tqdm

USER_AGENT = "vulnify/1.0.0"
TIMEOUT = 30
HEADERS = {
    "User-Agent": USER_AGENT,
    "Accept": "application/json",
}

# Status codes commonly returned by flaky upstreams where a retry may succeed.
_RETRYABLE_HTTP_STATUS_CODES = frozenset({408, 429, 502, 503, 504})


def _merge_request_headers(extra: dict[str, str] | None) -> dict[str, str]:
    merged = dict(HEADERS)
    if extra:
        merged.update(extra)
    return merged


def _backoff_sleep_sec(attempt: int, *, base_sec: float, max_sec: float) -> float:
    return min(max_sec, base_sec * (2**attempt))


def _retry_after_header_sec(response: httpx.Response | None) -> float | None:
    if response is None:
        return None
    raw = (response.headers.get("retry-after") or "").strip()
    if not raw:
        return None
    try:
        return float(raw)
    except ValueError:
        return None


async def fetch_json_maybe(
    url: str,
    *,
    max_attempts: int = 1,
    backoff_base_sec: float = 2.0,
    backoff_max_sec: float = 32.0,
    extra_headers: dict[str, str] | None = None,
    log_retries: bool = True,
) -> tuple[dict[str, Any], str | None]:
    """
    GET JSON into a dict. Returns ``(body, None)`` on HTTP success.

    Retries transient transport errors and select HTTP status codes. On permanent
    failure returns ``({}, error_detail)``.
    """

    attempts = max(1, int(max_attempts))
    headers = _merge_request_headers(extra_headers)
    last_detail = "no response"

    async with httpx.AsyncClient(timeout=TIMEOUT, headers=headers) as client:
        for attempt in range(attempts):
            response: httpx.Response | None = None
            try:
                response = await client.get(url)
                status = response.status_code
                if status in _RETRYABLE_HTTP_STATUS_CODES and attempt + 1 < attempts:
                    backoff = _backoff_sleep_sec(
                        attempt, base_sec=backoff_base_sec, max_sec=backoff_max_sec
                    )
                    ra = _retry_after_header_sec(response)
                    wait = max(backoff, ra) if ra is not None else backoff
                    last_detail = f"HTTP {status}"
                    if log_retries:
                        logger.debug(
                            "fetch_json_maybe retry after {delay:.1f}s ({reason}) attempt {cur}/{total} url={url!r}",
                            delay=wait,
                            reason=last_detail,
                            cur=attempt + 1,
                            total=attempts,
                            url=url,
                        )
                    await asyncio.sleep(wait)
                    continue
                response.raise_for_status()
            except httpx.RequestError as e:
                last_detail = str(e)
                if attempt + 1 < attempts:
                    wait = _backoff_sleep_sec(
                        attempt, base_sec=backoff_base_sec, max_sec=backoff_max_sec
                    )
                    if log_retries:
                        logger.debug(
                            "fetch_json_maybe retry after {delay:.1f}s ({reason}) attempt {cur}/{total} url={url!r}",
                            delay=wait,
                            reason=last_detail,
                            cur=attempt + 1,
                            total=attempts,
                            url=url,
                        )
                    await asyncio.sleep(wait)
                    continue
                return {}, last_detail

            except httpx.HTTPStatusError as e:
                body = getattr(e.response, "text", None) or ""
                frag = body[:200].replace("\n", " ") if body else ""
                last_detail = f"HTTP {e.response.status_code} {frag}".strip()
                return {}, last_detail

            assert response is not None
            try:
                parsed = response.json()
            except ValueError as e:
                return {}, f"invalid JSON ({e})"
            if not isinstance(parsed, dict):
                return {}, "response JSON was not an object"
            return parsed, None


async def fetch_json(url: str) -> dict:
    """
    Fetch JSON from a URL.

    :param url: The URL to fetch JSON from.
    :type url: str
    :return: The JSON data.
    :rtype: dict
    """

    data, err = await fetch_json_maybe(url, max_attempts=1)
    if err is not None:
        logger.error(f"Failed to fetch JSON from {url}: {err}")
    return data


async def download_file(url: str, output_file_name: str) -> bool:
    """
    Stream a URL to a local file (any content type — tarball, CSV, JSON, zip).

    Follows redirects (GitHub/GitLab raw endpoints bounce through codeload) and
    shows a tqdm progress bar. Returns ``True`` on success, ``False`` on any
    transport or HTTP error (logged, not raised).

    :param url: The URL to download.
    :type url: str
    :param output_file_name: Destination path; parent dirs are created.
    :type output_file_name: str
    :return: True if the file was downloaded successfully, False otherwise.
    :rtype: bool
    """

    output_file_path = _prepare_download_path(output_file_name)
    logger.info(f"Downloading {url} to {output_file_path}")

    try:
        async with httpx.AsyncClient(timeout=TIMEOUT, headers=HEADERS) as client:
            async with client.stream("GET", url, follow_redirects=True) as response:
                response.raise_for_status()
                await _write_response_body_to_file(response, output_file_path)
    except Exception as e:
        logger.error(f"Failed to download {url}: {e}")
        return False

    logger.info(f"Downloaded {url} to {output_file_path}")
    return True


#: How long a fetched upstream file may be reused before it is re-downloaded.
#: Every source this is used for (exploit corpora, the KEV catalog) moves daily.
CACHE_MAX_AGE_SEC = 24 * 60 * 60


def cache_is_fresh(path: Path, max_age_sec: float = CACHE_MAX_AGE_SEC) -> bool:
    """True when ``path`` exists and was written within ``max_age_sec``."""
    try:
        return time.time() - path.stat().st_mtime < max_age_sec
    except OSError:
        return False


async def fetch_cached(
    url: str,
    dest: Path,
    *,
    max_age_sec: float = CACHE_MAX_AGE_SEC,
    force: bool = False,
) -> Path | None:
    """
    Return ``dest``, re-downloading it when it is missing, stale, or ``force``.

    🚨 **A cache without an expiry is a pin nobody chose.** The exploit-corpus
    cache used to be reused while it existed, and a release built in September
    shipped June corpora. Staleness is judged by mtime, and a download lands in
    a ``.part`` file that replaces ``dest`` only when complete, so a failed
    fetch never truncates a good copy.

    On a failed refresh the stale copy is returned with a warning — an old
    corpus whose watermark says what it is beats no corpus — and ``None`` only
    when there is nothing on disk at all.

    :param url: Upstream URL.
    :param dest: Cache path.
    :param max_age_sec: Reuse ``dest`` if younger than this.
    :param force: Re-download regardless of age.
    :return: A usable path, or ``None``.
    """
    if not force and cache_is_fresh(dest, max_age_sec):
        logger.info(f"Using cached {dest} (fresh)")
        return dest
    part = dest.with_name(dest.name + ".part")
    if await download_file(url, str(part)):
        os.replace(part, dest)
        return dest
    part.unlink(missing_ok=True)
    if dest.is_file():
        logger.warning(f"Refresh of {url} failed; using stale cached {dest}")
        return dest
    return None


async def download_zip(url: str, output_file_name: str) -> bool:
    """
    Download a zip file from a URL.

    Thin alias over :func:`download_file` kept for the existing cvelistV5 call
    site; the streaming logic is content-type agnostic.

    :param url: The URL to download the zip file from.
    :type url: str
    :param output_file_name: The name of the file to download the zip file to.
    :type output_file_name: str
    :return: True if the zip file was downloaded successfully, False otherwise.
    :rtype: bool
    """

    return await download_file(url, output_file_name)


def _content_length_total(headers: httpx.Headers) -> int | None:
    """
    Get the total content length of a response.

    :param headers: The headers of the response.
    :type headers: httpx.Headers
    :return: The total content length of the response.
    :rtype: int | None
    """
    raw = headers.get("content-length")
    if raw is None:
        return None
    try:
        return int(raw)
    except ValueError:
        return None


def _prepare_download_path(output_file_name: str) -> Path:
    """
    Prepare the download path.

    :param output_file_name: The name of the file to download the zip file to.
    :type output_file_name: str
    :return: The path to the download file.
    :rtype: Path
    """
    path = Path(output_file_name)
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


async def _write_response_body_to_file(response: httpx.Response, dest: Path) -> None:
    """
    Write the response body to a file.

    :param response: The response to write the body to.
    :type response: httpx.Response
    :param dest: The path to the download file.
    :type dest: Path
    """
    total = _content_length_total(response.headers)
    if total is None:
        total = 0
    with (
        open(dest, "wb") as f,
        tqdm(
            total=int(total),
            unit="B",
            unit_scale=True,
            unit_divisor=1024,
            desc=dest.name,
        ) as pbar,
    ):
        async for chunk in response.aiter_bytes():
            f.write(chunk)
            pbar.update(len(chunk))
