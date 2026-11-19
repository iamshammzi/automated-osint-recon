import time
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests
from bs4 import BeautifulSoup

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept-Language": "en-US,en;q=0.9",
}

TIMEOUT = 8

# Platform definitions supporting status-code, API JSON, and content-based checks
PLATFORMS = [
    {
        "name": "GitHub",
        "category": "Developer",
        "url": "https://github.com/{u}",
        "check_url": "https://api.github.com/users/{u}",
        "mode": "github_api",
    },
    {
        "name": "Reddit",
        "category": "Social Media",
        "url": "https://www.reddit.com/user/{u}",
        "check_url": "https://www.reddit.com/user/{u}/about.json",
        "mode": "reddit_api",
    },
    {
        "name": "GitLab",
        "category": "Developer",
        "url": "https://gitlab.com/{u}",
        "check_url": "https://gitlab.com/api/v4/users?username={u}",
        "mode": "gitlab_api",
    },
    {
        "name": "HackerNews",
        "category": "Tech Forum",
        "url": "https://news.ycombinator.com/user?id={u}",
        "check_url": "https://hacker-news.firebaseio.com/v0/user/{u}.json",
        "mode": "hn_api",
    },
    {
        "name": "Bluesky",
        "category": "Social Media",
        "url": "https://bsky.app/profile/{u}.bsky.social",
        "check_url": "https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile?actor={u}.bsky.social",
        "mode": "bsky_api",
    },
    {
        "name": "YouTube",
        "category": "Video / Social",
        "url": "https://www.youtube.com/@{u}",
        "mode": "youtube_html",
    },
    {
        "name": "DEV Community",
        "category": "Blogging / Tech",
        "url": "https://dev.to/{u}",
        "mode": "status_html",
    },
    {
        "name": "Medium",
        "category": "Blogging",
        "url": "https://medium.com/@{u}",
        "mode": "status_html",
        "not_found_text": "Out of nothing, something.",
    },
    {
        "name": "Telegram",
        "category": "Messaging",
        "url": "https://t.me/{u}",
        "mode": "telegram_html",
    },
    {
        "name": "SoundCloud",
        "category": "Audio / Social",
        "url": "https://soundcloud.com/{u}",
        "mode": "status_html",
    },
    {
        "name": "Vimeo",
        "category": "Video",
        "url": "https://vimeo.com/{u}",
        "mode": "status_html",
    },
    {
        "name": "Linktree",
        "category": "Bio Aggregator",
        "url": "https://linktr.ee/{u}",
        "mode": "status_html",
    },
    {
        "name": "Keybase",
        "category": "Identity / Crypto",
        "url": "https://keybase.io/{u}",
        "mode": "status_html",
    },
    {
        "name": "Lichess",
        "category": "Gaming / Social",
        "url": "https://lichess.org/@/{u}",
        "check_url": "https://lichess.org/api/user/{u}",
        "mode": "status_only",
    },
    {
        "name": "npm",
        "category": "Developer",
        "url": "https://www.npmjs.com/~{u}",
        "mode": "status_html",
    },
    {
        "name": "Docker Hub",
        "category": "Developer",
        "url": "https://hub.docker.com/u/{u}",
        "check_url": "https://hub.docker.com/v2/users/{u}/",
        "mode": "status_only",
    },
    {
        "name": "Pastebin",
        "category": "Code / Text",
        "url": "https://pastebin.com/u/{u}",
        "mode": "status_html",
    },
    {
        "name": "Wikipedia",
        "category": "Knowledge",
        "url": "https://en.wikipedia.org/wiki/User:{u}",
        "mode": "status_html",
    },
]


def _extract_html_metadata(html_text):
    """Extracts public page title and meta description using BeautifulSoup."""
    metadata = {}
    try:
        soup = BeautifulSoup(html_text, "html.parser")
        if soup.title and soup.title.string:
            metadata["page_title"] = soup.title.string.strip()[:120]

        desc = soup.find("meta", attrs={"name": "description"}) or soup.find(
            "meta", attrs={"property": "og:description"}
        )
        if desc and desc.get("content"):
            metadata["bio_snippet"] = desc["content"].strip()[:200]
    except Exception:
        pass
    return metadata


def _check_single_platform(platform, username):
    profile_url = platform["url"].format(u=username)
    check_url = platform.get("check_url", profile_url).format(u=username)
    mode = platform["mode"]

    result = {
        "platform": platform["name"],
        "category": platform["category"],
        "url": profile_url,
        "status": "NOT_FOUND",
        "http_code": None,
        "response_time_ms": 0,
        "metadata": {},
    }

    start = time.perf_counter()
    try:
        req_headers = dict(HEADERS)
        if mode == "reddit_api":
            req_headers["User-Agent"] = "OSINT-Academic-Recon-Tool/1.0"

        resp = requests.get(
            check_url, headers=req_headers, timeout=TIMEOUT, allow_redirects=True
        )
        result["http_code"] = resp.status_code
        result["response_time_ms"] = round((time.perf_counter() - start) * 1000, 1)

        if mode == "github_api":
            if resp.status_code == 200:
                data = resp.json()
                result["status"] = "FOUND"
                result["metadata"] = {
                    k: v
                    for k, v in {
                        "display_name": data.get("name"),
                        "bio_snippet": data.get("bio"),
                        "company": data.get("company"),
                        "location": data.get("location"),
                        "website": data.get("blog"),
                        "public_repos": data.get("public_repos"),
                        "followers": data.get("followers"),
                        "account_created": data.get("created_at"),
                    }.items()
                    if v not in (None, "")
                }

        elif mode == "reddit_api":
            if resp.status_code == 200:
                data = resp.json().get("data", {})
                if data.get("name"):
                    result["status"] = "FOUND"
                    sub = data.get("subreddit") or {}
                    result["metadata"] = {
                        k: v
                        for k, v in {
                            "display_name": sub.get("title") or data.get("name"),
                            "bio_snippet": sub.get("public_description"),
                            "total_karma": data.get("total_karma"),
                        }.items()
                        if v not in (None, "")
                    }

        elif mode == "gitlab_api":
            if resp.status_code == 200:
                users = resp.json()
                if isinstance(users, list) and len(users) > 0:
                    user = users[0]
                    result["status"] = "FOUND"
                    result["metadata"] = {
                        k: v
                        for k, v in {
                            "display_name": user.get("name"),
                            "state": user.get("state"),
                        }.items()
                        if v not in (None, "")
                    }

        elif mode == "hn_api":
            if resp.status_code == 200 and resp.text.strip() != "null":
                data = resp.json()
                if isinstance(data, dict) and data.get("id"):
                    result["status"] = "FOUND"
                    result["metadata"] = {
                        k: v
                        for k, v in {
                            "karma": data.get("karma"),
                            "bio_snippet": (data.get("about") or "")[:200],
                        }.items()
                        if v not in (None, "")
                    }

        elif mode == "bsky_api":
            if resp.status_code == 200:
                data = resp.json()
                if data.get("handle"):
                    result["status"] = "FOUND"
                    result["metadata"] = {
                        k: v
                        for k, v in {
                            "display_name": data.get("displayName"),
                            "bio_snippet": (data.get("description") or "")[:200],
                            "followers": data.get("followersCount"),
                        }.items()
                        if v not in (None, "")
                    }

        elif mode == "telegram_html":
            if resp.status_code == 200 and (
                "tgme_page_title" in resp.text
            ):
                result["status"] = "FOUND"
                result["metadata"] = _extract_html_metadata(resp.text)

        elif mode == "youtube_html":
            if (
                resp.status_code == 200
                and "consent.youtube.com" not in resp.url
                and '"externalId"' in resp.text
            ):
                result["status"] = "FOUND"
                result["metadata"] = _extract_html_metadata(resp.text)

        elif mode == "status_only":
            if resp.status_code == 200:
                result["status"] = "FOUND"

        elif mode == "status_html":
            not_found_marker = platform.get("not_found_text")
            if resp.status_code == 200:
                if not_found_marker and not_found_marker in resp.text:
                    result["status"] = "NOT_FOUND"
                else:
                    result["status"] = "FOUND"
                    result["metadata"] = _extract_html_metadata(resp.text)

    except requests.exceptions.Timeout:
        result["status"] = "ERROR"
        result["error"] = "Request timed out"
        result["response_time_ms"] = round((time.perf_counter() - start) * 1000, 1)
    except requests.exceptions.RequestException as exc:
        result["status"] = "ERROR"
        result["error"] = str(exc)[:100]
        result["response_time_ms"] = round((time.perf_counter() - start) * 1000, 1)

    return result


def run_username_recon(username, max_workers=10, progress_callback=None):
    """
    Concurrently enumerates a username across configured public platforms
    and aggregates discovered profile metadata.
    """
    username = username.strip().lstrip("@")
    overall_start = time.perf_counter()
    results = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_map = {
            executor.submit(_check_single_platform, p, username): p
            for p in PLATFORMS
        }
        for future in as_completed(future_map):
            res = future.result()
            results.append(res)
            if progress_callback:
                progress_callback(res)

    results.sort(key=lambda r: (r["status"] != "FOUND", r["platform"]))
    elapsed = round(time.perf_counter() - overall_start, 2)

    found = [r for r in results if r["status"] == "FOUND"]
    errors = [r for r in results if r["status"] == "ERROR"]

    # Extract any external domains/websites discovered in profile metadata
    discovered_websites = []
    for item in found:
        site = item.get("metadata", {}).get("website")
        if site and site not in discovered_websites:
            discovered_websites.append(site)

    return {
        "target_username": username,
        "platforms_checked": len(PLATFORMS),
        "accounts_found": len(found),
        "errors_count": len(errors),
        "execution_time_sec": elapsed,
        "discovered_websites": discovered_websites,
        "results": results,
    }
