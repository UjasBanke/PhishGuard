"""Generate the PhishGuard SYNTHETIC demo dataset.

*** SYNTHETIC / DEMO DATA ***
Every URL produced here is fabricated by rule-based templates so the project is
runnable offline and contains no real phishing links. It is NOT a real-world
benchmark: metrics measured on it say nothing about accuracy on live traffic.
For production use, train on a real labelled corpus (e.g. PhishTank / OpenPhish
for phishing, Tranco / Common Crawl for benign URLs).

Usage:
    python data/generate_demo_dataset.py            # writes data/demo_urls.csv
    python data/generate_demo_dataset.py --n 6000   # per-class size
"""
from __future__ import annotations

import argparse
import json
import random
import string
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONFIG = json.loads((ROOT / "feature_engineering" / "feature_config.json").read_text(encoding="utf-8"))

WORDS = ("river stone cloud maple garden bright coffee harbor pixel meadow falcon orbit lotus "
         "canyon willow ember quartz summit breeze lumen anchor beacon cedar delta echo forge "
         "glacier haven island jasper kernel lantern mosaic nimbus oasis prairie quill raven "
         "saffron tundra umbra velvet whisper yonder zenith cotton bamboo copper silver north "
         "east travel fitness recipes photo books music movies games health science school "
         "campus market studio design travel news daily weekly tech code data learn").split()
LEGIT_BASES = ("wikipedia.org github.com stackoverflow.com nytimes.com bbc.co.uk reddit.com medium.com "
               "mozilla.org python.org apache.org kernel.org nasa.gov nih.gov mit.edu stanford.edu "
               "ox.ac.uk iitb.ac.in isro.gov.in thehindu.com indiatimes.com flipkart.com zomato.com "
               "swiggy.com spotify.com twitch.tv cloudflare.com digitalocean.com npmjs.com pypi.org "
               "docker.com kubernetes.io ubuntu.com debian.org archlinux.org imdb.com goodreads.com "
               "etsy.com ikea.com nike.com bbc.com cnn.com theguardian.com techcrunch.com wired.com").split()
LEGIT_TLDS = ["com"] * 55 + ["org"] * 12 + ["net"] * 6 + ["io"] * 5 + ["in"] * 5 + ["co.uk"] * 3 + \
             ["edu"] * 3 + ["gov"] * 2 + ["ac.in"] * 2 + ["co"] * 2 + ["de", "fr", "ca", "au", "dev", "app", "xyz"]
COMMON_TLDS = ["com", "net", "org", "info", "online", "site", "co", "live", "store", "club", "me"]
SUS_TLDS = CONFIG["suspicious_tlds"]
KEYWORDS = ["login", "verify", "account", "secure", "signin", "update", "password", "banking",
            "confirm", "wallet", "authenticate", "billing", "unlock", "recover", "validate"]
BRANDS = list(CONFIG["brands"].keys())
OFFICIAL = CONFIG["brands"]
SHORTENERS = CONFIG["url_shorteners"]
FREE_HOSTS = ["weebly.com", "000webhostapp.com", "web.app", "blogspot.com", "wixsite.com",
              "netlify.app", "github.io", "herokuapp.com", "glitch.me", "pages.dev"]
EXTS = ["php", "html", "asp", "aspx", "jsp"]


class Gen:
    def __init__(self, seed: int):
        self.r = random.Random(seed)

    # ---- primitives -------------------------------------------------------
    def word(self) -> str:
        return self.r.choice(WORDS)

    def rand(self, n: int, digits: bool = True) -> str:
        pool = string.ascii_lowercase + (string.digits if digits else "")
        return "".join(self.r.choice(pool) for _ in range(n))

    def n(self, a: int = 1, b: int = 9999) -> int:
        return self.r.randint(a, b)

    def ip(self) -> str:
        return ".".join(str(self.r.randint(1, 254)) for _ in range(4))

    def leet(self, s: str) -> str:
        table = {"a": "4", "e": "3", "o": "0", "l": "1", "i": "1", "s": "5"}
        idx = [i for i, c in enumerate(s) if c in table]
        if not idx:
            return s
        i = self.r.choice(idx)
        return s[:i] + table[s[i]] + s[i + 1:]

    def official_domain(self, brand: str) -> str:
        return self.r.choice(OFFICIAL[brand])

    # ---- legitimate -------------------------------------------------------
    def legit_domain(self) -> str:
        roll = self.r.random()
        if roll < 0.35:
            return self.r.choice(LEGIT_BASES)
        tld = self.r.choice(LEGIT_TLDS)
        if roll < 0.55:
            return f"{self.word()}-{self.word()}.{tld}"
        if roll < 0.60:
            return f"{self.word()}{self.r.choice(['24', '360', '365', '3d', '2go'])}.{tld}"
        if roll < 0.64:
            return f"{self.word()}{self.word()}.{self.r.choice(['xyz', 'top', 'online', 'site'])}"
        if roll < 0.67:
            return f"{self.word()}.{self.r.choice(FREE_HOSTS[4:])}"
        return f"{self.word()}{self.word() if self.r.random() < 0.5 else ''}.{tld}"

    def legit_path(self) -> str:
        w, r = self.word, self.r
        options = [
            lambda: "", lambda: "/", lambda: "/about", lambda: "/contact", lambda: "/pricing",
            lambda: f"/products/{w()}-{self.n()}", lambda: f"/blog/{self.n(2015, 2026)}/{self.n(1, 12):02d}/{w()}-{w()}-{w()}",
            lambda: f"/wiki/{w().title()}_{w().title()}", lambda: f"/search?q={w()}+{w()}",
            lambda: f"/docs/{w()}/{w()}/{w()}", lambda: f"/category/{w()}?page={self.n(1, 40)}",
            lambda: f"/en/{w()}/{w()}", lambda: f"/user/{self.n()}/profile", lambda: f"/help/articles/{self.n(1000, 99999)}",
            lambda: f"/watch?v={self.rand(11)}", lambda: f"/dp/B0{self.rand(8).upper()}",
            lambda: f"/{w()}/{w()}.html", lambda: f"/news/{w()}-{w()}-{w()}-{w()}-{w()}-{w()}-{self.n(100000, 999999)}",
            lambda: f"/{w()}?utm_source=newsletter&utm_medium=email&utm_campaign={w()}&ref={self.rand(6)}",
            lambda: f"/store/{w()}?id={self.n()}&sort=price&order=asc&color={w()}&size={self.n(1, 12)}&page={self.n(1, 9)}",
            lambda: f"/login", lambda: "/signin", lambda: "/account/settings", lambda: "/account/orders",
            lambda: "/security/overview", lambda: "/password/reset", lambda: "/secure/checkout",
            lambda: f"/account/login?next=/{w()}", lambda: "/signup", lambda: "/verify-email/success",
        ]
        weights = [3, 6, 3, 2, 2, 5, 5, 4, 5, 4, 4, 3, 3, 3, 3, 2, 4, 3, 3, 2, 2, 3, 3, 2, 2, 2, 2, 2, 2, 1]
        return self.r.choices(options, weights)[0]()

    def legit(self) -> str:
        r = self.r
        roll = r.random()
        scheme = "https" if r.random() < 0.9 else "http"
        if roll < 0.14:  # official brand domain, often with auth-like paths
            brand = r.choice(BRANDS)
            dom = self.official_domain(brand)
            sub = r.choice(["www", "www", "", "accounts", "login", "secure", "support", "mail", "help", "m", "developer"])
            host = f"{sub}.{dom}" if sub else dom
            path = r.choice(["", "/", "/signin", "/login", "/account", "/security", "/help", f"/{self.word()}",
                             f"/support/{self.word()}", "/account/manage", f"/products/{self.word()}-{self.n()}"])
            return f"{scheme}://{host}{path}"
        if roll < 0.155:  # legitimate shortener use
            return f"https://{r.choice(SHORTENERS)}/{self.rand(7, digits=True)}"
        if roll < 0.165:  # internal / dev hosts
            return f"http://{r.choice(['192.168', '10.0', '172.16'])}.{self.n(0, 254)}.{self.n(1, 254)}:{r.choice([8080, 3000, 8000, 5000])}/{r.choice(['admin', 'dashboard', 'status', ''])}"
        dom = self.legit_domain()
        sub_roll = r.random()
        if sub_roll < 0.38:
            host = f"www.{dom}"
        elif sub_roll < 0.65:
            host = dom
        elif sub_roll < 0.97:
            host = f"{r.choice(['blog', 'docs', 'mail', 'shop', 'news', 'api', 'app', 'learn', 'careers', 'cdn', 'status', 'community'])}.{dom}"
        else:
            host = f"{r.choice(['eu', 'us', 'staging'])}.{r.choice(['app', 'api', 'docs'])}.{dom}"
        port = f":{r.choice([8080, 8443, 3000])}" if r.random() < 0.01 else ""
        return f"{scheme}://{host}{port}{self.legit_path()}"

    # ---- phishing ---------------------------------------------------------
    def evil_domain(self, prefer_sus: float = 0.55) -> str:
        tld = self.r.choice(SUS_TLDS) if self.r.random() < prefer_sus else self.r.choice(COMMON_TLDS)
        style = self.r.random()
        if style < 0.35:
            base = f"{self.word()}-{self.word()}"
        elif style < 0.6:
            base = f"{self.word()}{self.n(1, 999)}"
        elif style < 0.8:
            base = self.rand(self.r.randint(8, 16))
        else:
            base = f"{self.word()}{self.word()}-{self.r.choice(KEYWORDS)}"
        return f"{base}.{tld}"

    def phish_path(self, brand: str | None = None) -> str:
        r, kw = self.r, self.r.choice(KEYWORDS)
        options = [
            lambda: f"/{kw}", lambda: f"/{kw}.{r.choice(EXTS)}", lambda: f"/{kw}/{self.rand(8)}",
            lambda: f"/{brand or self.word()}/{kw}.{r.choice(EXTS)}",
            lambda: f"/wp-content/{self.word()}/{kw}/index.{r.choice(EXTS)}",
            lambda: f"/{kw}?id={self.rand(10)}&session={self.rand(16)}&token={self.rand(12)}",
            lambda: f"/{kw}-{r.choice(KEYWORDS)}/{self.rand(6)}/index.{r.choice(EXTS)}?email={self.word()}@{self.word()}.com",
            lambda: f"/{self.rand(6)}/{kw}/", lambda: "/", lambda: "",
            lambda: f"/{brand or self.word()}/{kw}/{r.choice(KEYWORDS)}.{r.choice(EXTS)}?cmd=_{kw}&dispatch={self.rand(24)}",
        ]
        weights = [5, 5, 4, 5, 3, 4, 2, 2, 2, 1, 2]
        return r.choices(options, weights)[0]()

    def phish(self) -> str:
        r = self.r
        brand = r.choice(BRANDS)
        scheme = "https" if r.random() < 0.55 else "http"
        kw = r.choice(KEYWORDS)
        kind = r.choices(
            ["brand_sub", "brand_hyphen", "ip", "many_sub", "at", "shortener", "stuffed",
             "punycode", "clean", "freehost", "leet", "brand_path"],
            [15, 15, 8, 9, 5, 4, 10, 3, 10, 8, 6, 7])[0]
        if kind == "brand_sub":
            return f"{scheme}://{brand}.{r.choice(KEYWORDS)}-{self.word()}.{r.choice(SUS_TLDS + COMMON_TLDS)}{self.phish_path(brand)}"
        if kind == "brand_hyphen":
            pat = r.choice([f"{brand}-{kw}", f"{kw}-{brand}", f"{brand}{kw}", f"secure-{brand}-{kw}", f"{brand}-{self.word()}-{kw}"])
            sub = f"{r.choice(['www', 'login', 'my'])}." if r.random() < 0.4 else ""
            return f"{scheme}://{sub}{pat}.{r.choice(SUS_TLDS + COMMON_TLDS)}{self.phish_path(brand)}"
        if kind == "ip":
            port = f":{r.choice([8080, 8888, 81, 443, 8000])}" if r.random() < 0.3 else ""
            return f"http://{self.ip()}{port}{self.phish_path(brand if r.random() < 0.5 else None)}"
        if kind == "many_sub":
            labels = [r.choice([kw, brand, "secure", "account", "www", "login", "update", self.word()]) for _ in range(r.randint(3, 6))]
            return f"{scheme}://{'.'.join(labels)}.{self.evil_domain()}{self.phish_path()}"
        if kind == "at":
            official = self.official_domain(brand)
            tail = self.evil_domain(0.6)
            sep = "@" if r.random() < 0.8 else "%40"
            return f"{scheme}://{official}{sep}{tail}{self.phish_path(brand)}"
        if kind == "shortener":
            return f"{r.choice(['http', 'https'])}://{r.choice(SHORTENERS)}/{self.rand(r.randint(5, 8))}"
        if kind == "stuffed":
            return f"{scheme}://{self.evil_domain()}{self.phish_path(brand)}/{r.choice(KEYWORDS)}/{r.choice(KEYWORDS)}.{r.choice(EXTS)}"
        if kind == "punycode":
            return f"https://xn--{self.rand(r.randint(5, 9), digits=False)}-{self.rand(3, digits=False)}.{r.choice(COMMON_TLDS + SUS_TLDS)}/{kw}"
        if kind == "clean":  # deliberately hard: looks like an ordinary site
            return f"https://{self.word()}-{self.word()}.{r.choice(['com', 'net', 'org', 'co'])}/{r.choice([kw, 'portal', 'access', 'my'])}"
        if kind == "freehost":
            return f"https://{brand if r.random() < 0.5 else self.word()}-{r.choice(KEYWORDS)}.{r.choice(FREE_HOSTS)}{self.phish_path()}"
        if kind == "leet":
            return f"{scheme}://{self.leet(brand)}{r.choice(['', '-' + kw, '-support', '-online'])}.{r.choice(SUS_TLDS + COMMON_TLDS)}{self.phish_path(brand)}"
        # brand_path: unrelated domain hosting a brand-named folder
        return f"{scheme}://{self.evil_domain(0.3)}/{brand}/{kw}.{r.choice(EXTS)}?{r.choice(['ref', 'id', 'sid'])}={self.rand(9)}"


def build(n_per_class: int, seed: int) -> list[tuple[str, int]]:
    g = Gen(seed)
    seen: set[str] = set()
    rows: list[tuple[str, int]] = []
    for label, fn in ((0, g.legit), (1, g.phish)):
        count, guard = 0, 0
        while count < n_per_class and guard < n_per_class * 50:
            guard += 1
            url = fn()
            if url in seen:
                continue
            seen.add(url)
            rows.append((url, label))
            count += 1
    g.r.shuffle(rows)
    return rows


def main(argv: list[str] | None = None) -> Path:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--n", type=int, default=4000, help="URLs per class (default 4000)")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--out", type=Path, default=ROOT / "data" / "demo_urls.csv")
    args = ap.parse_args(argv)
    rows = build(args.n, args.seed)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with open(args.out, "w", encoding="utf-8", newline="") as fh:
        fh.write("url,label,source\n")
        for url, label in rows:
            fh.write(f"{url},{label},synthetic\n")
    print(f"[data] wrote {len(rows)} SYNTHETIC URLs -> {args.out}")
    return args.out


if __name__ == "__main__":
    sys.exit(0 if main() else 1)
