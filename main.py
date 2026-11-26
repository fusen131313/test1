import os
import sys
import re
import json
import socket
import base64
import hashlib
import asyncio
import datetime
from urllib.parse import urljoin, urlparse
import aiohttp
import aiodns
from bs4 import BeautifulSoup
from cryptography import x509
from cryptography.x509.oid import NameOID
from pydantic import BaseModel
from google import genai
from google.genai import types

GAS_WEBAPP_URL = os.environ["GAS_WEBAPP_URL"]
GEMINI_API_KEY = os.environ["GEMINI_API_KEY"]
TARGET_OPERATOR = sys.argv[1] if len(sys.argv) > 1 else "google"

client = genai.Client(api_key=GEMINI_API_KEY)

class SiteAnalysisResult(BaseModel):
    id: int
    is_japan_business: bool
    is_newly_launched: bool
    company_name: str
    prefecture: str
    address: str
    phone: str

MAX_TOTAL_ENTRIES_PER_JOB = 200000
MIN_ENTRIES_PER_LOG = 25000
INITIAL_LOOKBACK_ENTRIES = 60000
DNS_CONCURRENCY = 50
MAX_UNMATCHED_JP_SAMPLE_PER_JOB = 100

OPERATOR_START_OFFSET = {
    "google": 0,
    "cloudflare": 3,
    "sectigo": 6,
    "letsencrypt": 9
}

VALID_JP_PREFECTURES = {
    "北海道", "青森県", "岩手県", "宮城県", "秋田県", "山形県", "福島県",
    "茨城県", "栃木県", "群馬県", "埼玉県", "千葉県", "東京都", "神奈川県",
    "新潟県", "富山県", "石川県", "福井県", "山梨県", "長野県", "岐阜県",
    "静岡県", "愛知県", "三重県", "滋賀県", "京都府", "大阪府", "兵庫県",
    "奈良県", "和歌山県", "鳥取県", "島根県", "岡山県", "広島県", "山口県",
    "徳島県", "香川県", "愛媛県", "高知県", "福岡県", "佐賀県", "長崎県",
    "熊本県", "大分県", "宮崎県", "鹿児島県", "沖縄県"
}

EXCLUDED_TLDS = {
    "cn", "ru", "br", "de", "uk", "fr", "it", "es", "nl", "pl", "in", "kr", "tw", "vn",
    "id", "th", "au", "ca", "se", "ch", "tr", "ir", "ua", "za", "mx", "ar", "cl", "pe",
    "co.uk", "com.au", "com.br", "com.cn", "com.tw", "co.kr", "co.in", "co.id", "co.za",
    "cz", "hu", "ro", "bg", "gr", "pt", "be", "at", "dk", "fi", "no", "ie", "il", "sa",
    "ae", "eg", "ng", "ke", "pk", "bd", "ph", "my", "sg", "hk", "nz", "kz", "by", "uz",
    "tk", "ml", "ga", "cf", "gq", "top", "loan", "win", "bid", "stream", "download",
    "gdn", "racing", "review", "party", "date", "faith", "accountant", "science",
    "cricket", "webcam", "trade", "men", "kim", "icu", "buzz", "cyou", "cfd", "sbs",
    "rest", "monster", "xyz", "club"
}

EXCLUDED_PLATFORM_PATTERN = re.compile(
    r"(^|\.)("
    r"blog|diary|note|ameblo|amebaownd|hatenablog|hatenadiary|livedoor|fc2|seesaa|jugem|"
    r"cocolog-nifty|goo\.ne\.jp|exblog|wordpress\.com|blogspot\.com|tumblr\.com|"
    r"wixsite\.com|peraichi\.com|jimdofree\.com|jimdosite\.com|weebly\.com|strikingly\.com|"
    r"canva\.site|studio\.site|myportfolio\.com|webnode\.jp|crayonsite\.net|"
    r"rakuten\.co\.jp|stores\.jp|thebase\.in|base\.shop|myshopify\.com|makeshop\.jp|shop-pro\.jp|"
    r"xsrv\.jp|sakura\.ne\.jp|lolipop\.jp|heteml\.net|coreserver\.jp|starfree\.jp|wp\.xdomain\.jp"
    r")$",
    re.IGNORECASE
)

JP_NS_PATTERN = re.compile(
    r"(xserver|sakura\.ne\.jp|onamae\.com|muumuu-domain|value-domain|lolipop|heteml|"
    r"cpi\.ad\.jp|wadax|firstserver|star-domain|etius\.jp|alpha-prm\.jp|kagoya|conoha)",
    re.IGNORECASE
)

FALLBACK_LOGS = {
    "google": [
        ("google_argon2026h2", "https://ct.googleapis.com/logs/us1/argon2026h2/ct/v1/"),
        ("google_xenon2026h2", "https://ct.googleapis.com/logs/eu1/xenon2026h2/ct/v1/")
    ],
    "cloudflare": [
        ("cloudflare_nimbus2026", "https://ct.cloudflare.com/logs/nimbus2026/ct/v1/")
    ],
    "sectigo": [
        ("sectigo_sabre2026h2", "https://sabre2026h2.ct.sectigo.com/ct/v1/")
    ],
    "letsencrypt": [
        ("letsencrypt_oak2026h2", "https://oak.ct.letsencrypt.org/2026h2/ct/v1/")
    ]
}

HIGH_PRIORITY_LINK = re.compile(r"(company|about|overview|profile|law|tokushoho|contact|inquiry|corporate|gaiyou|会社概要|企業情報|法人概要|特定商取引|お問い合わせ)", re.IGNORECASE)
MID_PRIORITY_LINK = re.compile(r"(shop|store|salon|clinic|access|office|店舗|医院|サロン|アクセス|事務所)", re.IGNORECASE)
JP_PHONE_REGEX = re.compile(r"(?:0\d{1,4}[\-\s]?\d{1,4}[\-\s]?\d{3,4}|0120[\-\s]?\d{3}[\-\s]?\d{3}|0800[\-\s]?\d{3}[\-\s]?\d{4})")

def resolve_available_gemini_models() -> list[str]:
    preferred_order = [
        "gemini-3.1-flash-lite",
        "gemini-3.1-flash",
        "gemini-3.0-flash",
        "gemini-3-flash-preview",
        "gemini-flash-latest"
    ]
    available = []
    try:
        for m in client.models.list():
            name = (getattr(m, "name", "") or "").replace("models/", "")
            methods = getattr(m, "supported_actions", None) or getattr(m, "supported_generation_methods", None) or []
            if "flash" in name.lower() and (not methods or "generateContent" in methods):
                if "embedding" not in name.lower() and "image" not in name.lower() and "audio" not in name.lower():
                    available.append(name)
    except Exception as e:
        print(f"[{TARGET_OPERATOR}] モデル一覧取得スキップ: {e}")

    ordered = [p for p in preferred_order if p in available]
    for a in available:
        if a not in ordered and not a.startswith("gemini-2."):
            ordered.append(a)
    return ordered if ordered else ["gemini-3.1-flash-lite"]

def normalize_domain(domain: str) -> str:
    d = domain.strip().lower()
    d = re.sub(r"^https?://", "", d).split("/")[0].split(":")[0]
    d = re.sub(r"^(\*\.)+", "", d)
    d = re.sub(r"^www\.", "", d)
    return d

def is_valid_business_domain(domain: str) -> bool:
    if EXCLUDED_PLATFORM_PATTERN.search(domain):
        return False

    parts = domain.split(".")
    if len(parts) < 2:
        return False

    second_level_jp = {"co", "or", "ne", "ac", "go", "gr", "ed", "lg"}
    if parts[-1] == "jp" and len(parts) >= 3 and parts[-2] in second_level_jp:
        if len(parts) > 3:
            return False
    elif len(parts) > 2:
        return False

    tld = parts[-1]
    two_part_tld = f"{parts[-2]}.{parts[-1]}"
    if tld in EXCLUDED_TLDS or two_part_tld in EXCLUDED_TLDS:
        return False

    return True

def get_ip_prefix(ip: str) -> str:
    parts = ip.strip().split(".")
    return f"{parts[0]}.{parts[1]}.{parts[2]}" if len(parts) == 4 else ""

def is_valid_jp_phone(phone_str: str) -> bool:
    if not phone_str:
        return False
    cleaned = re.sub(r"[^0-9]", "", phone_str)
    if cleaned.startswith("81") and len(cleaned) >= 11:
        cleaned = "0" + cleaned[2:]
    return cleaned.startswith("0") and len(cleaned) in (10, 11)

async def resolve_all_active_ct_logs(session: aiohttp.ClientSession, operator_key: str) -> list[tuple[str, str]]:
    found_logs = []
    match_name = "let's encrypt" if operator_key == "letsencrypt" else operator_key
    try:
        async with session.get("https://www.gstatic.com/ct/log_list/v3/log_list.json", timeout=10) as resp:
            if resp.status == 200:
                data = await resp.json()
                now = datetime.datetime.now(datetime.timezone.utc)
                for op in data.get("operators", []):
                    op_name = op.get("name", "").lower()
                    if match_name not in op_name:
                        continue
                    for log in op.get("logs", []):
                        if "usable" not in log.get("state", {}):
                            continue
                        ti = log.get("temporal_interval", {})
                        start_s = ti.get("start_inclusive")
                        end_s = ti.get("end_exclusive")
                        if start_s and end_s:
                            s_dt = datetime.datetime.fromisoformat(start_s.replace("Z", "+00:00"))
                            e_dt = datetime.datetime.fromisoformat(end_s.replace("Z", "+00:00"))
                            if s_dt <= now < e_dt:
                                url = log["url"].rstrip("/") + "/"
                                url_hash = hashlib.sha256(url.encode("utf-8")).hexdigest()[:12]
                                found_logs.append((f"{operator_key}_{url_hash}", f"{url}ct/v1/"))
    except Exception:
        pass
    return found_logs if found_logs else FALLBACK_LOGS.get(operator_key, [])

def parse_domains_from_ct_entry(entry: dict, cutoff_dt: datetime.datetime) -> list[str]:
    try:
        leaf_bytes = base64.b64decode(entry["leaf_input"])
        entry_type = int.from_bytes(leaf_bytes[10:12], "big")
        if entry_type == 0:
            cert_len = int.from_bytes(leaf_bytes[12:15], "big")
            cert_der = leaf_bytes[15:15 + cert_len]
        elif entry_type == 1:
            extra_bytes = base64.b64decode(entry["extra_data"])
            cert_len = int.from_bytes(extra_bytes[0:3], "big")
            cert_der = extra_bytes[3:3 + cert_len]
        else:
            return []

        cert = x509.load_der_x509_certificate(cert_der)
        if cert.not_valid_before_utc < cutoff_dt:
            return []

        domains = set()
        try:
            ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            for name in ext.value.get_values_for_type(x509.DNSName):
                domains.add(name)
        except x509.ExtensionNotFound:
            for attr in cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME):
                domains.add(attr.value)

        valid_domains = []
        for raw_d in domains:
            d = normalize_domain(raw_d)
            if d and is_valid_business_domain(d):
                valid_domains.append(d)

        return valid_domains
    except Exception:
        return []

async def fetch_ct_log_dynamic(session: aiohttp.ClientSession, log_key: str, base_url: str, last_idx: int | None, budget: int, cert_cutoff_dt: datetime.datetime, existing_domains: set[str]) -> tuple[int, set[str]]:
    async with session.get(f"{base_url}get-sth", timeout=10) as sth_resp:
        sth = await sth_resp.json()
        tree_size = sth["tree_size"]

    if last_idx is None:
        current_idx = max(0, tree_size - INITIAL_LOOKBACK_ENTRIES)
    else:
        current_idx = int(last_idx)

    if current_idx >= tree_size or budget <= 0:
        return current_idx, set()

    target_end = min(tree_size - 1, current_idx + budget - 1)
    print(f"[{log_key}] 差分取得: {current_idx} -> {target_end} (最新: {tree_size})")

    extracted = set()
    while current_idx <= target_end:
        req_end = min(target_end, current_idx + 255)
        url = f"{base_url}get-entries?start={current_idx}&end={req_end}"
        success = False

        for attempt in range(3):
            try:
                async with session.get(url, timeout=15) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        entries = data.get("entries", [])
                        if not entries:
                            return current_idx, extracted

                        for entry in entries:
                            for d in parse_domains_from_ct_entry(entry, cert_cutoff_dt):
                                if d not in existing_domains:
                                    extracted.add(d)

                        current_idx += len(entries)
                        success = True
                        break
                    elif resp.status == 429:
                        await asyncio.sleep(2 * (attempt + 1))
                    else:
                        await asyncio.sleep(1)
            except Exception:
                await asyncio.sleep(1)

        if not success:
            break

    return current_idx, extracted

async def resolve_domains_with_retry_queue(domains: list[str]) -> tuple[dict[str, str], list[str], set[str]]:
    loop = asyncio.get_running_loop()
    resolver = aiodns.DNSResolver(nameservers=["8.8.8.8", "1.1.1.1"], timeout=2.0, loop=loop)
    dns_fn = getattr(resolver, "query_dns", resolver.query)
    sem = asyncio.Semaphore(DNS_CONCURRENCY)
    ip_map = {}
    unresolved_jp_candidates = []
    jp_ns_domains = set()

    async def lookup(domain: str):
        async with sem:
            resolved = False
            for host in (domain, f"www.{domain}"):
                try:
                    res = await dns_fn(host, "A")
                    if res:
                        first = res[0]
                        ip = getattr(first, "host", None) or getattr(getattr(first, "data", None), "host", None)
                        if ip:
                            ip_map[domain] = ip
                            resolved = True
                            break
                except Exception:
                    pass
                try:
                    infos = await asyncio.wait_for(
                        loop.getaddrinfo(host, None, family=socket.AF_INET), timeout=2.0
                    )
                    if infos:
                        ip_map[domain] = infos[0][4][0]
                        resolved = True
                        break
                except Exception:
                    pass

            if domain.endswith(".jp"):
                jp_ns_domains.add(domain)
                if not resolved:
                    unresolved_jp_candidates.append(domain)
            else:
                try:
                    ns_res = await dns_fn(domain, "NS")
                    ns_hosts = [
                        getattr(n, "host", "") or getattr(getattr(n, "data", None), "host", "")
                        for n in (ns_res or [])
                    ]
                    if any(JP_NS_PATTERN.search(h) for h in ns_hosts if h):
                        jp_ns_domains.add(domain)
                        if not resolved:
                            unresolved_jp_candidates.append(domain)
                except Exception:
                    pass

    await asyncio.gather(*(lookup(d) for d in domains))
    return ip_map, unresolved_jp_candidates, jp_ns_domains

def extract_tel_candidates(soup: BeautifulSoup, plain_text: str) -> set[str]:
    tels = set()
    for a in soup.find_all("a", href=True):
        href = a["href"].strip()
        if href.lower().startswith("tel:"):
            raw_tel = re.sub(r"^\+81\-?", "0", href[4:].strip())
            num = re.sub(r"[^0-9\-]", "", raw_tel)
            if is_valid_jp_phone(num):
                tels.add(num)
    for img in soup.find_all("img", alt=True):
        alt_txt = img["alt"].strip()
        for m in JP_PHONE_REGEX.findall(alt_txt):
            norm = re.sub(r"\s+", "-", m.strip())
            if is_valid_jp_phone(norm):
                tels.add(norm)
    for m in JP_PHONE_REGEX.findall(plain_text):
        norm = re.sub(r"\s+", "-", m.strip())
        if is_valid_jp_phone(norm):
            tels.add(norm)
    return tels

async def fetch_site_full_text(session: aiohttp.ClientSession, domain: str) -> str:
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36",
        "Accept-Language": "ja,en-US;q=0.9,en;q=0.8"
    }
    base_url = f"https://{domain}"
    try:
        async with session.get(base_url, headers=headers, timeout=12, allow_redirects=True, ssl=False) as resp:
            if resp.status < 200 or resp.status >= 300:
                return ""
            final_url = str(resp.url)
            if final_url.startswith("http://"):
                return ""
            raw_bytes = await resp.read()
    except Exception:
        return ""

    if not raw_bytes:
        return ""

    soup = BeautifulSoup(raw_bytes, "html.parser")

    meta_refresh = soup.find("meta", attrs={"http-equiv": re.compile(r"^refresh$", re.I)})
    if meta_refresh and meta_refresh.get("content"):
        m = re.search(r"url\s*=\s*['\"]?([^'\">\s]+)", meta_refresh["content"], re.I)
        if m:
            redirect_target = urljoin(final_url, m.group(1).strip())
            if redirect_target.startswith("https://"):
                try:
                    async with session.get(redirect_target, headers=headers, timeout=10, allow_redirects=True, ssl=False) as r_resp:
                        if 200 <= r_resp.status < 300 and str(r_resp.url).startswith("https://"):
                            final_url = str(r_resp.url)
                            raw_bytes = await r_resp.read()
                            soup = BeautifulSoup(raw_bytes, "html.parser")
                except Exception:
                    pass

    if len(raw_bytes) < 300:
        return ""

    html_tag = soup.find("html")
    if html_tag and html_tag.get("lang"):
        lang_val = html_tag["lang"].strip().lower()
        if lang_val and not lang_val.startswith("ja"):
            return ""

    final_netloc = urlparse(final_url).netloc
    high_links = []
    mid_links = []
    seen_urls = {final_url, final_url.rstrip("/")}

    for a in soup.find_all("a", href=True):
        href = a["href"].strip()
        if not href or href.startswith(("#", "javascript:", "mailto:", "tel:")):
            continue
        text = a.get_text(strip=True)
        full_sub = urljoin(final_url, href).split("#")[0]
        if full_sub in seen_urls or full_sub.rstrip("/") in seen_urls:
            continue
        if urlparse(full_sub).netloc != final_netloc:
            continue

        if HIGH_PRIORITY_LINK.search(href) or HIGH_PRIORITY_LINK.search(text):
            seen_urls.add(full_sub)
            high_links.append(full_sub)
        elif MID_PRIORITY_LINK.search(href) or MID_PRIORITY_LINK.search(text):
            seen_urls.add(full_sub)
            mid_links.append(full_sub)

    prioritized_sub_urls = (high_links + mid_links)[:3]

    def extract_head_and_footer(s_obj: BeautifulSoup) -> str:
        for tag in s_obj(["script", "style", "noscript", "svg"]):
            tag.decompose()
        full_str = re.sub(r"\s+", " ", s_obj.get_text(separator=" ", strip=True))
        if len(full_str) <= 3200:
            return full_str
        return f"{full_str[:2000]} ... {full_str[-1200:]}"

    tel_numbers = extract_tel_candidates(soup, soup.get_text(" ", strip=True))
    top_text = extract_head_and_footer(soup)
    kana_count = len(re.findall(r"[\u3040-\u309F\u30A0-\u30FF]", top_text))
    if kana_count < 60:
        return ""

    combined_text = f"【トップページ】\n{top_text}"

    for sub_url in prioritized_sub_urls:
        try:
            async with session.get(sub_url, headers=headers, timeout=8, ssl=False) as sub_resp:
                if sub_resp.status == 200:
                    sub_bytes = await sub_resp.read()
                    sub_soup = BeautifulSoup(sub_bytes, "html.parser")
                    tel_numbers.update(extract_tel_candidates(sub_soup, sub_soup.get_text(" ", strip=True)))
                    combined_text += f"\n【下層】\n{extract_head_and_footer(sub_soup)[:1800]}"
        except Exception:
            pass

    if not tel_numbers:
        base_root = f"{urlparse(final_url).scheme}://{final_netloc}"
        for fallback_path in ("/company", "/about", "/contact", "/law", "/corporate", "/company/", "/contact/"):
            cand_url = f"{base_root}{fallback_path}"
            if cand_url in seen_urls:
                continue
            seen_urls.add(cand_url)
            try:
                async with session.get(cand_url, headers=headers, timeout=6, ssl=False) as fb_resp:
                    if fb_resp.status == 200:
                        fb_bytes = await fb_resp.read()
                        fb_soup = BeautifulSoup(fb_bytes, "html.parser")
                        found = extract_tel_candidates(fb_soup, fb_soup.get_text(" ", strip=True))
                        if found:
                            tel_numbers.update(found)
                            combined_text += f"\n【追加探索】\n{extract_head_and_footer(fb_soup)[:1200]}"
                            break
            except Exception:
                pass

    if tel_numbers:
        combined_text += f"\n【検出電話番号候補】: {', '.join(sorted(tel_numbers))}"
    return combined_text[:5600]

async def analyze_batch_with_gemini(site_items: list[dict], today_str: str, candidate_models: list[str]) -> list[dict]:
    sites_block = ""
    for idx, item in enumerate(site_items):
        sites_block += f"\n--- サイトID: {idx} | ドメイン: {item['domain']} ---\n{item['text']}\n"

    prompt = f"""
あなたは日本のWebサイト調査アナリストです。本日は {today_str} です。
以下の複数サイト（サイトID: 0〜{len(site_items)-1}）をそれぞれ分析し、指定のJSON配列スキーマで回答してください。

【重要方針：取りこぼし防止・目視確認優先】
- 抽出漏れを防ぐため、「迷うサイト」「判断材料が少ないサイト」は落とさず `true` にして通過させてください。
- 明確な除外対象（海外サイト・個人ブログ・ポータル・大企業・官公庁・数年前の古い記事が大量にある既存サイト）だけを `false` にしてください。

【各フィールドの判定・抽出基準】
- id: 入力のサイトID
- is_japan_business: 日本国内に拠点がある事業用公式Webサイト（中小企業・店舗・クリニック・士業・個人事業主など）なら true。日本国外の海外企業・個人ブログ・アフィリエイト・ポータル・上場大企業・官公庁・ECモール内ページは false。
- is_newly_launched: 「明らかな既存サイト」でなければ **原則 true** にすること。ブログやお知らせ機能がない新規サイト、年号記載がないサイト、判断に迷うサイトはすべて true にする。**2024年以前の過去のブログ記事・ニュース・施工実績の日付が明確に掲載されている場合のみ false** とする。
- company_name: 日本の会社名・屋号・店舗名・医院名（不明なら ""）
- prefecture: 日本の47都道府県名のいずれか（例: "東京都", "福岡県"。住所や市外局番から補完可。日本国外や不明なら ""）
- address: 都道府県以降の日本の住所（不明なら ""）
- phone: 日本の代表・問い合わせ電話番号（0から始まるハイフンあり形式、FAX除外。画像バナー等で本文から読み取れない場合は無理に推測せず "" にする）

【分析対象サイト一覧】
{sites_block}
"""
    model_idx = 0
    for attempt in range(5):
        model_name = candidate_models[min(model_idx, len(candidate_models) - 1)]
        try:
            response = await asyncio.to_thread(
                client.models.generate_content,
                model=model_name,
                contents=prompt,
                config=types.GenerateContentConfig(
                    response_mime_type="application/json",
                    response_schema=list[SiteAnalysisResult]
                )
            )
            res_json = json.loads(response.text)
            return res_json if isinstance(res_json, list) else []
        except Exception as e:
            err_str = str(e)
            if "404" in err_str:
                model_idx += 1
                wait_sec = 2
            else:
                wait_sec = 15 * (attempt + 1)
            print(f"[{TARGET_OPERATOR}] Gemini APIリトライ ({attempt + 1}/5, model={model_name}, {wait_sec}s): {e}")
            await asyncio.sleep(wait_sec)
    return []

async def main():
    offset = OPERATOR_START_OFFSET.get(TARGET_OPERATOR, 0)
    if offset > 0:
        await asyncio.sleep(offset)

    candidate_models = resolve_available_gemini_models()
    print(f"[{TARGET_OPERATOR}] 利用可能Geminiモデル候補: {candidate_models[:3]}")

    now_utc = datetime.datetime.now(datetime.timezone.utc)
    cert_cutoff_dt = now_utc - datetime.timedelta(days=90)
    today_jst = (now_utc + datetime.timedelta(hours=9)).strftime("%Y-%m-%d")

    async with aiohttp.ClientSession() as session:
        config = None
        for attempt in range(3):
            try:
                async with session.get(f"{GAS_WEBAPP_URL}?action=get_config", timeout=30) as resp:
                    if resp.status == 200:
                        config = await resp.json()
                        break
            except Exception:
                await asyncio.sleep(3 * (attempt + 1))

        if not config or config.get("status") != "ok":
            print("GASからの設定取得に失敗しました。")
            return

        ip_list = config.get("ips", [])
        existing_domains = set(config.get("existing_domains", []))
        ct_state = config.get("ct_state", {})
        pending_domains = set(config.get("pending_domains", []))

        target_prefix_map = {}
        for item in ip_list:
            prefix = get_ip_prefix(item["ip"])
            if prefix and prefix not in target_prefix_map:
                target_prefix_map[prefix] = item["name"]

        if not target_prefix_map:
            print("対象IPリストが空です。")
            return

        active_logs = await resolve_all_active_ct_logs(session, TARGET_OPERATOR)
        per_log_budget = max(MIN_ENTRIES_PER_LOG, MAX_TOTAL_ENTRIES_PER_JOB // max(1, len(active_logs)))

        candidate_domains = set()
        if TARGET_OPERATOR == "google":
            for pd in pending_domains:
                if pd not in existing_domains:
                    candidate_domains.add(pd)

        log_updates = {}
        for log_key, base_url in active_logs:
            try:
                next_idx, domains = await fetch_ct_log_dynamic(
                    session, log_key, base_url, ct_state.get(log_key), per_log_budget, cert_cutoff_dt, existing_domains
                )
                log_updates[log_key] = next_idx
                candidate_domains.update(domains)
            except Exception as e:
                print(f"[{log_key}] ログ取得スキップ: {e}")

        print(f"[{TARGET_OPERATOR}] フィルタ通過・DNS照会対象ドメイン数: {len(candidate_domains)}")

        matched_targets = []
        unmatched_jp_targets = []
        new_pending = []
        resolved_pending = []

        if candidate_domains:
            ip_map, unresolved_jp, jp_ns_domains = await resolve_domains_with_retry_queue(list(candidate_domains))
            new_pending = [d for d in unresolved_jp if d not in pending_domains]
            resolved_pending = [d for d in ip_map.keys() if d in pending_domains]

            for domain, resolved_ip in ip_map.items():
                prefix = get_ip_prefix(resolved_ip)
                if prefix in target_prefix_map:
                    matched_targets.append({
                        "domain": domain,
                        "ip": resolved_ip,
                        "label": target_prefix_map[prefix],
                        "is_matched_ip": True
                    })
                elif domain in jp_ns_domains and len(unmatched_jp_targets) < MAX_UNMATCHED_JP_SAMPLE_PER_JOB:
                    unmatched_jp_targets.append({
                        "domain": domain,
                        "ip": resolved_ip,
                        "label": "指定外",
                        "is_matched_ip": False
                    })

        print(f"[{TARGET_OPERATOR}] 実績IP一致: {len(matched_targets)} 件 / 指定外JP調査対象: {len(unmatched_jp_targets)} 件 / 新規保留: {len(new_pending)} 件")

        all_targets = matched_targets + unmatched_jp_targets
        html_sem = asyncio.Semaphore(20)
        valid_sites = []

        async def gather_site(target: dict):
            async with html_sem:
                text = await fetch_site_full_text(session, target["domain"])
                if text:
                    valid_sites.append({**target, "text": text})

        await asyncio.gather(*(gather_site(t) for t in all_targets))
        print(f"[{TARGET_OPERATOR}] 日本語HTML有効サイト数: {len(valid_sites)}")

        new_rows = []
        unmatched_rows = []

        for i in range(0, len(valid_sites), 5):
            batch = valid_sites[i:i + 5]
            ai_results = await analyze_batch_with_gemini(batch, today_jst, candidate_models)
            res_map = {r.get("id"): r for r in ai_results if isinstance(r, dict)}

            for idx, item in enumerate(batch):
                ai_res = res_map.get(idx)
                if not ai_res:
                    continue
                if ai_res.get("is_japan_business") is not True or ai_res.get("is_newly_launched") is not True:
                    continue

                pref = str(ai_res.get("prefecture", "")).strip()
                phone = str(ai_res.get("phone", "")).strip()

                # 海外データのみ強制除外（電話番号空欄は目視確認用にそのまま出力）
                if pref and pref not in VALID_JP_PREFECTURES:
                    continue
                if phone and not is_valid_jp_phone(phone):
                    phone = ""

                row_data = [
                    item["domain"],
                    f"{item['ip']} ({item['label']})",
                    today_jst,
                    ai_res.get("company_name", ""),
                    pref,
                    ai_res.get("address", ""),
                    phone,
                    False,
                    False
                ]

                if item["is_matched_ip"]:
                    new_rows.append(row_data)
                else:
                    unmatched_rows.append(row_data)

            if i + 5 < len(valid_sites):
                await asyncio.sleep(2.5)

        payload = {
            "log_updates": log_updates,
            "add_pending": new_pending[:500],
            "remove_pending": resolved_pending,
            "rows": new_rows,
            "unmatched_rows": unmatched_rows
        }

        for attempt in range(5):
            try:
                async with session.post(GAS_WEBAPP_URL, json=payload, timeout=30) as post_resp:
                    res_data = await post_resp.json()
                    if res_data.get("status") == "ok":
                        print(f"[{TARGET_OPERATOR}] GAS送信完了（新着: {res_data.get('added', 0)} 件 / 指定外: {res_data.get('added_unmatched', 0)} 件）")
                        break
                    print(f"[{TARGET_OPERATOR}] GASロック待機リトライ ({attempt + 1}/5): {res_data}")
            except Exception as e:
                print(f"[{TARGET_OPERATOR}] GAS送信リトライ ({attempt + 1}/5): {e}")
            await asyncio.sleep(5 * (attempt + 1))

if __name__ == "__main__":
    asyncio.run(main())
