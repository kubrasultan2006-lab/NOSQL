"""CTI Digest: a working web app for Chapter 7 (MongoDB architecture).

It sits on top of the chapter-07 database (articles, sources, threat_actors,
vulnerabilities) and shows the Chapter 7 ideas working in a real application:

  Search / Latest threats / Top threats / Threat and CVE pages
      -> an application built on a model that EMBEDS article content and REFERENCES
         sources, threat actors and CVEs (every page shows the lookups it needed)
  Data model
      -> embedding vs referencing with measured sizes ($bsonSize), plus a live
         experiment: build an embedded copy of the articles and time both designs (Lab 7.1)
  Database metrics
      -> the WiredTiger cache hit ratio read from serverStatus every 10 seconds,
         cache fill, working-set estimate, and a random-read workload (Lab 7.2)

Run (from the project root, MongoDB must be running):

    python chapter-07\\cti_digest_app.py

then open http://127.0.0.1:8000. If the database is empty, use "Seed demo data" on the
Database metrics page (it uses 7_1_Seed_ctidigest.py from the same folder).

Needs only pymongo. Set MONGO_URI to use a non-default server, for example Atlas.
Note: the Database metrics page needs the WiredTiger section of serverStatus, which a
self-managed mongod or Docker container provides (some shared Atlas tiers do not).
"""

import argparse
import importlib.util
import json
import os
import random
import re
import statistics
import threading
import time
import webbrowser
from collections import deque
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import bson
from bson import ObjectId
from pymongo import MongoClient
from pymongo.errors import OperationFailure, PyMongoError

MONGO_URI = os.environ.get("MONGO_URI", "mongodb://localhost:27017")
DB_NAME = "chapter-07"
HERE = Path(__file__).resolve().parent
SAMPLE_SECONDS = 10               # how often the cache hit ratio is read
RECENT_DAYS = 90                  # window used to rate a threat actor
LIMIT_BYTES = 16 * 1024 * 1024    # MongoDB's 16 MB document limit
MB = 1024 * 1024
LEVEL_RANK = {"high": 3, "medium": 2, "low": 1}


# ----------------------------------------------------------------------- basics
class ApiError(Exception):
    def __init__(self, status, message):
        super().__init__(message)
        self.status, self.message = status, message


_client = None
_client_lock = threading.Lock()


def client():
    global _client
    with _client_lock:
        if _client is None:
            _client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=3000)
        return _client


def db():
    return client()[DB_NAME]


def utcnow():
    """Naive UTC datetime: pymongo returns naive UTC datetimes by default."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def encode(obj):
    if isinstance(obj, ObjectId):
        return str(obj)
    if isinstance(obj, datetime):
        return obj.replace(tzinfo=None).isoformat() + "Z"
    raise TypeError(f"cannot encode {type(obj)}")


def oid(text):
    try:
        return ObjectId(text)
    except Exception:
        raise ApiError(400, "invalid id")


def rx(text):
    """Case-insensitive, escaped $regex condition (safe for user input)."""
    return {"$regex": re.escape(text), "$options": "i"}


def iparam(q, name, default, lo, hi):
    try:
        value = int(q.get(name, default))
    except (TypeError, ValueError):
        value = default
    return max(lo, min(hi, value))


_cache = {}
_cache_lock = threading.Lock()


def cached(key, ttl, fn):
    now = time.time()
    with _cache_lock:
        hit = _cache.get(key)
        if hit and now - hit[0] < ttl:
            return hit[1]
    value = fn()
    with _cache_lock:
        _cache[key] = (now, value)
    return value


def clear_caches():
    with _cache_lock:
        _cache.clear()


# ------------------------------------------------------------- threat actor rating
def actor_levels():
    """Rate every actor: score = articles in the last 90 days + 3 x articles that also name
    a CVE exploited in the wild. Top quarter = high, upper half = medium, the rest = low."""
    def compute():
        d = db()
        exploited = [v["cve_id"] for v in
                     d.vulnerabilities.find({"exploited_in_wild": True}, {"cve_id": 1})]
        cutoff = utcnow() - timedelta(days=RECENT_DAYS)
        rows = d.articles.aggregate([
            {"$unwind": "$actor_ids"},
            {"$group": {
                "_id": "$actor_ids",
                "articles": {"$sum": 1},
                "recent": {"$sum": {"$cond": [{"$gte": ["$published", cutoff]}, 1, 0]}},
                "linked": {"$sum": {"$cond": [
                    {"$gt": [{"$size": {"$setIntersection": ["$cve_ids", exploited]}}, 0]}, 1, 0]}},
                "last_seen": {"$max": "$published"},
                "sources": {"$addToSet": "$source_id"},
            }},
        ])
        stats = {r["_id"]: r for r in rows}
        actors = list(d.threat_actors.find())
        scores = {}
        for a in actors:
            r = stats.get(a["_id"], {})
            scores[a["_id"]] = r.get("recent", 0) + 3 * r.get("linked", 0)
        ordered = sorted(scores.values())
        if not ordered:
            return {}
        median = ordered[len(ordered) // 2]
        p75 = ordered[(len(ordered) * 3) // 4]
        out = {}
        for a in actors:
            r = stats.get(a["_id"], {})
            score = scores[a["_id"]]
            level = "high" if score >= p75 else "medium" if score >= median else "low"
            out[a["_id"]] = {
                "id": a["_id"], "name": a["name"], "aliases": a.get("aliases", []),
                "country": a.get("country", ""), "motivation": a.get("motivation", ""),
                "ttps": a.get("ttps", []), "level": level, "score": score,
                "articles": r.get("articles", 0), "recent": r.get("recent", 0),
                "linked": r.get("linked", 0), "last_seen": r.get("last_seen"),
                "source_count": len(r.get("sources", [])),
            }
        return out
    return cached("levels", 30, compute)


def actor_brief(actor_id):
    a = actor_levels().get(actor_id)
    if not a:
        return {"id": actor_id, "name": "unknown", "level": "low"}
    return {"id": a["id"], "name": a["name"], "level": a["level"]}


# ----------------------------------------------------------------------- articles
def article_list(match, skip, limit):
    """Articles (newest first) with their source and actor names joined in."""
    rows = db().articles.aggregate([
        {"$match": match},
        {"$sort": {"published": -1, "_id": -1}},
        {"$skip": skip},
        {"$limit": limit},
        {"$lookup": {"from": "sources", "localField": "source_id",
                     "foreignField": "_id", "as": "src"}},
        {"$project": {"title": 1, "published": 1, "tags": 1, "sectors": 1, "actor_ids": 1,
                      "cve_ids": 1, "source_id": 1, "src": 1,
                      "blocks": {"$size": "$content_blocks"}}},
    ])
    levels = actor_levels()
    items = []
    for r in rows:
        src = (r.get("src") or [{}])[0]
        actors = [actor_brief(i) for i in r.get("actor_ids", [])]
        top = max((a["level"] for a in actors), key=lambda x: LEVEL_RANK[x], default=None)
        items.append({
            "id": r["_id"], "title": r["title"], "published": r["published"],
            "tags": r.get("tags", []), "sectors": r.get("sectors", []),
            "cve_count": len(r.get("cve_ids", [])), "blocks": r.get("blocks", 0),
            "source": {"id": r.get("source_id"), "name": src.get("name", "unknown"),
                       "type": src.get("type", "")},
            "actors": actors, "top_level": top,
        })
    del levels
    return items


def build_match(q):
    match = {}
    text = (q.get("q") or "").strip()
    if text:
        match["$or"] = [{"title": rx(text)}, {"tags": rx(text)}]
    if q.get("tag"):
        match["tags"] = q["tag"]
    if q.get("sector"):
        match["sectors"] = q["sector"]
    if q.get("source"):
        match["source_id"] = oid(q["source"])
    if q.get("actor"):
        match["actor_ids"] = oid(q["actor"])
    if q.get("cve"):
        match["cve_ids"] = q["cve"]
    days = iparam(q, "days", 0, 0, 3650)
    if days:
        match["published"] = {"$gte": utcnow() - timedelta(days=days)}
    return match


def api_overview(q):
    d = db()
    counts = {n: d[n].estimated_document_count()
              for n in ("articles", "sources", "threat_actors", "vulnerabilities")}
    newest = d.articles.find_one({}, {"published": 1}, sort=[("published", -1)])
    return {"db": DB_NAME, "counts": counts, "empty": counts["articles"] == 0,
            "newest": newest["published"] if newest else None}


def api_articles(q):
    per = iparam(q, "per", 15, 5, 50)
    page = iparam(q, "page", 1, 1, 100000)
    match = build_match(q)
    total = db().articles.count_documents(match)
    items = article_list(match, (page - 1) * per, per)
    return {"items": items, "total": total, "page": page, "per": per,
            "pages": max(1, -(-total // per))}


def api_facets(q):
    def compute():
        d = db()
        tags = [{"name": r["_id"], "n": r["n"]} for r in d.articles.aggregate([
            {"$unwind": "$tags"}, {"$group": {"_id": "$tags", "n": {"$sum": 1}}},
            {"$sort": {"n": -1}}])]
        sectors = [{"name": r["_id"], "n": r["n"]} for r in d.articles.aggregate([
            {"$unwind": "$sectors"}, {"$group": {"_id": "$sectors", "n": {"$sum": 1}}},
            {"$sort": {"n": -1}}])]
        sources = [{"id": r["_id"], "name": (r.get("s") or [{}])[0].get("name", "unknown"),
                    "type": (r.get("s") or [{}])[0].get("type", ""), "n": r["n"]}
                   for r in d.articles.aggregate([
                       {"$group": {"_id": "$source_id", "n": {"$sum": 1}}},
                       {"$sort": {"n": -1}},
                       {"$lookup": {"from": "sources", "localField": "_id",
                                    "foreignField": "_id", "as": "s"}}])]
        return {"tags": tags, "sectors": sectors, "sources": sources}
    return cached("facets", 30, compute)


def api_search(q):
    text = (q.get("q") or "").strip()
    if not text:
        return {"q": "", "actors": [], "vulns": [], "articles": [], "article_total": 0}
    d = db()
    r = rx(text)
    levels = actor_levels()
    actors = [levels[a["_id"]] for a in
              d.threat_actors.find({"$or": [{"name": r}, {"aliases": r}]}).limit(8)
              if a["_id"] in levels]
    vulns = list(d.vulnerabilities.find(
        {"$or": [{"cve_id": r}, {"product": r}]}).sort("cvss", -1).limit(8))
    match = {"$or": [{"title": r}, {"tags": r}]}
    return {"q": text, "actors": actors, "vulns": vulns,
            "articles": article_list(match, 0, 10),
            "article_total": d.articles.count_documents(match)}


def api_article(q, aid):
    d = db()
    t0 = time.perf_counter()
    a = d.articles.find_one({"_id": oid(aid)})
    if not a:
        raise ApiError(404, "Article not found")
    src = d.sources.find_one({"_id": a["source_id"]}) or {}
    actors = list(d.threat_actors.find({"_id": {"$in": a.get("actor_ids", [])}}))
    vulns = list(d.vulnerabilities.find({"cve_id": {"$in": a.get("cve_ids", [])}}))
    ms = (time.perf_counter() - t0) * 1000
    levels = actor_levels()
    return {
        "id": a["_id"], "title": a["title"], "published": a["published"],
        "tags": a.get("tags", []), "sectors": a.get("sectors", []),
        "blocks": a.get("content_blocks", []), "source": src,
        "actors": [levels.get(x["_id"], {"id": x["_id"], "name": x["name"], "level": "low"})
                   for x in actors],
        "vulns": vulns,
        "reads": {"queries": 4, "ms": round(ms, 2), "bytes": len(bson.encode(a)),
                  "block_count": len(a.get("content_blocks", []))},
    }


def weekly_counts(match_extra, weeks=12):
    start = utcnow() - timedelta(days=7 * weeks)
    counts = [0] * weeks
    match = dict(match_extra)
    match["published"] = {"$gte": start}
    for row in db().articles.find(match, {"published": 1}):
        idx = int((row["published"] - start).days // 7)
        counts[max(0, min(weeks - 1, idx))] += 1
    return counts


def api_actor(q, aid):
    d = db()
    actor_id = oid(aid)
    card = actor_levels().get(actor_id)
    if not card:
        raise ApiError(404, "Threat actor not found")
    match = {"actor_ids": actor_id}
    related = []
    for r in d.articles.aggregate([
        {"$match": match}, {"$unwind": "$actor_ids"},
        {"$match": {"actor_ids": {"$ne": actor_id}}},
        {"$group": {"_id": "$actor_ids", "n": {"$sum": 1}}},
        {"$sort": {"n": -1}}, {"$limit": 6},
    ]):
        other = actor_levels().get(r["_id"])
        if other:
            related.append({**other, "shared": r["n"]})
    cves = []
    for r in d.articles.aggregate([
        {"$match": match}, {"$unwind": "$cve_ids"},
        {"$group": {"_id": "$cve_ids", "n": {"$sum": 1}}},
        {"$sort": {"n": -1}}, {"$limit": 8},
        {"$lookup": {"from": "vulnerabilities", "localField": "_id",
                     "foreignField": "cve_id", "as": "v"}},
    ]):
        v = (r.get("v") or [{}])[0]
        cves.append({"cve_id": r["_id"], "n": r["n"], "cvss": v.get("cvss"),
                     "product": v.get("product", ""),
                     "exploited_in_wild": v.get("exploited_in_wild", False)})
    sources = [{"id": r["_id"], "name": (r.get("s") or [{}])[0].get("name", "unknown"), "n": r["n"]}
               for r in d.articles.aggregate([
                   {"$match": match}, {"$group": {"_id": "$source_id", "n": {"$sum": 1}}},
                   {"$sort": {"n": -1}},
                   {"$lookup": {"from": "sources", "localField": "_id",
                                "foreignField": "_id", "as": "s"}}])]
    return {
        "actor": card, "weekly": weekly_counts(match),
        "articles": article_list(match, 0, 10), "article_total": d.articles.count_documents(match),
        "related": related, "cves": cves, "sources": sources,
    }


def api_vuln(q, cve):
    d = db()
    v = d.vulnerabilities.find_one({"cve_id": cve})
    if not v:
        raise ApiError(404, "CVE not found")
    match = {"cve_ids": cve}
    actors = []
    for r in d.articles.aggregate([
        {"$match": match}, {"$unwind": "$actor_ids"},
        {"$group": {"_id": "$actor_ids", "n": {"$sum": 1}}},
        {"$sort": {"n": -1}}, {"$limit": 6},
    ]):
        a = actor_levels().get(r["_id"])
        if a:
            actors.append({**a, "shared": r["n"]})
    return {"vuln": v, "articles": article_list(match, 0, 10),
            "article_total": d.articles.count_documents(match), "actors": actors}


def api_top(q):
    days = iparam(q, "days", 30, 1, 3650)
    d = db()
    cutoff = utcnow() - timedelta(days=days)
    window = {"published": {"$gte": cutoff}}
    levels = actor_levels()
    actors = []
    for r in d.articles.aggregate([
        {"$match": window}, {"$unwind": "$actor_ids"},
        {"$group": {"_id": "$actor_ids", "n": {"$sum": 1}}},
        {"$sort": {"n": -1}}, {"$limit": 12},
    ]):
        a = levels.get(r["_id"])
        if a:
            actors.append({**a, "window_articles": r["n"]})
    vulns = []
    for r in d.articles.aggregate([
        {"$match": window}, {"$unwind": "$cve_ids"},
        {"$group": {"_id": "$cve_ids", "n": {"$sum": 1}}},
        {"$sort": {"n": -1}}, {"$limit": 10},
        {"$lookup": {"from": "vulnerabilities", "localField": "_id",
                     "foreignField": "cve_id", "as": "v"}},
    ]):
        v = (r.get("v") or [{}])[0]
        vulns.append({"cve_id": r["_id"], "n": r["n"], "cvss": v.get("cvss"),
                      "product": v.get("product", ""),
                      "exploited_in_wild": v.get("exploited_in_wild", False)})

    def top_of(field):
        return [{"name": r["_id"], "n": r["n"]} for r in d.articles.aggregate([
            {"$match": window}, {"$unwind": "$" + field},
            {"$group": {"_id": "$" + field, "n": {"$sum": 1}}},
            {"$sort": {"n": -1}}, {"$limit": 8}])]

    return {"days": days, "articles": d.articles.count_documents(window),
            "actors": actors, "vulns": vulns, "tags": top_of("tags"), "sectors": top_of("sectors")}


# --------------------------------------------------------- data model (Lab 7.1)
def collection_sizes(name):
    try:
        rows = list(db()[name].aggregate([
            {"$project": {"size": {"$bsonSize": "$$ROOT"}}},
            {"$group": {"_id": None, "count": {"$sum": 1}, "avg": {"$avg": "$size"},
                        "min": {"$min": "$size"}, "max": {"$max": "$size"},
                        "total": {"$sum": "$size"}}},
        ]))
    except OperationFailure:
        return None
    if not rows:
        return {"count": 0, "avg": 0, "min": 0, "max": 0, "total": 0, "limit_pct": 0}
    r = rows[0]
    return {"count": r["count"], "avg": r["avg"], "min": r["min"], "max": r["max"],
            "total": r["total"], "limit_pct": r["max"] / LIMIT_BYTES * 100}


def api_model(q):
    d = db()
    n_articles = d.articles.estimated_document_count()
    if not n_articles:
        return {"empty": True}
    agg = list(d.articles.aggregate([{"$group": {
        "_id": None,
        "blocks": {"$sum": {"$size": "$content_blocks"}},
        "block_bytes": {"$sum": {"$bsonSize": {"c": "$content_blocks"}}},
        "actor_refs": {"$sum": {"$size": "$actor_ids"}},
        "cve_refs": {"$sum": {"$size": "$cve_ids"}},
    }}]))[0]
    block_types = [{"type": r["_id"], "n": r["n"]} for r in d.articles.aggregate([
        {"$unwind": "$content_blocks"},
        {"$group": {"_id": "$content_blocks.type", "n": {"$sum": 1}}},
        {"$sort": {"n": -1}}])]
    sizes = {n: collection_sizes(n) for n in
             ("articles", "sources", "threat_actors", "vulnerabilities")}
    refs = {"sources": n_articles, "threat_actors": agg["actor_refs"],
            "vulnerabilities": agg["cve_refs"]}
    duplication = []
    for name, ref_count in refs.items():
        s = sizes.get(name)
        if not s or not s["count"]:
            continue
        stored_once = s["total"]
        if_embedded = ref_count * s["avg"]
        duplication.append({"collection": name, "documents": s["count"], "references": ref_count,
                            "avg_bytes": s["avg"], "stored_once": stored_once,
                            "if_embedded": if_embedded,
                            "factor": if_embedded / stored_once if stored_once else None})
    return {
        "empty": False, "articles": n_articles,
        "avg_blocks": agg["blocks"] / n_articles, "avg_block_bytes": agg["block_bytes"] / n_articles,
        "block_types": block_types, "sizes": sizes, "duplication": duplication,
        "refs": refs, "embedded_exists": "articles_embedded" in d.list_collection_names(),
    }


def median_ms(fn, runs=7):
    fn()   # warm-up, not timed
    times = []
    for _ in range(runs):
        t0 = time.perf_counter()
        fn()
        times.append((time.perf_counter() - t0) * 1000)
    return statistics.median(times)


def api_embed_build(body):
    d = db()
    if not d.articles.estimated_document_count():
        raise ApiError(400, "No articles to copy. Seed the data first.")
    d.articles_embedded.drop()
    t0 = time.perf_counter()
    list(d.articles.aggregate([
        {"$lookup": {"from": "threat_actors", "localField": "actor_ids",
                     "foreignField": "_id", "as": "actors"}},
        {"$project": {"actor_ids": 0}},
        {"$out": "articles_embedded"},
    ]))
    d.articles_embedded.create_index("actors._id")
    d.articles_embedded.create_index([("published", -1)])
    return {"built": d.articles_embedded.estimated_document_count(),
            "seconds": round(time.perf_counter() - t0, 2)}


def api_embed_compare(body):
    d = db()
    if "articles_embedded" not in d.list_collection_names():
        raise ApiError(400, "Build the embedded copy first.")
    first = d.threat_actors.find_one({}, sort=[("name", 1)])
    target = d.threat_actors.find_one({"name": "Lazarus Group"}) or first
    if not target:
        raise ApiError(400, "No threat actors found.")
    tid = target["_id"]

    def q1_ref():
        return list(d.articles.aggregate([
            {"$sort": {"published": -1}}, {"$limit": 50},
            {"$lookup": {"from": "threat_actors", "localField": "actor_ids",
                         "foreignField": "_id", "as": "actors"}},
            {"$project": {"title": 1, "actors.name": 1}}]))

    def q1_emb():
        return list(d.articles_embedded.find({}, {"title": 1, "actors.name": 1})
                    .sort("published", -1).limit(50))

    def q2_ref():
        return list(d.articles.find({"actor_ids": tid}, {"title": 1}))

    def q2_emb():
        return list(d.articles_embedded.find({"actors._id": tid}, {"title": 1}))

    t1r, t1e = median_ms(q1_ref), median_ms(q1_emb)
    t2r, t2e = median_ms(q2_ref), median_ms(q2_emb)
    same = len(q2_ref()) == len(q2_emb())

    original = target.get("motivation", "")
    ref_times, emb_times, ref_mod, emb_mod = [], [], 0, 0
    for i in range(5):
        value = f"{original}-test{i}"
        t0 = time.perf_counter()
        r = d.threat_actors.update_one({"_id": tid}, {"$set": {"motivation": value}})
        ref_times.append((time.perf_counter() - t0) * 1000)
        ref_mod = r.modified_count
        t0 = time.perf_counter()
        r = d.articles_embedded.update_many(
            {"actors._id": tid}, {"$set": {"actors.$[a].motivation": value}},
            array_filters=[{"a._id": tid}])
        emb_times.append((time.perf_counter() - t0) * 1000)
        emb_mod = r.modified_count
    d.threat_actors.update_one({"_id": tid}, {"$set": {"motivation": original}})
    d.articles_embedded.update_many(
        {"actors._id": tid}, {"$set": {"actors.$[a].motivation": original}},
        array_filters=[{"a._id": tid}])

    s_ref, s_emb = collection_sizes("articles"), collection_sizes("articles_embedded")
    return {
        "actor": target["name"], "same_result": same,
        "rows": [
            {"query": "Show the 50 newest articles with their actors' names",
             "referenced_ms": t1r, "embedded_ms": t1e},
            {"query": f"Find the articles that name {target['name']}",
             "referenced_ms": t2r, "embedded_ms": t2e},
            {"query": f"Change one field of {target['name']}",
             "referenced_ms": statistics.median(ref_times), "embedded_ms": statistics.median(emb_times)},
        ],
        "docs_written": {"referenced": ref_mod, "embedded": emb_mod},
        "avg_bytes": {"referenced": s_ref["avg"] if s_ref else None,
                      "embedded": s_emb["avg"] if s_emb else None},
        "total_bytes": {"referenced": s_ref["total"] if s_ref else None,
                        "embedded": s_emb["total"] if s_emb else None},
    }


# ------------------------------------------------------- metrics (Lab 7.2)
def read_cache():
    ss = client().admin.command("serverStatus")
    c = ss["wiredTiger"]["cache"]
    return {
        "requested": c["pages requested from the cache"],
        "read_in": c["pages read into cache"],
        "bytes_read_in": c.get("bytes read into cache", 0),
        "in_cache": c["bytes currently in the cache"],
        "max": c["maximum bytes configured"],
        "dirty": c.get("tracked dirty bytes in the cache", 0),
        "evicted": c.get("unmodified pages evicted", 0) + c.get("modified pages evicted", 0),
    }


def interval_ratio(prev, cur):
    requested = cur["requested"] - prev["requested"]
    misses = cur["read_in"] - prev["read_in"]
    if requested <= 0:
        return None, requested, misses
    return max(0.0, min(1.0, 1 - misses / requested)), requested, misses


class Sampler:
    """Reads the cache counters every SAMPLE_SECONDS and keeps the last 60 readings."""

    def __init__(self):
        self.samples = deque(maxlen=60)
        self.prev = self.latest = None
        self.error = None
        self.next_at = time.time() + SAMPLE_SECONDS
        self.lock = threading.Lock()

    def take(self):
        try:
            cur = read_cache()
        except Exception as exc:   # server down, not WiredTiger, serverStatus not allowed...
            with self.lock:
                self.error = f"{type(exc).__name__}: {str(exc)[:160]}"
            return
        with self.lock:
            self.error = None
            self.latest = cur
            if self.prev:
                ratio, requested, misses = interval_ratio(self.prev, cur)
                self.samples.append({
                    "t": time.time(), "ratio": ratio, "requested": requested, "misses": misses,
                    "fill": cur["in_cache"] / cur["max"] if cur["max"] else 0,
                    "evicted": cur["evicted"] - self.prev["evicted"]})
            self.prev = cur

    def loop(self):
        self.take()
        time.sleep(2)
        self.take()
        while True:
            self.next_at = time.time() + SAMPLE_SECONDS
            time.sleep(SAMPLE_SECONDS)
            self.take()


SAMPLER = Sampler()
WORKLOADS = deque(maxlen=8)


def api_metrics(q):
    with SAMPLER.lock:
        samples, latest, error = list(SAMPLER.samples), SAMPLER.latest, SAMPLER.error
    out = {"interval": SAMPLE_SECONDS, "next_in": max(0, round(SAMPLER.next_at - time.time())),
           "samples": samples, "error": error, "workloads": list(WORKLOADS)}
    if latest:
        out["cache"] = {**latest, "fill": latest["in_cache"] / latest["max"] if latest["max"] else 0}
        out["lifetime_ratio"] = (max(0.0, min(1.0, 1 - latest["read_in"] / latest["requested"]))
                                 if latest["requested"] else None)
    d = db()
    storage, names = [], d.list_collection_names()
    for name in ("articles", "sources", "threat_actors", "vulnerabilities", "articles_embedded"):
        if name not in names:
            continue
        try:
            s = d.command("collStats", name)
            storage.append({"name": name, "count": s["count"], "size": s["size"],
                            "storage": s["storageSize"], "indexes": s["totalIndexSize"],
                            "avg": s.get("avgObjSize", 0)})
        except PyMongoError:
            continue
    out["storage"] = storage
    out["sizes"] = {n: collection_sizes(n) for n in ("articles", "sources", "threat_actors",
                                                     "vulnerabilities") if n in names}
    if latest and storage:
        working_set = sum(s["size"] + s["indexes"] for s in storage)
        share = working_set / latest["max"] if latest["max"] else 0
        out["working_set"] = {
            "bytes": working_set, "share": share,
            "verdict": ("fits" if share <= 0.8 else "borderline" if share <= 1.0 else "too_big")}
    out["seed"] = dict(SEED_STATE)
    return out


def article_ids():
    return cached("article_ids", 120, lambda: [r["_id"] for r in db().articles.find({}, {"_id": 1})])


def api_workload(body):
    reads = max(50, min(20000, int(body.get("reads", 2000) or 2000)))
    ids = article_ids()
    if not ids:
        raise ApiError(400, "No articles to read. Seed the data first.")
    col = db().articles
    rng = random.Random()
    try:
        before = read_cache()
    except Exception:
        before = None
    t0 = time.perf_counter()
    for _ in range(reads):
        col.find_one({"_id": rng.choice(ids)})
    elapsed = time.perf_counter() - t0
    result = {"reads": reads, "seconds": round(elapsed, 3), "avg_ms": elapsed / reads * 1000,
              "docs": len(ids), "at": time.time()}
    if before:
        try:
            after = read_cache()
            ratio, requested, misses = interval_ratio(before, after)
            result.update({"ratio": ratio, "requested": requested, "misses": misses,
                           "evicted": after["evicted"] - before["evicted"],
                           "fill": after["in_cache"] / after["max"] if after["max"] else 0})
            SAMPLER.take()
        except Exception:
            pass
    WORKLOADS.appendleft(result)
    return result


# ------------------------------------------------------------------ seeding
SEED_STATE = {"running": False, "done": False, "error": None, "message": "", "n": 0}


def run_seed(n):
    SEED_STATE.update(running=True, done=False, error=None, n=n, message=f"Seeding {n:,} articles...")
    try:
        path = HERE / "7_1_Seed_ctidigest.py"
        if not path.is_file():
            raise FileNotFoundError("7_1_Seed_ctidigest.py must be in the same folder as this app")
        spec = importlib.util.spec_from_file_location("cti_seed", path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        mod.MONGO_URI, mod.DB_NAME, mod.N_ARTICLES = MONGO_URI, DB_NAME, n
        mod.main()
        clear_caches()
        SEED_STATE.update(done=True, message=f"Seeded {n:,} articles.")
    except Exception as exc:
        SEED_STATE.update(error=f"{type(exc).__name__}: {exc}", message="Seeding failed.")
    finally:
        SEED_STATE["running"] = False


def api_seed(body):
    if SEED_STATE["running"]:
        raise ApiError(409, "Seeding is already running")
    n = max(100, min(100000, int(body.get("n", 500) or 500)))
    threading.Thread(target=run_seed, args=(n,), daemon=True).start()
    return {"started": True, "n": n}


def api_seed_status(q):
    return dict(SEED_STATE)


def api_sample(body):
    SAMPLER.take()
    return {"ok": True}


# --------------------------------------------------------------------- HTTP
GET_ROUTES = [
    (r"^/api/overview$", api_overview),
    (r"^/api/search$", api_search),
    (r"^/api/articles$", api_articles),
    (r"^/api/facets$", api_facets),
    (r"^/api/article/([0-9a-f]{24})$", api_article),
    (r"^/api/actor/([0-9a-f]{24})$", api_actor),
    (r"^/api/vuln/(CVE-[A-Za-z0-9-]+)$", api_vuln),
    (r"^/api/top$", api_top),
    (r"^/api/model$", api_model),
    (r"^/api/metrics$", api_metrics),
    (r"^/api/seed/status$", api_seed_status),
]
POST_ROUTES = {
    "/api/workload": api_workload,
    "/api/seed": api_seed,
    "/api/embed/build": api_embed_build,
    "/api/embed/compare": api_embed_compare,
    "/api/sample": api_sample,
}


class Handler(BaseHTTPRequestHandler):
    server_version = "CTIDigest/1.0"

    def log_message(self, *args):
        pass

    def _send(self, body, ctype="application/json; charset=utf-8", status=200):
        data = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def _json(self, obj, status=200):
        self._send(json.dumps(obj, default=encode), status=status)

    def _local_only(self):
        return (self.headers.get("Host") or "").split(":")[0] in ("127.0.0.1", "localhost", "[::1]")

    def _run(self, fn, *args):
        try:
            self._json(fn(*args))
        except ApiError as exc:
            self._json({"error": exc.message}, exc.status)
        except PyMongoError as exc:
            self._json({"error": f"MongoDB error: {type(exc).__name__}: {str(exc)[:200]}",
                        "mongo": True}, 503)
        except Exception as exc:
            self._json({"error": f"{type(exc).__name__}: {exc}"}, 500)

    def do_GET(self):
        if not self._local_only():
            return self._json({"error": "forbidden"}, 403)
        u = urlparse(self.path)
        if u.path == "/":
            return self._send(PAGE, "text/html; charset=utf-8")
        q = {k: v[0] for k, v in parse_qs(u.query).items()}
        for pattern, fn in GET_ROUTES:
            m = re.match(pattern, u.path)
            if m:
                return self._run(fn, q, *m.groups())
        self._json({"error": "not found"}, 404)

    def do_POST(self):
        if not self._local_only() or self.headers.get("X-Requested-With") != "cti-ui":
            return self._json({"error": "forbidden"}, 403)
        fn = POST_ROUTES.get(urlparse(self.path).path)
        if not fn:
            return self._json({"error": "not found"}, 404)
        try:
            n = int(self.headers.get("Content-Length") or 0)
            body = json.loads(self.rfile.read(n) or b"{}")
        except (ValueError, json.JSONDecodeError):
            return self._json({"error": "bad request"}, 400)
        self._run(fn, body)


# ---------------------------------------------------------------------- page
PAGE = (HERE / "cti_digest_page.html").read_text(encoding="utf-8") \
    if (HERE / "cti_digest_page.html").is_file() else "<h1>cti_digest_page.html is missing</h1>"


def main():
    ap = argparse.ArgumentParser(description="CTI Digest (Chapter 7 web app)")
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--no-browser", action="store_true")
    args = ap.parse_args()

    try:
        client().admin.command("ping")
        print(f"Connected to MongoDB, database '{DB_NAME}'.")
        if not db().articles.estimated_document_count():
            print("The database is empty: open the Database metrics page and use 'Seed demo data'.")
    except PyMongoError as exc:
        print(f"[WARN] MongoDB not reachable ({type(exc).__name__}). Start it, the app will retry.")

    threading.Thread(target=SAMPLER.loop, daemon=True).start()
    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    url = f"http://127.0.0.1:{args.port}"
    print(f"CTI Digest running at {url}  (Ctrl+C to stop)")
    if not args.no_browser:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()