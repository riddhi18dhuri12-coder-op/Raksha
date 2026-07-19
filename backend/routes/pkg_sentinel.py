"""
RAKSHA -- Package Trust Scanner endpoint.

A Python port of the core detection logic from the standalone "pkg-sentinel"
npm supply-chain security CLI: typosquatting detection (Levenshtein distance
+ pattern matching against a curated popular-package list) and install-script
risk heuristics (credential access, exec/shell, network exfiltration,
obfuscation patterns).

Scope note: pkg-sentinel's original script-analyzer parses the actual JS
*files* a package's install scripts point to, using a full AST engine
(scores of files, acorn-based). That's a large standalone toolchain. This
port instead applies the same pattern library directly to the "scripts"
field of a package's real package.json (fetched live from the npm registry)
-- which is exactly where a huge share of real supply-chain attacks live
(e.g. `"postinstall": "curl ... | bash"` embedded right in the manifest).
Full tarball/AST analysis of arbitrary installed JS is intentionally out of
scope here; the npm registry metadata (versions, maintainers, repository,
publish history) and typosquat detection are real, live lookups against
https://registry.npmjs.org.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone

import requests
from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter(prefix="/api/pkg-sentinel", tags=["pkg-sentinel"])

NPM_REGISTRY = "https://registry.npmjs.org"

# ---------------------------------------------------------------------------
# Popular package list (curated subset, ported from pkg-sentinel)
# ---------------------------------------------------------------------------
POPULAR_PACKAGES = [
    "lodash", "underscore", "ramda", "rxjs",
    "typescript", "webpack", "rollup", "esbuild", "vite", "parcel", "turbo",
    "babel-core", "@babel/core", "@babel/parser", "@babel/traverse",
    "tsup", "tslib", "ts-node", "tsx",
    "jest", "mocha", "chai", "vitest", "cypress", "playwright",
    "sinon", "nyc", "istanbul", "supertest",
    "react", "react-dom", "react-router", "react-router-dom",
    "next", "gatsby", "redux", "react-redux", "@reduxjs/toolkit",
    "styled-components", "emotion", "@emotion/react", "@emotion/styled",
    "formik", "react-hook-form", "swr", "react-query", "@tanstack/react-query",
    "vue", "vuex", "vue-router", "pinia", "nuxt",
    "@angular/core", "@angular/cli", "@angular/common",
    "express", "koa", "fastify", "hapi", "nest", "@nestjs/core",
    "socket.io", "ws", "cors", "helmet", "morgan", "compression",
    "commander", "yargs", "minimist", "meow", "inquirer",
    "chalk", "ora", "cli-progress", "cli-table3", "boxen",
    "mongoose", "sequelize", "typeorm", "prisma", "@prisma/client",
    "pg", "mysql", "mysql2", "redis", "ioredis", "knex",
    "mongodb", "sqlite3", "better-sqlite3",
    "axios", "node-fetch", "got", "superagent", "request", "undici",
    "fs-extra", "glob", "globby", "chokidar", "rimraf", "mkdirp",
    "uuid", "nanoid", "date-fns", "moment", "dayjs", "luxon",
    "debug", "dotenv", "cross-env", "env-cmd",
    "semver", "yup", "zod", "joi", "ajv",
    "async", "bluebird", "p-limit", "p-queue",
    "jsonwebtoken", "bcrypt", "bcryptjs", "passport", "helmet",
    "crypto-js", "jose", "oauth",
    "winston", "pino", "bunyan", "log4js", "morgan",
    "eslint", "prettier", "stylelint", "tslint",
    "tailwindcss", "postcss", "autoprefixer", "sass", "less",
    "css-loader", "style-loader",
    "npm", "yarn", "pnpm", "lerna",
    "aws-sdk", "@aws-sdk/client-s3", "@aws-sdk/client-lambda",
    "@google-cloud/storage", "firebase", "firebase-admin",
    "body-parser", "cookie-parser", "multer", "sharp",
    "cheerio", "puppeteer", "jsdom",
    "marked", "markdown-it", "highlight.js", "prismjs",
    "nodemailer", "handlebars", "ejs", "pug",
    "classnames", "clsx", "prop-types",
    "immutable", "immer",
    "husky", "lint-staged", "commitlint",
    "cross-spawn", "execa", "shelljs",
    "tar", "archiver", "adm-zip",
    "xml2js", "csv-parse", "papaparse",
    "socket.io-client",
    "three", "d3", "chart.js", "echarts",
    "swiper", "slick-carousel",
    "framer-motion", "gsap",
    "i18next", "react-i18next", "vue-i18n",
    "storybook", "@storybook/react",
    "electron", "electron-builder",
    "pm2", "nodemon", "concurrently",
]

# ---------------------------------------------------------------------------
# Typosquat detection (ported from levenshtein.ts / typosquat-analyzer.ts)
# ---------------------------------------------------------------------------

def _levenshtein(a: str, b: str) -> int:
    m, n = len(a), len(b)
    if m == 0:
        return n
    if n == 0:
        return m
    previous = list(range(n + 1))
    current = [0] * (n + 1)
    for i in range(1, m + 1):
        current[0] = i
        for j in range(1, n + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            current[j] = min(current[j - 1] + 1, previous[j] + 1, previous[j - 1] + cost)
        previous, current = current, previous
    return previous[n]


_SUBSTITUTIONS = {
    "0": ["o", "O"], "o": ["0"], "O": ["0"],
    "1": ["l", "I", "i"], "l": ["1", "I"], "I": ["1", "l"], "i": ["1"],
}


def _has_character_substitution(a: str, b: str) -> bool:
    if len(a) != len(b):
        return False
    differences = 0
    for ca, cb in zip(a, b):
        if ca != cb:
            differences += 1
            if cb not in _SUBSTITUTIONS.get(ca, []):
                return False
    return 0 < differences <= 2


def _has_separator_confusion(a: str, b: str) -> bool:
    normalize = lambda s: re.sub(r"[-_.]", "", s)  # noqa: E731
    return a != b and normalize(a) == normalize(b)


def _detect_typosquat_patterns(suspect: str, legitimate: str) -> list[dict]:
    matches = []
    if _has_character_substitution(suspect, legitimate):
        matches.append({
            "type": "character-substitution",
            "description": f'"{suspect}" has character substitution compared to "{legitimate}"',
            "confidence": 85,
        })
    if _has_separator_confusion(suspect, legitimate):
        matches.append({
            "type": "separator-confusion",
            "description": f'"{suspect}" differs only in separators from "{legitimate}"',
            "confidence": 90,
        })
    if _levenshtein(suspect, legitimate) == 1:
        matches.append({
            "type": "single-char-edit",
            "description": f'"{suspect}" is 1 character edit away from "{legitimate}"',
            "confidence": 92,
        })
    unscoped = re.sub(r"^@[^/]+/", "", suspect)
    if unscoped != suspect and unscoped == legitimate:
        matches.append({
            "type": "scope-squatting",
            "description": f'"{suspect}" adds a scope to legitimate package "{legitimate}"',
            "confidence": 70,
        })
    if re.search(r"\d+$", suspect):
        without_digits = re.sub(r"\d+$", "", suspect)
        if without_digits == legitimate:
            matches.append({
                "type": "version-in-name",
                "description": f'"{suspect}" appends digits to "{legitimate}"',
                "confidence": 75,
            })
    return matches


def _check_typosquatting(package_name: str) -> list[dict]:
    if package_name in POPULAR_PACKAGES:
        return []
    findings = []
    for popular in POPULAR_PACKAGES:
        if abs(len(package_name) - len(popular)) > 2:
            continue
        matches = _detect_typosquat_patterns(package_name, popular)
        if matches:
            findings.append({"similar_to": popular, "matches": matches})
    findings.sort(key=lambda f: max(m["confidence"] for m in f["matches"]), reverse=True)
    return findings[:5]

# ---------------------------------------------------------------------------
# Install-script heuristics (ported from detectors/*.ts, applied directly to
# the literal "scripts" command strings from package.json rather than a full
# AST walk of referenced JS files -- see module docstring)
# ---------------------------------------------------------------------------

_CREDENTIAL_PATTERNS = [
    ("NPM_TOKEN", "critical"), ("NODE_AUTH_TOKEN", "critical"),
    ("GITHUB_TOKEN", "critical"), ("GH_TOKEN", "critical"),
    ("AWS_ACCESS_KEY", "critical"), ("AWS_SECRET_ACCESS_KEY", "critical"),
    ("DOCKER_PASSWORD", "critical"), ("SLACK_TOKEN", "high"),
    ("DISCORD_TOKEN", "high"), ("API_KEY", "high"), ("SECRET_KEY", "high"),
    ("PRIVATE_KEY", "high"), ("PASSWORD", "high"), ("REGISTRY_TOKEN", "critical"),
    (".npmrc", "critical"), ("id_rsa", "critical"), (".ssh/", "critical"),
    (".git-credentials", "high"), (".gitconfig", "high"),
]

_DANGEROUS_COMMANDS = [
    "curl", "wget", "powershell", "certutil", "bitsadmin", "cmd.exe",
    "bash -c", "/bin/sh", "/bin/bash", "cmd /c", "Start-Process",
    "Invoke-WebRequest", "Invoke-Expression", "IEX", "nslookup",
]

_NETWORK_PATTERNS = [
    (r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", "raw-ip-url",
     "Sends data to a raw IP address rather than a domain"),
    (r"pastebin\.com|discord(app)?\.com/api/webhooks|telegram\.org/bot", "exfil-endpoint",
     "References a known data-exfiltration-style endpoint (pastebin/webhook/bot API)"),
]

_OBFUSCATION_PATTERNS = [
    (r"\beval\s*\(", "eval-usage", "high"),
    (r"Buffer\.from\([^)]*['\"]base64['\"]\)", "base64-decode", "medium"),
    (r"(\\x[0-9a-fA-F]{2}){6,}", "hex-escape-obfuscation", "high"),
    (r"atob\s*\(", "base64-decode", "medium"),
]


def _scan_script_text(script_name: str, command: str) -> list[dict]:
    findings = []
    for pattern, severity in _CREDENTIAL_PATTERNS:
        if pattern in command:
            findings.append({
                "detector": "credential", "severity": severity,
                "description": f'"{script_name}" references credential-like pattern "{pattern}"',
            })
    for cmd in _DANGEROUS_COMMANDS:
        if cmd in command:
            findings.append({
                "detector": "exec", "severity": "critical" if cmd in ("curl", "wget", "Invoke-Expression", "IEX") else "high",
                "description": f'"{script_name}" invokes "{cmd}"',
            })
    for pattern, ftype, desc in _NETWORK_PATTERNS:
        if re.search(pattern, command):
            findings.append({"detector": "network", "severity": "critical", "description": f'"{script_name}": {desc}'})
    for pattern, ftype, severity in _OBFUSCATION_PATTERNS:
        if re.search(pattern, command):
            findings.append({
                "detector": "obfuscation", "severity": severity,
                "description": f'"{script_name}" contains obfuscation pattern ({ftype})',
            })
    return findings

# ---------------------------------------------------------------------------
# Endpoint
# ---------------------------------------------------------------------------


class PackageScanRequest(BaseModel):
    package: str


@router.post("/scan")
def scan_package(request: PackageScanRequest):
    name = request.package.strip()
    typosquat_findings = _check_typosquatting(name)

    registry_error = None
    metadata = {}
    script_findings = []
    scripts = {}

    try:
        resp = requests.get(f"{NPM_REGISTRY}/{name}", timeout=8)
        if resp.status_code == 404:
            registry_error = "Package not found on the npm registry."
        else:
            resp.raise_for_status()
            data = resp.json()
            latest_tag = data.get("dist-tags", {}).get("latest")
            versions = data.get("versions", {})
            latest = versions.get(latest_tag, {}) if latest_tag else {}
            scripts = latest.get("scripts", {}) or {}
            time_info = data.get("time", {})
            created = time_info.get("created")
            modified = time_info.get("modified")
            age_days = None
            if created:
                created_dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
                age_days = (datetime.now(timezone.utc) - created_dt).days
            maintainers = data.get("maintainers", [])
            metadata = {
                "latest_version": latest_tag,
                "total_versions": len(versions),
                "created": created,
                "last_modified": modified,
                "package_age_days": age_days,
                "maintainer_count": len(maintainers),
                "has_repository": bool(data.get("repository")),
                "license": latest.get("license") or data.get("license"),
                "description": data.get("description"),
            }
            for script_name, command in scripts.items():
                if script_name in ("preinstall", "install", "postinstall", "prepare"):
                    script_findings.extend(_scan_script_text(script_name, command))
    except requests.RequestException as e:
        registry_error = f"Could not reach the npm registry: {e}"

    # ---- trust score (0-100, higher = more trustworthy) ----
    score = 100
    reasons = []

    if typosquat_findings:
        top = typosquat_findings[0]
        top_conf = max(m["confidence"] for m in top["matches"])
        penalty = round(top_conf * 0.5)
        score -= penalty
        reasons.append(f"Name closely resembles popular package \"{top['similar_to']}\" ({top['matches'][0]['type']}).")

    severity_penalty = {"critical": 30, "high": 18, "medium": 8, "low": 3}
    for f in script_findings:
        score -= severity_penalty.get(f["severity"], 5)
        reasons.append(f["description"])

    if metadata.get("package_age_days") is not None and metadata["package_age_days"] < 14:
        score -= 15
        reasons.append("Package was published to npm less than 14 days ago.")
    if metadata and not metadata.get("has_repository"):
        score -= 5
        reasons.append("No source repository listed in package metadata.")

    score = max(0, min(100, score))
    if score >= 80:
        level = "Trusted"
    elif score >= 55:
        level = "Caution"
    else:
        level = "High Risk"

    return {
        "package": name,
        "trust_score": score,
        "trust_level": level,
        "reasons": reasons,
        "typosquat_findings": typosquat_findings,
        "install_scripts": scripts,
        "script_findings": script_findings,
        "metadata": metadata,
        "registry_error": registry_error,
    }
