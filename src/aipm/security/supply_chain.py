"""Pure supply-chain checks: package names, typosquat distance, release-age policy (SECURITY.md
§12.2).

The registry HTTP lookups live in `aipm.scanners.registry` (ARCHITECTURE §5.1). A new
dependency passes only if its name is valid for its ecosystem, it is not one edit away from a
popular package it is not, and its first release is at least `min_dependency_age_days` old.
That catches hallucinated names ("slopsquatting") and freshly published malicious packages.
"""

import re
from collections.abc import Iterable, Sequence
from datetime import datetime, timedelta

from aipm.domain.errors import PolicyViolation
from aipm.domain.models import DependencyAdd, Ecosystem

MAX_NAME = 214

POPULAR_PYPI: tuple[str, ...] = (
    "aiohttp", "alembic", "anyio", "attrs", "azure-core", "babel", "beautifulsoup4", "black",
    "boto3", "botocore", "build", "cachetools", "celery", "certifi", "cffi", "chardet",
    "charset-normalizer", "click", "colorama", "coverage", "cryptography", "cython", "dask",
    "decorator", "django", "djangorestframework", "docker", "docutils", "dnspython",
    "email-validator",
    "fastapi", "filelock", "flake8", "flask", "fsspec", "gevent", "gitpython", "google-api-core",
    "google-auth", "greenlet", "grpcio", "gunicorn", "h11", "httpcore", "httpx", "huggingface-hub",
    "hypothesis", "idna", "importlib-metadata", "iniconfig", "isort", "itsdangerous", "jinja2",
    "jmespath", "joblib", "jsonschema", "keras", "kombu", "lxml", "markdown", "markupsafe",
    "matplotlib", "mock", "more-itertools", "msgpack", "mypy", "networkx", "nltk", "numpy",
    "oauthlib", "openai", "openpyxl", "opencv-python", "orjson", "packaging", "pandas",
    "paramiko", "pathspec", "pillow", "pip", "platformdirs", "pluggy", "poetry", "protobuf",
    "psutil", "psycopg", "psycopg2", "psycopg2-binary", "pyarrow", "pycparser", "pydantic",
    "pydantic-core", "pyflakes", "pygments", "pyjwt", "pylint", "pymongo", "pymysql",
    "pyopenssl", "pyparsing", "pytest", "pytest-asyncio", "pytest-cov", "pytest-mock",
    "python-dateutil", "python-dotenv", "python-multipart", "pytz", "pyyaml", "redis", "regex",
    "requests", "requests-oauthlib", "rich", "rsa", "ruamel-yaml", "ruff", "s3transfer",
    "scikit-learn", "scipy", "selenium", "setuptools", "shapely", "simplejson", "six",
    "slowapi", "sniffio", "soupsieve", "sqlalchemy", "starlette", "sympy", "tabulate",
    "tenacity", "tensorflow", "toml", "tomli", "torch", "tornado", "tqdm", "transformers",
    "typer", "typing-extensions", "tzdata", "ujson", "urllib3", "uvicorn", "uvloop",
    "virtualenv", "websockets", "werkzeug", "wheel", "wrapt", "xlrd", "yarl", "zipp",
)  # fmt: skip
"""Widely used PyPI names, PEP 503 normalized: the typosquat reference list."""

POPULAR_NPM: tuple[str, ...] = (
    "@angular/core", "@babel/core", "@nestjs/core", "@types/node", "@types/react",
    "@vitejs/plugin-react", "angular", "ajv", "axios", "babel-loader", "bcrypt", "bluebird",
    "body-parser", "chalk", "cheerio", "chokidar", "classnames", "commander", "compression",
    "cookie-parser", "cors", "cross-env", "csstype", "date-fns", "dayjs", "debug", "dotenv",
    "esbuild", "eslint", "eslint-config-prettier", "eslint-plugin-react", "express",
    "express-validator", "fastify", "fs-extra", "glob", "graphql", "helmet", "husky",
    "immer", "inquirer", "jest", "jquery", "js-yaml", "jsonwebtoken", "knex", "lint-staged",
    "lodash", "lru-cache", "minimist", "mkdirp", "mocha", "moment", "mongodb", "mongoose",
    "morgan", "multer", "mysql", "mysql2", "nanoid", "next", "node-fetch", "nodemailer",
    "nodemon", "nuxt", "passport", "pg", "pino", "playwright", "postcss", "prettier",
    "prisma", "prop-types", "puppeteer", "qs", "react", "react-dom", "react-redux",
    "react-router", "react-router-dom", "redis", "redux", "request", "rimraf", "rollup",
    "rxjs", "sass", "semver", "sequelize", "sharp", "socket.io", "styled-components",
    "supertest", "svelte", "tailwindcss", "ts-node", "tslib", "typeorm", "typescript",
    "underscore", "uuid", "vite", "vitest", "vue", "webpack", "webpack-cli", "winston",
    "ws", "yargs", "zod", "zustand",
)  # fmt: skip
"""Widely used npm names: the typosquat reference list."""

POPULAR: dict[Ecosystem, tuple[str, ...]] = {
    Ecosystem.PYPI: POPULAR_PYPI,
    Ecosystem.NPM: POPULAR_NPM,
}


def normalize_name(ecosystem: Ecosystem, name: str) -> str:
    """PEP 503 for PyPI (lowercase, runs of `-_.` become `-`); lowercase for npm."""
    if ecosystem is Ecosystem.PYPI:
        return re.sub(r"[-_.]+", "-", name).lower()
    return name.lower()


def check_package_name(ecosystem: str, name: str) -> DependencyAdd:
    """Validate the ecosystem and the name format, or raise `PolicyViolation` (exit 6)."""
    try:
        eco = Ecosystem(ecosystem)
    except ValueError:
        raise PolicyViolation(f"unknown package ecosystem {ecosystem[:40]!r}") from None
    if not 0 < len(name) <= MAX_NAME:
        raise PolicyViolation(f"a {eco.value} package name has 1 to {MAX_NAME} characters")
    try:
        return DependencyAdd(ecosystem=eco, name=name)
    except ValueError:
        raise PolicyViolation(f"{name[:80]!r} is not a valid {eco.value} package name") from None


def edit_distance(a: str, b: str, *, limit: int = 3) -> int:
    """Optimal-string-alignment distance (an adjacent swap costs 1), capped at `limit + 1`."""
    if abs(len(a) - len(b)) > limit:
        return limit + 1
    prev2: list[int] = []
    prev = list(range(len(b) + 1))
    for i in range(1, len(a) + 1):
        row = [i] + [0] * len(b)
        for j in range(1, len(b) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            row[j] = min(prev[j] + 1, row[j - 1] + 1, prev[j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                row[j] = min(row[j], prev2[j - 2] + 1)
        if min(row) > limit:
            return limit + 1
        prev2, prev = prev, row
    return min(prev[len(b)], limit + 1)


def typosquat_distance(name: str, popular: Sequence[str]) -> int:
    """The smallest edit distance from `name` to a popular name other than itself (capped at 4)."""
    others = [p for p in popular if p != name]
    return min((edit_distance(name, p) for p in others), default=4)


def typosquat_of(ecosystem: Ecosystem, name: str, *, popular: Iterable[str] = ()) -> str | None:
    """The popular package `name` is one edit away from, if any (and it is not that package)."""
    wanted = normalize_name(ecosystem, name)
    reference = tuple(popular) or POPULAR[ecosystem]
    if wanted in reference:
        return None
    scope, _, base = wanted.rpartition("/")
    for candidate in reference:
        if edit_distance(wanted, candidate, limit=1) <= 1:
            return candidate
        if scope and "/" not in candidate and edit_distance(base, candidate, limit=1) == 0:
            return candidate
    return None


def age_ok(first_release: datetime, *, min_days: int, now: datetime) -> bool:
    """Whether a package's first release is at least `min_days` old."""
    return now - first_release >= timedelta(days=min_days)
