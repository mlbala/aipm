# A deliberately violating module for tests/security/test_banned_api.py.
# It is excluded from the normal ruff run and never imported. The test lints it as if it lived
# at src/aipm/, where every line below must be reported by the TID251 banned-api rule.
import _posixsubprocess
import asyncio
import builtins
import importlib
import marshal
import multiprocessing
import os
import pickle
import posix
import pty
import subprocess
from asyncio import subprocess as asyncio_subprocess

asyncio.create_subprocess_exec("x")
asyncio.create_subprocess_shell("x")
os.system("x")
os.popen("x")
os.fork()
os.forkpty()
os.posix_spawn("x", ["x"], {})
os.posix_spawnp("x", ["x"], {})
os.execv("x", ["x"])
os.spawnv(os.P_WAIT, "x", ["x"])
importlib.import_module("os")
__builtins__["__import__"]("os")
__import__("os")
