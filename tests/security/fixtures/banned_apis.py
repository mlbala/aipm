# A deliberately violating module for tests/security/test_banned_api.py.
# It is excluded from the normal ruff run and never imported. The test lints it as if it lived
# at src/aipm/; every line below must be reported, by ruff's TID251 rule or by the AST scan.
import _posixsubprocess
import asyncio
import builtins
import code
import codeop
import ctypes
import importlib
import importlib.machinery
import importlib.util
import marshal
import multiprocessing
import os
import pickle
import posix
import pty
import pydoc
import runpy
import subprocess
import sys
import webbrowser
from asyncio import subprocess as asyncio_subprocess
from concurrent.futures import ProcessPoolExecutor

asyncio.create_subprocess_exec("x")
asyncio.create_subprocess_shell("x")
asyncio.get_event_loop().subprocess_exec(object, "x")
os.system("x")
os.popen("x")
os.fork()
os.forkpty()
os.posix_spawn("x", ["x"], {})
os.posix_spawnp("x", ["x"], {})
os.execv("x", ["x"])
os.spawnv(os.P_WAIT, "x", ["x"])
getattr(os, "system")("x")
sys.modules["subprocess"]
importlib.import_module("os")
importlib.__import__("os")
__builtins__["__import__"]("os")
__import__("os")
