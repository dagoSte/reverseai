"""Derived Ghidra analysis through the contained worker; the host verifies its anchors."""

from pathlib import Path

from reverseai.contained import ContainedError, DockerExecutor, inspect_image, load_lock
from reverseai.contract import ArgSpec, ContractError, OperationSpec, ToolRef, ToolSpec, WorkerError, parse_worker_reply, sha256_hex
from reverseai.tools import ghidra_verify

REF = ToolRef("ghidra", "12.1.4-r2")
DEFAULT_LOCK = Path(__file__).resolve().parents[2] / "containers/ghidra/image.lock.json"


def make_tool(executor=None):
    if executor is None:
        executor = DockerExecutor(DEFAULT_LOCK, adapter_version=REF.version)
    lock = load_lock(executor.lock, adapter_version=REF.version)

    def invoke(data, args):
        checked = operation.validate_args(args)
        digest = sha256_hex(data)
        raw = executor.run("ghidra.analyze", checked, data, digest)
        try:
            observations = parse_worker_reply(raw, input_sha256=digest, max_observations=400)
        except WorkerError:
            raise
        except (ContractError, UnicodeError):
            raise ContractError(ghidra_verify.REFUSED) from None
        ghidra_verify.verify(data, observations, checked)
        return observations

    operation = OperationSpec("ghidra.analyze", {
        "max_functions": ArgSpec("int", 1, 128, default=64),
        "decompile": ArgSpec("int", 0, 16, default=8),
        "max_chars": ArgSpec("int", 64, 2048, default=1024),
        "max_calls": ArgSpec("int", 0, 256, default=128),
    }, invoke, max_observations=400, derived=True)
    return ToolSpec(REF, {operation.name: operation}, contained=True,
                    runtime={"image": lock["image_id"], "platform": lock["platform"]})


def available(lock=None, *, inspect=None):
    try:
        executor = DockerExecutor(DEFAULT_LOCK if lock is None else lock, adapter_version=REF.version,
                                  inspect=inspect_image if inspect is None else inspect)
        return executor.available()
    except ContainedError:
        return False


def __getattr__(name):
    if name == "TOOL":
        return make_tool()
    raise AttributeError(name)
