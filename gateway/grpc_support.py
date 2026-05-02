from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import re
import shlex
from typing import Any


GRPC_METADATA_NAME_PATTERN = re.compile(r"^[0-9a-z_.-]+$")
GRPC_HTTP_STATUS_MAP = {
    "OK": 200,
    "CANCELLED": 499,
    "UNKNOWN": 502,
    "INVALID_ARGUMENT": 400,
    "DEADLINE_EXCEEDED": 504,
    "NOT_FOUND": 404,
    "ALREADY_EXISTS": 409,
    "PERMISSION_DENIED": 403,
    "RESOURCE_EXHAUSTED": 429,
    "FAILED_PRECONDITION": 400,
    "ABORTED": 409,
    "OUT_OF_RANGE": 400,
    "UNIMPLEMENTED": 501,
    "INTERNAL": 502,
    "UNAVAILABLE": 503,
    "DATA_LOSS": 502,
    "UNAUTHENTICATED": 401,
}


@dataclass(slots=True)
class GrpcInvocationResult:
    status_code: int
    headers: dict[str, str]
    body: bytes
    upstream_url: str
    upstream_curl: str


class GrpcTransportError(RuntimeError):
    def __init__(
        self,
        detail: str,
        *,
        status_code: int = 500,
        upstream_url: str = "",
        upstream_curl: str = "",
    ) -> None:
        super().__init__(detail)
        self.detail = detail
        self.status_code = status_code
        self.upstream_url = upstream_url
        self.upstream_curl = upstream_curl


def invoke_grpc_unary(
    *,
    target: str,
    full_method: str,
    payload: Any,
    metadata: list[tuple[str, str]],
    timeout_seconds: float,
    use_tls: bool,
    authority: str | None = None,
    root_certificates_path: str | None = None,
    descriptor_set_path: str | None = None,
    use_reflection: bool = True,
) -> GrpcInvocationResult:
    grpc, descriptor_pool, descriptor_pb2, json_format, message_factory, reflection_db_cls = (
        _import_grpc_modules(use_reflection=use_reflection and not descriptor_set_path)
    )

    normalized_method = _normalize_full_method(full_method)
    upstream_url = f"{'grpcs' if use_tls else 'grpc'}://{target}{normalized_method}"
    upstream_curl = _build_grpcurl_command(
        target=target,
        full_method=normalized_method,
        payload=payload,
        metadata=metadata,
        use_tls=use_tls,
        descriptor_set_path=descriptor_set_path,
    )

    service_name, method_name = _split_full_method(normalized_method)
    channel = _build_channel(
        grpc=grpc,
        target=target,
        use_tls=use_tls,
        authority=authority,
        root_certificates_path=root_certificates_path,
    )
    try:
        pool = _build_descriptor_pool(
            descriptor_pool=descriptor_pool,
            descriptor_pb2=descriptor_pb2,
            reflection_db_cls=reflection_db_cls,
            channel=channel,
            descriptor_set_path=descriptor_set_path,
            use_reflection=use_reflection,
        )
        service_descriptor = pool.FindServiceByName(service_name)
        method_descriptor = service_descriptor.FindMethodByName(method_name)
        request_cls = _message_class(message_factory, pool, method_descriptor.input_type)
        response_cls = _message_class(message_factory, pool, method_descriptor.output_type)
        request_message = request_cls()
        json_text = json.dumps({} if payload is None else payload, ensure_ascii=False)
        json_format.Parse(json_text, request_message, ignore_unknown_fields=False)

        rpc = channel.unary_unary(
            normalized_method,
            request_serializer=lambda message: message.SerializeToString(),
            response_deserializer=response_cls.FromString,
        )
        grpc_metadata = _normalize_metadata(metadata)
        try:
            response_message = rpc(
                request_message,
                timeout=timeout_seconds,
                metadata=grpc_metadata,
            )
        except grpc.RpcError as exc:
            response_payload = {
                "detail": exc.details() or (exc.code().name if exc.code() else "gRPC upstream error"),
                "grpc_code": exc.code().name if exc.code() else "UNKNOWN",
                "grpc_status": exc.code().value[0] if exc.code() else 2,
            }
            return GrpcInvocationResult(
                status_code=_grpc_status_to_http_status(exc),
                headers={"Content-Type": "application/json; charset=utf-8"},
                body=json.dumps(response_payload, ensure_ascii=False).encode("utf-8"),
                upstream_url=upstream_url,
                upstream_curl=upstream_curl,
            )

        response_payload = json_format.MessageToDict(
            response_message,
            preserving_proto_field_name=True,
        )
        return GrpcInvocationResult(
            status_code=200,
            headers={"Content-Type": "application/json; charset=utf-8"},
            body=json.dumps(response_payload, ensure_ascii=False).encode("utf-8"),
            upstream_url=upstream_url,
            upstream_curl=upstream_curl,
        )
    except GrpcTransportError:
        raise
    except Exception as exc:  # noqa: BLE001
        raise GrpcTransportError(
            f"gRPC invocation failed for {normalized_method}: {exc}",
            status_code=502,
            upstream_url=upstream_url,
            upstream_curl=upstream_curl,
        ) from exc
    finally:
        channel.close()


def _import_grpc_modules(*, use_reflection: bool) -> tuple[Any, Any, Any, Any, Any, Any]:
    try:
        import grpc  # type: ignore[import-not-found]
    except ImportError as exc:  # pragma: no cover - depends on optional extra
        raise GrpcTransportError(
            "gRPC upstreams require the optional grpc dependencies. Install with pip install \".[grpc]\".",
            status_code=500,
        ) from exc
    try:
        from google.protobuf import descriptor_pb2, descriptor_pool, json_format, message_factory  # type: ignore[import-not-found]
    except ImportError as exc:  # pragma: no cover - depends on optional extra
        raise GrpcTransportError(
            "gRPC upstreams require protobuf support. Install with pip install \".[grpc]\".",
            status_code=500,
        ) from exc

    reflection_db_cls = None
    if use_reflection:
        try:
            from grpc_reflection.v1alpha.proto_reflection_descriptor_database import ProtoReflectionDescriptorDatabase  # type: ignore[import-not-found]
        except ImportError as exc:  # pragma: no cover - depends on optional extra
            raise GrpcTransportError(
                "gRPC reflection support requires grpc reflection dependencies. Install with pip install \".[grpc]\" or configure grpc.descriptor_set_path.",
                status_code=500,
            ) from exc
        reflection_db_cls = ProtoReflectionDescriptorDatabase
    return grpc, descriptor_pool, descriptor_pb2, json_format, message_factory, reflection_db_cls


def _normalize_full_method(full_method: str) -> str:
    method = str(full_method or "").strip()
    if not method:
        raise GrpcTransportError("Configured gRPC method is empty.", status_code=500)
    if not method.startswith("/"):
        method = f"/{method}"
    if method.count("/") != 2:
        raise GrpcTransportError(
            "Configured gRPC method must look like /package.Service/Method.",
            status_code=500,
        )
    return method


def _split_full_method(full_method: str) -> tuple[str, str]:
    service_name, method_name = full_method.lstrip("/").rsplit("/", 1)
    if not service_name or not method_name:
        raise GrpcTransportError(
            "Configured gRPC method must look like /package.Service/Method.",
            status_code=500,
        )
    return service_name, method_name


def _build_channel(
    *,
    grpc: Any,
    target: str,
    use_tls: bool,
    authority: str | None,
    root_certificates_path: str | None,
):
    options: list[tuple[str, str]] = []
    if authority:
        options.append(("grpc.ssl_target_name_override", authority))
        options.append(("grpc.default_authority", authority))
    if not use_tls:
        return grpc.insecure_channel(target, options=options)

    root_certificates = None
    if root_certificates_path:
        try:
            root_certificates = Path(root_certificates_path).read_bytes()
        except OSError as exc:
            raise GrpcTransportError(
                f"Could not read gRPC root certificates from {root_certificates_path}: {exc}",
                status_code=500,
            ) from exc
    credentials = grpc.ssl_channel_credentials(root_certificates=root_certificates)
    return grpc.secure_channel(target, credentials, options=options)


def _build_descriptor_pool(
    *,
    descriptor_pool: Any,
    descriptor_pb2: Any,
    reflection_db_cls: Any,
    channel: Any,
    descriptor_set_path: str | None,
    use_reflection: bool,
):
    if descriptor_set_path:
        pool = descriptor_pool.DescriptorPool()
        file_set = descriptor_pb2.FileDescriptorSet()
        try:
            file_set.ParseFromString(Path(descriptor_set_path).read_bytes())
        except OSError as exc:
            raise GrpcTransportError(
                f"Could not read gRPC descriptor set from {descriptor_set_path}: {exc}",
                status_code=500,
            ) from exc
        for file_descriptor in file_set.file:
            pool.Add(file_descriptor)
        return pool

    if not use_reflection:
        raise GrpcTransportError(
            "gRPC services need grpc.use_reflection=true or grpc.descriptor_set_path.",
            status_code=500,
        )

    reflection_db = reflection_db_cls(channel)
    return descriptor_pool.DescriptorPool(reflection_db)


def _message_class(message_factory_module: Any, pool: Any, descriptor: Any):
    get_message_class = getattr(message_factory_module, "GetMessageClass", None)
    if callable(get_message_class):
        return get_message_class(descriptor)
    factory = message_factory_module.MessageFactory(pool)
    get_prototype = getattr(factory, "GetPrototype", None)
    if callable(get_prototype):
        return get_prototype(descriptor)
    raise GrpcTransportError(
        "Installed protobuf runtime does not expose a dynamic message factory.",
        status_code=500,
    )


def _normalize_metadata(metadata: list[tuple[str, str]]) -> list[tuple[str, Any]]:
    normalized: list[tuple[str, Any]] = []
    for raw_name, raw_value in metadata:
        name = str(raw_name or "").strip().lower()
        if not name or not GRPC_METADATA_NAME_PATTERN.fullmatch(name):
            continue
        value = "" if raw_value is None else str(raw_value)
        normalized.append((name, value.encode("utf-8") if name.endswith("-bin") else value))
    return normalized


def _grpc_status_to_http_status(exc: Any) -> int:
    code = exc.code()
    name = code.name if code is not None else "UNKNOWN"
    return GRPC_HTTP_STATUS_MAP.get(name, 502)


def _build_grpcurl_command(
    *,
    target: str,
    full_method: str,
    payload: Any,
    metadata: list[tuple[str, str]],
    use_tls: bool,
    descriptor_set_path: str | None,
) -> str:
    command = ["grpcurl"]
    if not use_tls:
        command.append("-plaintext")
    if descriptor_set_path:
        command.extend(["-protoset", descriptor_set_path])
    for name, value in metadata:
        command.extend(["-H", f"{name}: {value}"])
    command.extend(["-d", json.dumps({} if payload is None else payload, ensure_ascii=False)])
    command.append(target)
    command.append(full_method.lstrip("/"))
    return " \\\n  ".join(shlex.quote(part) for part in command)
