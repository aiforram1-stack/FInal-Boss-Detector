"""Stable, sanitized worker failures."""

from __future__ import annotations

from enum import StrEnum


class WorkerErrorCode(StrEnum):
    INVALID_JOB = "INVALID_JOB"
    UNSUPPORTED_MIME_TYPE = "UNSUPPORTED_MIME_TYPE"
    INPUT_TOO_LARGE = "INPUT_TOO_LARGE"
    INPUT_FETCH_FAILED = "INPUT_FETCH_FAILED"
    INPUT_REDIRECT_REJECTED = "INPUT_REDIRECT_REJECTED"
    INPUT_HOST_REJECTED = "INPUT_HOST_REJECTED"
    INPUT_HASH_MISMATCH = "INPUT_HASH_MISMATCH"
    INPUT_LENGTH_MISMATCH = "INPUT_LENGTH_MISMATCH"
    IMAGE_DECODE_FAILED = "IMAGE_DECODE_FAILED"
    IMAGE_DIMENSIONS_EXCEEDED = "IMAGE_DIMENSIONS_EXCEEDED"
    PREPROCESSING_FAILED = "PREPROCESSING_FAILED"
    MODEL_MANIFEST_INVALID = "MODEL_MANIFEST_INVALID"
    CHECKPOINT_UNAVAILABLE = "CHECKPOINT_UNAVAILABLE"
    CHECKPOINT_HASH_MISMATCH = "CHECKPOINT_HASH_MISMATCH"
    CUDA_UNAVAILABLE = "CUDA_UNAVAILABLE"
    MODEL_LOAD_FAILED = "MODEL_LOAD_FAILED"
    INFERENCE_FAILED = "INFERENCE_FAILED"
    OUTPUT_CONTRACT_INVALID = "OUTPUT_CONTRACT_INVALID"
    WORKER_NOT_READY = "WORKER_NOT_READY"
    INTERNAL_ERROR = "INTERNAL_ERROR"


RETRYABLE_CODES = {
    WorkerErrorCode.INPUT_FETCH_FAILED,
    WorkerErrorCode.CUDA_UNAVAILABLE,
    WorkerErrorCode.MODEL_LOAD_FAILED,
    WorkerErrorCode.WORKER_NOT_READY,
    WorkerErrorCode.INTERNAL_ERROR,
}


class WorkerError(RuntimeError):
    """Error safe for conversion into an external worker response."""

    def __init__(
        self,
        code: WorkerErrorCode,
        message: str,
        *,
        retryable: bool | None = None,
        internal_detail: str | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.safe_message = message
        self.retryable = code in RETRYABLE_CODES if retryable is None else retryable
        self.internal_detail = internal_detail

    def external_dict(self) -> dict[str, object]:
        return {
            "schema_version": "1.0",
            "error": {
                "code": self.code.value,
                "message": self.safe_message,
                "retryable": self.retryable,
            },
        }
