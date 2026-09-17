"use strict";
/**
 * Strongly-typed IPC Contract Types for Smart Cleaner Desktop UI
 * Matching docs/IPC-CONTRACT.md and core/crates/file-models/src/ipc.rs
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.IpcErrorCodes = void 0;
// Well-known structured IPC Error Codes
exports.IpcErrorCodes = {
    ACCESS_DENIED: 'ACCESS_DENIED',
    ELEVATION_REQUIRED: 'ELEVATION_REQUIRED',
    FILE_IN_USE: 'FILE_IN_USE',
    SOURCE_MISSING: 'SOURCE_MISSING',
    STATE_DRIFT: 'STATE_DRIFT',
    PROTECTED_ITEM: 'PROTECTED_ITEM',
    QUARANTINE_FAILED: 'QUARANTINE_FAILED',
    RESTORE_CONFLICT: 'RESTORE_CONFLICT',
    INSUFFICIENT_SPACE: 'INSUFFICIENT_SPACE',
    UNSUPPORTED_CAPABILITY: 'UNSUPPORTED_CAPABILITY',
    INTERNAL_CORE_ERROR: 'INTERNAL_CORE_ERROR',
};
