import { IpcError, IpcErrorCodes, IpcErrorCode } from '../types/ipc';

export interface StructuredErrorPresentation {
  title: string;
  description: string;
  suggestedAction?: string;
  severity: 'error' | 'warning' | 'info';
  requiresElevation: boolean;
  canRetry: boolean;
}

/**
 * Maps a strongly-typed IpcError code to a structured, professional presentation.
 * Adheres strictly to: Never show generic "Something went wrong" when a structured code exists.
 */
export function formatIpcError(error: IpcError): StructuredErrorPresentation {
  const code = error.code as IpcErrorCode;

  switch (code) {
    case IpcErrorCodes.ACCESS_DENIED:
      return {
        title: 'Access Denied',
        description: error.message || 'The operating system denied access to one or more requested filesystem locations.',
        suggestedAction: 'Ensure your user account has read/write permissions for the target path or request administrator elevation.',
        severity: 'error',
        requiresElevation: true,
        canRetry: true,
      };

    case IpcErrorCodes.ELEVATION_REQUIRED:
      return {
        title: 'Administrator Elevation Required',
        description: error.message || 'This operation touches protected Windows subsystem locations requiring UAC elevation.',
        suggestedAction: 'Re-run Smart Cleaner with administrator privileges (UAC prompt) to proceed.',
        severity: 'warning',
        requiresElevation: true,
        canRetry: false,
      };

    case IpcErrorCodes.FILE_IN_USE:
      return {
        title: 'File Is In Use By Another Process',
        description: error.message || 'An active background application holds an exclusive file lock on the target.',
        suggestedAction: 'Close the corresponding application before attempting to quarantine this item.',
        severity: 'warning',
        requiresElevation: false,
        canRetry: true,
      };

    case IpcErrorCodes.SOURCE_MISSING:
      return {
        title: 'Source Item Not Found',
        description: error.message || 'The file was deleted or moved by another process between scan and execution.',
        suggestedAction: 'Perform a rescan to synchronize the active candidate list with disk state.',
        severity: 'warning',
        requiresElevation: false,
        canRetry: false,
      };

    case IpcErrorCodes.STATE_DRIFT:
      return {
        title: 'File State Drift Detected',
        description: error.message || 'The file size, hash, or timestamps changed since it was scanned. Pre-flight check aborted.',
        suggestedAction: 'Trigger a fresh scan before applying operations to modified files.',
        severity: 'warning',
        requiresElevation: false,
        canRetry: true,
      };

    case IpcErrorCodes.PROTECTED_ITEM:
      return {
        title: 'Protected System Resource',
        description: error.message || 'Safety Engine hard rules prevent any modification to this protected item.',
        suggestedAction: 'This item is vital to Windows or application integrity and will not be quarantined.',
        severity: 'error',
        requiresElevation: false,
        canRetry: false,
      };

    case IpcErrorCodes.QUARANTINE_FAILED:
      return {
        title: 'Quarantine Vault Ingestion Failed',
        description: error.message || 'The item could not be safely ingested into the quarantine vault.',
        suggestedAction: 'Verify disk space and permissions on the Quarantine Vault storage directory.',
        severity: 'error',
        requiresElevation: false,
        canRetry: true,
      };

    case IpcErrorCodes.RESTORE_CONFLICT:
      return {
        title: 'Restore Target Conflict',
        description: error.message || 'A file already exists at the original restore path or path collision occurred.',
        suggestedAction: 'Specify an alternate restoration directory or inspect existing target file.',
        severity: 'warning',
        requiresElevation: false,
        canRetry: true,
      };

    case IpcErrorCodes.INSUFFICIENT_SPACE:
      return {
        title: 'Insufficient Free Disk Space',
        description: error.message || 'The target drive or quarantine storage volume lacks sufficient capacity.',
        suggestedAction: 'Free space on the target volume or adjust the quarantine storage drive.',
        severity: 'error',
        requiresElevation: false,
        canRetry: true,
      };

    case IpcErrorCodes.UNSUPPORTED_CAPABILITY:
      return {
        title: 'Capability Not Supported',
        description: error.message || 'The requested action is not supported on this platform or storage configuration.',
        suggestedAction: 'Verify Windows version and file system capabilities.',
        severity: 'info',
        requiresElevation: false,
        canRetry: false,
      };

    case IpcErrorCodes.INTERNAL_CORE_ERROR:
    default:
      return {
        title: `Core Operation Error (${error.code || 'UNKNOWN'})`,
        description: error.message || 'The native Rust core reported an unhandled exception or internal invariant failure.',
        suggestedAction: error.details ? JSON.stringify(error.details) : 'Review application logs for diagnostic traces.',
        severity: 'error',
        requiresElevation: false,
        canRetry: true,
      };
  }
}
