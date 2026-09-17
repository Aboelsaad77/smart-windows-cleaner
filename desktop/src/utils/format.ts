/**
 * Formatting utilities for Smart Cleaner Desktop UI
 */

export function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B';
  if (!bytes || isNaN(bytes) || bytes < 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  const val = bytes / Math.pow(k, i);
  return `${val < 10 ? val.toFixed(2) : val.toFixed(1)} ${sizes[i]}`;
}

export function formatDuration(ms: number): string {
  if (!ms || isNaN(ms) || ms < 0) return '0s';
  const totalSeconds = Math.floor(ms / 1000);
  const minutes = Math.floor(totalSeconds / 60);
  const seconds = totalSeconds % 60;

  if (minutes === 0) {
    return `${seconds}s`;
  }

  const hours = Math.floor(minutes / 60);
  const remainingMinutes = minutes % 60;
  if (hours === 0) {
    return `${minutes}m ${seconds.toString().padStart(2, '0')}s`;
  }

  return `${hours}h ${remainingMinutes.toString().padStart(2, '0')}m ${seconds.toString().padStart(2, '0')}s`;
}

export function formatNumber(num: number): string {
  if (typeof num !== 'number' || isNaN(num)) return '0';
  return num.toLocaleString();
}

export function formatRelativeTime(dateString: string): string {
  const date = new Date(dateString);
  if (isNaN(date.getTime())) return dateString;
  const now = new Date();
  const diffSec = Math.floor((now.getTime() - date.getTime()) / 1000);

  if (diffSec < 60) return 'Just now';
  const diffMin = Math.floor(diffSec / 60);
  if (diffMin < 60) return `${diffMin}m ago`;
  const diffHour = Math.floor(diffMin / 60);
  if (diffHour < 24) return `${diffHour}h ago`;
  const diffDay = Math.floor(diffHour / 24);
  if (diffDay < 30) return `${diffDay}d ago`;

  return date.toLocaleDateString();
}

export function formatDate(dateString: string): string {
  const date = new Date(dateString);
  if (isNaN(date.getTime())) return dateString;
  return date.toLocaleString();
}
