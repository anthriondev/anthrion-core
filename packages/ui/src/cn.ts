import { clsx, type ClassValue } from 'clsx';

/**
 * Compose conditional className strings. Thin wrapper over `clsx` so components
 * have one import for class composition.
 */
export function cn(...inputs: ClassValue[]): string {
  return clsx(inputs);
}
