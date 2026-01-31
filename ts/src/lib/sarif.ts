import { Threat } from '../types/core';

export function generateSarifOutput(threats: Threat[]): { threats: Threat[] } {
  return { threats };
}
