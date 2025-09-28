import { Threat } from '../types/core';

export function generateSarifOutput(threats: Threat[]): any {
  return { threats };
}