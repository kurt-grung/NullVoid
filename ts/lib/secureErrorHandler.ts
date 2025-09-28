import { Threat } from '../types/core';

export class ErrorHandler {
  handle(_error: Error): Threat[] {
    return [];
  }
}