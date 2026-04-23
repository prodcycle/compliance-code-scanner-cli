import * as fs from 'fs';
import * as path from 'path';

export interface ScanOptions {
  severityThreshold?: 'low' | 'medium' | 'high' | 'critical';
  failOn?: ('low' | 'medium' | 'high' | 'critical')[];
  include?: string[];
  exclude?: string[];
  apiKey?: string;
  apiUrl?: string;
  config?: Record<string, unknown>;
}

export interface GateOptions {
  files: Record<string, string>;
  frameworks?: string[];
  severityThreshold?: 'low' | 'medium' | 'high' | 'critical';
  failOn?: ('low' | 'medium' | 'high' | 'critical')[];
  apiKey?: string;
  apiUrl?: string;
  config?: Record<string, unknown>;
}

export class ComplianceApiClient {
  private apiUrl: string;
  private apiKey: string;

  constructor(apiUrl?: string, apiKey?: string) {
    this.apiUrl = apiUrl || process.env.PC_API_URL || 'https://api.prodcycle.com';
    this.apiKey = apiKey || process.env.PC_API_KEY || '';

    if (!this.apiKey && process.env.NODE_ENV !== 'test') {
      console.warn('Warning: PC_API_KEY is not set. API calls will likely fail.');
    }
  }

  async validate(files: Record<string, string>, frameworks: string[], options: ScanOptions = {}) {
    return this.post('/v1/compliance/validate', {
      files,
      frameworks,
      options: {
        severity_threshold: options.severityThreshold,
        fail_on: options.failOn,
        ...options.config,
      },
    });
  }

  async hook(files: Record<string, string>, frameworks: string[], options: ScanOptions = {}) {
    return this.post('/v1/compliance/hook', {
      files,
      frameworks,
      options: {
        severity_threshold: options.severityThreshold,
        fail_on: options.failOn,
        ...options.config,
      },
    });
  }

  private async post(endpoint: string, data: any) {
    const url = `${this.apiUrl}${endpoint}`;
    
    try {
      const response = await fetch(url, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${this.apiKey}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(data),
      });

      const responseData = await response.json();
      
      if (!response.ok) {
        throw new Error(responseData.error?.message || `API request failed with status ${response.status}`);
      }

      return responseData;
    } catch (error: any) {
      throw new Error(`Failed to connect to ProdCycle API: ${error.message}`);
    }
  }
}
