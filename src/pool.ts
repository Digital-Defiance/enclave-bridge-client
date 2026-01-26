/**
 * Connection pool for EnclaveBridge Client
 * 
 * Manages multiple socket connections for parallel operations.
 * This is useful for high-throughput scenarios but generally not needed
 * for typical use cases since Unix sockets are fast locally.
 */

import { EnclaveBridgeClient } from './index.js';
import type { EnclaveBridgeClientOptions } from './types.js';
import { InvalidOperationError } from './errors.js';

export interface ConnectionPoolOptions extends EnclaveBridgeClientOptions {
  /**
   * Number of connections in the pool
   * @default 3
   */
  poolSize?: number;

  /**
   * Maximum time to wait for an available connection in milliseconds
   * @default 5000
   */
  acquireTimeout?: number;
}

/**
 * Connection pool for managing multiple EnclaveBridge clients
 */
export class ConnectionPool {
  private pool: EnclaveBridgeClient[] = [];
  private available: EnclaveBridgeClient[] = [];
  private waiting: Array<{
    resolve: (client: EnclaveBridgeClient) => void;
    reject: (error: Error) => void;
    timer: NodeJS.Timeout;
  }> = [];
  private poolSize: number;
  private acquireTimeout: number;
  private options: EnclaveBridgeClientOptions;
  private isInitialized = false;

  constructor(options: ConnectionPoolOptions = {}) {
    this.poolSize = options.poolSize ?? 3;
    this.acquireTimeout = options.acquireTimeout ?? 5000;
    this.options = options;
  }

  /**
   * Initialize the connection pool
   */
  async initialize(): Promise<void> {
    if (this.isInitialized) {
      return;
    }

    const promises: Promise<void>[] = [];
    
    for (let i = 0; i < this.poolSize; i++) {
      const client = new EnclaveBridgeClient(this.options);
      promises.push(client.connect());
      this.pool.push(client);
      this.available.push(client);
    }

    await Promise.all(promises);
    this.isInitialized = true;
  }

  /**
   * Acquire a connection from the pool
   * 
   * @returns Promise resolving to an available client
   */
  async acquire(): Promise<EnclaveBridgeClient> {
    if (!this.isInitialized) {
      throw new InvalidOperationError('Connection pool not initialized');
    }

    if (this.available.length > 0) {
      const client = this.available.shift()!;
      return client;
    }

    // Wait for a connection to become available
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        const index = this.waiting.findIndex((w) => w.resolve === resolve);
        if (index !== -1) {
          this.waiting.splice(index, 1);
        }
        reject(new InvalidOperationError(`Acquire timeout after ${this.acquireTimeout}ms`));
      }, this.acquireTimeout);

      this.waiting.push({ resolve, reject, timer });
    });
  }

  /**
   * Release a connection back to the pool
   * 
   * @param client - Client to release
   */
  release(client: EnclaveBridgeClient): void {
    if (!this.pool.includes(client)) {
      throw new InvalidOperationError('Client does not belong to this pool');
    }

    if (this.waiting.length > 0) {
      const waiter = this.waiting.shift()!;
      clearTimeout(waiter.timer);
      waiter.resolve(client);
    } else {
      this.available.push(client);
    }
  }

  /**
   * Execute a function with an acquired connection
   * 
   * @param fn - Function to execute with the connection
   * @returns Promise resolving to the function result
   */
  async execute<T>(fn: (client: EnclaveBridgeClient) => Promise<T>): Promise<T> {
    const client = await this.acquire();
    try {
      return await fn(client);
    } finally {
      this.release(client);
    }
  }

  /**
   * Get pool statistics
   */
  getStats(): {
    poolSize: number;
    available: number;
    inUse: number;
    waiting: number;
  } {
    return {
      poolSize: this.poolSize,
      available: this.available.length,
      inUse: this.poolSize - this.available.length,
      waiting: this.waiting.length,
    };
  }

  /**
   * Drain and close all connections in the pool
   */
  async close(): Promise<void> {
    // Reject all waiting requests
    for (const waiter of this.waiting) {
      clearTimeout(waiter.timer);
      waiter.reject(new InvalidOperationError('Pool is closing'));
    }
    this.waiting = [];

    // Close all connections
    const promises: Promise<void>[] = [];
    for (const client of this.pool) {
      promises.push(client.disconnect());
    }

    await Promise.all(promises);
    
    this.pool = [];
    this.available = [];
    this.isInitialized = false;
  }
}
