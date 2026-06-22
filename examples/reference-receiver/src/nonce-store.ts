/**
 * In-memory single-use nonce store for the reference receiver.
 *
 * `verifyInkAuth` from @adastracomputing/ink fails closed when no nonce
 * store is supplied, so we wire up a small ring buffer scoped to the
 * worker isolate. Adopters running multi-isolate or multi-region should
 * swap in a KV-backed implementation; the local ring buffer is
 * adequate for a single-isolate test target where the goal is to break
 * obvious replays inside the 5-minute freshness window.
 *
 * Capacity is bounded so a flood of unique nonces cannot blow up
 * memory; oldest entries fall off when the ring rotates.
 */

export interface InMemoryNonceStoreOpts {
  capacity?: number;
}

export class InMemoryNonceStore {
  private capacity: number;
  private set: Set<string>;
  private queue: string[];

  constructor(opts: InMemoryNonceStoreOpts = {}) {
    this.capacity = Math.max(64, opts.capacity ?? 1024);
    this.set = new Set();
    this.queue = [];
  }

  has(nonce: string): boolean {
    return this.set.has(nonce);
  }

  add(nonce: string): void {
    if (this.set.has(nonce)) return;
    this.set.add(nonce);
    this.queue.push(nonce);
    while (this.queue.length > this.capacity) {
      const oldest = this.queue.shift();
      if (oldest !== undefined) this.set.delete(oldest);
    }
  }

  /**
   * Atomic check-and-record. `verifyInkAuth` prefers this over has()+add() so
   * single-use enforcement has no check-then-act race. Inside one isolate it
   * runs synchronously, so the check and the record cannot interleave. A
   * KV/DO-backed replacement MUST keep this atomic (a conditional put), and
   * MUST retain a recorded nonce for at least the 5-minute freshness window.
   */
  addIfAbsent(nonce: string): boolean {
    if (this.set.has(nonce)) return false;
    this.add(nonce);
    return true;
  }
}
