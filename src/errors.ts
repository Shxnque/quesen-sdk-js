/**
 * Structured error hierarchy for the Quesen JS SDK.
 *
 * Every server-side failure maps to a specific error subclass so integrators
 * can `catch` on the concrete class rather than parsing strings.
 */

export class QuesenError extends Error {
  status?: number;
  requestId?: string;
  detail?: unknown;

  constructor(message: string, opts?: { status?: number; requestId?: string; detail?: unknown }) {
    super(message);
    this.name = "QuesenError";
    if (opts) {
      this.status = opts.status;
      this.requestId = opts.requestId;
      this.detail = opts.detail;
    }
  }
}

export class QuesenAuthError extends QuesenError {
  constructor(message: string, opts?: { status?: number; requestId?: string; detail?: unknown }) {
    super(message, opts);
    this.name = "QuesenAuthError";
  }
}

export class QuesenRateLimitError extends QuesenError {
  retryAfter?: number;
  constructor(message: string, opts?: { status?: number; requestId?: string; detail?: unknown; retryAfter?: number }) {
    super(message, opts);
    this.name = "QuesenRateLimitError";
    this.retryAfter = opts?.retryAfter;
  }
}

export class QuesenValidationError extends QuesenError {
  constructor(message: string, opts?: { status?: number; requestId?: string; detail?: unknown }) {
    super(message, opts);
    this.name = "QuesenValidationError";
  }
}

export class QuesenServerError extends QuesenError {
  constructor(message: string, opts?: { status?: number; requestId?: string; detail?: unknown }) {
    super(message, opts);
    this.name = "QuesenServerError";
  }
}

export class QuesenTimeout extends QuesenError {
  constructor(message: string) {
    super(message);
    this.name = "QuesenTimeout";
  }
}

export class QuesenTransportError extends QuesenError {
  cause?: unknown;
  constructor(message: string, cause?: unknown) {
    super(message);
    this.name = "QuesenTransportError";
    this.cause = cause;
  }
}
