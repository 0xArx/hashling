import { EventEmitter } from 'node:events';

/** In-process change notifications, fanned out to dashboard clients over SSE. */
export const bus = new EventEmitter();
bus.setMaxListeners(100);
