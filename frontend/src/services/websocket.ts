export type WebsocketMessage<T = unknown> = {
  type: string;
  payload: T;
};

type Handlers = {
  onConnect?: () => void;
  onDisconnect?: () => void;
  onMessage?: (msg: WebsocketMessage) => void;
};

export class SocWebsocket {
  private ws: WebSocket | null = null;
  private handlers: Handlers;

  constructor(private url: string, handlers: Handlers) {
    this.handlers = handlers;
  }

  connect() {
    this.ws = new WebSocket(this.url);

    this.ws.onopen = () => {
      this.handlers.onConnect?.();
    };

    this.ws.onclose = () => {
      this.handlers.onDisconnect?.();
    };

    this.ws.onmessage = (event) => {
      try {
        const msg = JSON.parse(event.data) as WebsocketMessage;
        this.handlers.onMessage?.(msg);
      } catch {
        // ignore invalid frames
      }
    };
  }

  close() {
    this.ws?.close();
    this.ws = null;
  }
}

export function getSocWebsocketUrl(path = '/ws/soc/') {
  const explicit = import.meta.env.VITE_WS_BASE_URL as string | undefined;
  if (explicit) return explicit.replace(/\/$/, '') + path;

  const apiBase = (import.meta.env.VITE_API_BASE_URL as string | undefined) ?? '/api/v1';
  const origin = typeof window !== 'undefined' ? window.location.origin : '';
  const baseUrl = apiBase.startsWith('http') ? new URL(apiBase) : new URL(apiBase, origin);
  baseUrl.protocol = baseUrl.protocol === 'https:' ? 'wss:' : 'ws:';
  baseUrl.pathname = path;
  baseUrl.search = '';
  return baseUrl.toString();
}

