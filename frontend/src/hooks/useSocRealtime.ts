import { useEffect, useState } from 'react';
import { getSocWebsocketUrl, SocWebsocket, WebsocketMessage } from '../services/websocket';

type RealtimeHandler = (message: WebsocketMessage) => void;

export function useSocRealtime(onMessage: RealtimeHandler, channels: string[] = []) {
  const [connected, setConnected] = useState(false);

  useEffect(() => {
    const query = channels.length ? `?channels=${encodeURIComponent(channels.join(','))}` : '';
    const socket = new SocWebsocket(getSocWebsocketUrl(`/ws/soc/${query}`), {
      onConnect: () => setConnected(true),
      onDisconnect: () => setConnected(false),
      onMessage
    });

    socket.connect();
    return () => socket.close();
  }, [channels.join(','), onMessage]);

  return { connected };
}
