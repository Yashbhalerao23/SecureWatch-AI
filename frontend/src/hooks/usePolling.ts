import { useEffect } from 'react';

export default function usePolling(callback: () => void, interval = 30000) {
  useEffect(() => {
    callback();
    const timer = window.setInterval(callback, interval);
    return () => window.clearInterval(timer);
  }, [callback, interval]);
}
