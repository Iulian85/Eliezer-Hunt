
import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App.tsx';
import { TonConnectUIProvider } from '@tonconnect/ui-react';
import './styles.css';

// Folosim manifestul local definit în public/tonconnect-manifest.json
const manifestUrl = `${globalThis.location?.origin || (typeof globalThis.window !== 'undefined' && globalThis.window.location.origin) || ''}/tonconnect-manifest.json`;

const rootElement = typeof document !== 'undefined' ? document.getElementById('root') : null;
if (!rootElement) {
  throw new Error("Could not find root element to mount to");
}

const root = ReactDOM.createRoot(rootElement);

root.render(
  <React.StrictMode>
    <TonConnectUIProvider manifestUrl={manifestUrl}>
      <App />
    </TonConnectUIProvider>
  </React.StrictMode>
);
