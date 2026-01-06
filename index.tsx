
import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App';
import ErrorBoundary from './ErrorBoundary';
import './src/index.css';
import { TonConnectUIProvider } from '@tonconnect/ui-react';

// Folosim manifestul local definit în public/tonconnect-manifest.json
const manifestUrl = 'https://eliezer-hunt-production.up.railway.app/tonconnect-manifest.json';

const rootElement = document.getElementById('root');
if (!rootElement) {
  throw new Error("Could not find root element to mount to");
}

// Verificare suplimentară pentru elementul root
if (rootElement.tagName !== 'DIV' || rootElement.id !== 'root') {
  throw new Error("Invalid root element");
}

const root = ReactDOM.createRoot(rootElement);

root.render(
  <React.StrictMode>
    <ErrorBoundary>
      <TonConnectUIProvider manifestUrl={manifestUrl}>
        <App />
      </TonConnectUIProvider>
    </ErrorBoundary>
  </React.StrictMode>
);
