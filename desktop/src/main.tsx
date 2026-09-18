import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App';
import { ErrorBoundary } from './components/ErrorBoundary';
import './index.css';

window.addEventListener('error', (event) => {
  console.error('[GLOBAL_WINDOW_ERROR]', event.message, event.filename, event.lineno, event.error);
});

window.addEventListener('unhandledrejection', (event) => {
  console.error('[UNHANDLED_PROMISE_REJECTION]', event.reason);
});

const rootElement = document.getElementById('root');
if (rootElement) {
  ReactDOM.createRoot(rootElement).render(
    <React.StrictMode>
      <ErrorBoundary>
        <App />
      </ErrorBoundary>
    </React.StrictMode>
  );
}
