import { Component, ErrorInfo, ReactNode } from 'react';

interface Props {
  children: ReactNode;
}

interface State {
  hasError: boolean;
  error: Error | null;
  errorInfo: ErrorInfo | null;
}

export class ErrorBoundary extends Component<Props, State> {
  public state: State = {
    hasError: false,
    error: null,
    errorInfo: null,
  };

  public static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error, errorInfo: null };
  }

  public componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error('[UNCAUGHT_REACT_ERROR]', error, errorInfo);
    this.setState({ errorInfo });
  }

  public render() {
    if (this.state.hasError) {
      return (
        <div style={{
          padding: '32px',
          color: '#f87171',
          backgroundColor: '#0f172a',
          minHeight: '100vh',
          fontFamily: 'Segoe UI, system-ui, sans-serif'
        }}>
          <h1 style={{ fontSize: '20px', fontWeight: 'bold', marginBottom: '12px', color: '#ef4444' }}>
            Application Error
          </h1>
          <p style={{ color: '#94a3b8', marginBottom: '16px' }}>
            Smart Cleaner encountered an unexpected error while rendering the interface:
          </p>
          <pre style={{
            background: '#1e293b',
            padding: '16px',
            borderRadius: '6px',
            color: '#fca5a5',
            overflowX: 'auto',
            fontSize: '13px'
          }}>
            {this.state.error?.toString()}
            {'\n'}
            {this.state.errorInfo?.componentStack}
          </pre>
          <button
            onClick={() => window.location.reload()}
            style={{
              marginTop: '16px',
              padding: '8px 16px',
              backgroundColor: '#3b82f6',
              color: '#ffffff',
              border: 'none',
              borderRadius: '4px',
              cursor: 'pointer',
              fontWeight: 600
            }}
          >
            Reload Application
          </button>
        </div>
      );
    }

    return this.props.children;
  }
}
