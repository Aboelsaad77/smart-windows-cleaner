import React from 'react';
import { AppProvider, NavigationRoute } from './state/AppContext';
import { Shell } from './components/Shell';
import { IpcClient } from './ipc/client';

export interface AppProps {
  client?: IpcClient;
  initialRoute?: NavigationRoute;
}

export const App: React.FC<AppProps> = ({ client, initialRoute = 'dashboard' }) => {
  return (
    <AppProvider client={client} initialRoute={initialRoute}>
      <Shell />
    </AppProvider>
  );
};

export default App;
