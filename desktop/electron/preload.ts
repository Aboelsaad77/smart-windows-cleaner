import { contextBridge, ipcRenderer } from 'electron';
import { IpcRequest, IpcResponse, IpcEvent } from '../src/types/ipc';

contextBridge.exposeInMainWorld('smartCleanerIpc', {
  send: (request: IpcRequest): Promise<IpcResponse> => {
    return ipcRenderer.invoke('smart-cleaner:ipc', request);
  },
  onEvent: (callback: (event: IpcEvent) => void): (() => void) => {
    const listener = (_event: Electron.IpcRendererEvent, data: IpcEvent) => {
      callback(data);
    };
    ipcRenderer.on('smart-cleaner:event', listener);
    return () => {
      ipcRenderer.removeListener('smart-cleaner:event', listener);
    };
  },
  isConnected: (): boolean => {
    return true;
  },
});
