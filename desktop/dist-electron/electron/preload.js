"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const electron_1 = require("electron");
electron_1.contextBridge.exposeInMainWorld('smartCleanerIpc', {
    send: (request) => {
        return electron_1.ipcRenderer.invoke('smart-cleaner:ipc', request);
    },
    onEvent: (callback) => {
        const listener = (_event, data) => {
            callback(data);
        };
        electron_1.ipcRenderer.on('smart-cleaner:event', listener);
        return () => {
            electron_1.ipcRenderer.removeListener('smart-cleaner:event', listener);
        };
    },
    isConnected: () => {
        return true;
    },
});
