// Chrome Extension API types
declare namespace chrome {
  namespace storage {
    interface StorageArea {
      get(keys: string[], callback: (items: any) => void): void;
      set(items: any, callback?: () => void): void;
      remove(keys: string[], callback?: () => void): void;
    }
    const local: StorageArea;
  }
  
  namespace runtime {
    function sendMessage(message: any, callback?: (response: any) => void): void;
  }
}
