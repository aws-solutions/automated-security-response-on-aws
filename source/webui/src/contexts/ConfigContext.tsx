// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import React, { createContext, useContext, ReactNode } from 'react';

interface ConfigContextType {
  ticketingEnabled: boolean;
}

const ConfigContext = createContext<ConfigContextType | undefined>(undefined);

interface ConfigContextProviderProps {
  children: ReactNode;
  config: ConfigContextType;
}

export const ConfigContextProvider: React.FC<ConfigContextProviderProps> = ({ children, config }) => {
  return (
    <ConfigContext.Provider value={config}>
      {children}
    </ConfigContext.Provider>
  );
};

export const useConfig = (): ConfigContextType => {
  const context = useContext(ConfigContext);
  if (context === undefined) {
    throw new Error('useConfig must be used within a ConfigContextProvider');
  }
  return context;
};
