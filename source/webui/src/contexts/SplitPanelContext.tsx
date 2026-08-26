// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import React, { createContext, useCallback, useContext, useId, useMemo, useRef, useState } from 'react';

interface SplitPanelContextValue {
  splitPanelContent: React.ReactNode;
  isSplitPanelOpen: boolean;
  registerPanel: (ownerId: string, content: React.ReactNode) => void;
  unregisterPanel: (ownerId: string) => void;
  openSplitPanel: (ownerId: string) => void;
  closeSplitPanel: (ownerId: string) => void;
}

const SplitPanelContext = createContext<SplitPanelContextValue>({
  splitPanelContent: null,
  isSplitPanelOpen: false,
  registerPanel: () => {},
  unregisterPanel: () => {},
  openSplitPanel: () => {},
  closeSplitPanel: () => {},
});

export const useSplitPanel = () => {
  // Stable unique ID used as an ownership token to prevent one consumer from overwriting another's panel state
  const id = useId();
  const context = useContext(SplitPanelContext);

  const registerPanel = useCallback(
    (content: React.ReactNode) => context.registerPanel(id, content),
    [context.registerPanel, id],
  );

  const unregisterPanel = useCallback(() => context.unregisterPanel(id), [context.unregisterPanel, id]);

  const openSplitPanel = useCallback(() => context.openSplitPanel(id), [context.openSplitPanel, id]);

  const closeSplitPanel = useCallback(() => context.closeSplitPanel(id), [context.closeSplitPanel, id]);

  return {
    splitPanelContent: context.splitPanelContent,
    isSplitPanelOpen: context.isSplitPanelOpen,
    registerPanel,
    unregisterPanel,
    openSplitPanel,
    closeSplitPanel,
  };
};

export const SplitPanelProvider = ({ children }: { children: React.ReactNode }): React.ReactElement => {
  const [content, setContent] = useState<React.ReactNode>(null);
  const [isOpen, setIsOpen] = useState(false);
  const activeOwnerRef = useRef<string | null>(null);

  const registerPanel = useCallback((ownerId: string, panelContent: React.ReactNode) => {
    activeOwnerRef.current = ownerId;
    setContent(panelContent);
  }, []);

  const unregisterPanel = useCallback((ownerId: string) => {
    if (activeOwnerRef.current !== ownerId) return;
    activeOwnerRef.current = null;
    setContent(null);
    setIsOpen(false);
  }, []);

  const openSplitPanel = useCallback((ownerId: string) => {
    if (activeOwnerRef.current !== ownerId) return;
    setIsOpen(true);
  }, []);

  const closeSplitPanel = useCallback((_ownerId: string) => {
    setIsOpen(false);
  }, []);

  const contextValue = useMemo(
    () => ({
      splitPanelContent: content,
      isSplitPanelOpen: isOpen,
      registerPanel,
      unregisterPanel,
      openSplitPanel,
      closeSplitPanel,
    }),
    [content, isOpen, registerPanel, unregisterPanel, openSplitPanel, closeSplitPanel],
  );

  return <SplitPanelContext.Provider value={contextValue}>{children}</SplitPanelContext.Provider>;
};
