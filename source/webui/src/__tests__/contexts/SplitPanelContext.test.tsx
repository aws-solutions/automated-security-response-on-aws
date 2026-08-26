// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { useEffect, useState } from 'react';

import { SplitPanelProvider, useSplitPanel } from '../../contexts/SplitPanelContext.tsx';

const PanelDisplay = () => {
  const { splitPanelContent, isSplitPanelOpen } = useSplitPanel();
  return (
    <div>
      <div data-testid="panelContent">{splitPanelContent}</div>
      <div data-testid="panelOpenState">{isSplitPanelOpen ? 'open' : 'closed'}</div>
    </div>
  );
};

const PanelOwner = ({ ownerLabel }: { ownerLabel: string }) => {
  const { registerPanel, unregisterPanel, openSplitPanel } = useSplitPanel();

  // Mirrors the unmount cleanup that ControlsOverviewPage registers
  useEffect(() => {
    return () => {
      unregisterPanel();
    };
  }, [unregisterPanel]);

  return (
    <div>
      <button onClick={() => registerPanel(<span>{ownerLabel} panel content</span>)}>Register {ownerLabel}</button>
      <button onClick={() => openSplitPanel()}>Open panel from {ownerLabel}</button>
    </div>
  );
};

const UnmountableFirstOwner = () => {
  const [isMounted, setIsMounted] = useState(true);
  return (
    <div>
      {isMounted && <PanelOwner ownerLabel="first owner" />}
      <button onClick={() => setIsMounted(false)}>Unmount first owner</button>
    </div>
  );
};

describe('SplitPanelContext', () => {
  it('keeps the second owner active when the non-active first owner unmounts', async () => {
    // ARRANGE — two consumers, each a distinct owner via its own useId token, plus a display of the panel state
    render(
      <SplitPanelProvider>
        <PanelDisplay />
        <UnmountableFirstOwner />
        <PanelOwner ownerLabel="second owner" />
      </SplitPanelProvider>,
    );

    await userEvent.click(screen.getByRole('button', { name: 'Register first owner' }));
    await userEvent.click(screen.getByRole('button', { name: 'Register second owner' }));
    await userEvent.click(screen.getByRole('button', { name: 'Open panel from second owner' }));

    expect(screen.getByTestId('panelContent')).toHaveTextContent('second owner panel content');
    expect(screen.getByTestId('panelOpenState')).toHaveTextContent('open');

    // ACT — the non-active first owner unmounts, running its unregister cleanup
    await userEvent.click(screen.getByRole('button', { name: 'Unmount first owner' }));

    // ASSERT — the active owner's content and open state both survive the stale owner's teardown
    expect(screen.queryByRole('button', { name: 'Register first owner' })).not.toBeInTheDocument();
    expect(screen.getByTestId('panelContent')).toHaveTextContent('second owner panel content');
    expect(screen.getByTestId('panelOpenState')).toHaveTextContent('open');
  });
});
