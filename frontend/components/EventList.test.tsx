import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import { jest } from '@jest-globals';
import EventList from './EventList';

const baseEvent = {
  id: 'evt-1',
  tx_hash: '0xabcdef1234567890abcdef1234567890abcdef1234567890',
  tx_status: 'confirmed',
  tier: 'gold',
};

describe('EventList', () => {
  it('renders an empty state when there are no events', () => {
    render(<EventList events={[]} onRefresh={() => {}} />);
    expect(screen.getByText(/no events/i)).toBeInTheDocument();
  });

  it('renders an event with a short hash', () => {
    render(<EventList events={[baseEvent]} onRefresh={() => {}} />);
    expect(screen.getByText(/0xabcdef1234/i)).toBeInTheDocument();
  });

  it('renders the tx_status when present', () => {
    render(<EventList events={[baseEvent]} onRefresh={() => {}} />);
    expect(screen.getByText(/confirmed/i)).toBeInTheDocument();
  });

  it('falls back to tier when tx_status is missing', () => {
    render(
      <EventList
        events={[{ ...baseEvent, tx_status: undefined }]}
        onRefresh={() => {}}
      />,
    );
    expect(screen.getByText(/gold/i)).toBeInTheDocument();
  });

  it('renders "untiered" when both tx_status and tier are missing', () => {
    render(
      <EventList
        events={[{ ...baseEvent, tx_status: undefined, tier: undefined }]}
        onRefresh={() => {}}
      />,
    );
    expect(screen.getByText(/untiered/i)).toBeInTheDocument();
  });

  it('calls onRefresh when the refresh button is clicked', () => {
    const onRefresh = jest.fn();
    render(<EventList events={[]} onRefresh={onRefresh} />);
    fireEvent.click(screen.getByRole('button', { name: /refresh/i }));
    expect(onRefresh).toHaveBeenCalledTimes(1);
  });
});
