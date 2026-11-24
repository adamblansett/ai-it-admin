import { render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import App from '../App';

describe('AI IT Administrator starter workspace', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('renders planned capabilities and live API health status', async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        status: 'ok',
        service: 'ai-it-admin',
        app_name: 'AI IT Administrator',
        version: '0.1.0',
        environment: 'test',
        llm_provider: 'mock',
      }),
    });
    vi.stubGlobal('fetch', mockFetch);

    render(<App />);

    expect(screen.getByRole('heading', { name: 'AI IT Administrator' })).toBeInTheDocument();
    await waitFor(() => {
      expect(screen.getByText(/API Healthy \(mock\)/i)).toBeInTheDocument();
    });
    expect(mockFetch).toHaveBeenCalledWith('/api/v1/health');
  });
});
