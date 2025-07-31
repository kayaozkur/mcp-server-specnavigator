const { SpecFetcher } = require('../src/spec-fetcher');
const axios = require('axios');

// Mock axios
jest.mock('axios');
const mockedAxios = axios as jest.Mocked<typeof axios>;

describe('SpecFetcher', () => {
  let specFetcher: SpecFetcher;

  beforeEach(() => {
    specFetcher = new SpecFetcher();
    mockedAxios.get.mockClear();
    mockedAxios.head.mockClear();
  });

  describe('checkForUpdates', () => {
    it('should return update info when checking for updates', async () => {
      // Mock successful API responses
      mockedAxios.head.mockResolvedValue({
        headers: { 'last-modified': 'Thu, 01 Jan 2024 00:00:00 GMT' },
        status: 200,
      });
      mockedAxios.get.mockResolvedValue({
        data: '# MCP Specification\n\nTest content',
        status: 200,
      });

      const result = await specFetcher.checkForUpdates();
      
      expect(result).toBeDefined();
      expect(result.lastChecked).toBeInstanceOf(Date);
      expect(typeof result.hasUpdates).toBe('boolean');
    });

    it('should handle API errors gracefully', async () => {
      // Mock API error
      mockedAxios.head.mockRejectedValue(new Error('Network error'));

      const result = await specFetcher.checkForUpdates();
      
      expect(result).toBeDefined();
      expect(result.hasUpdates).toBe(false);
    });

    it('should force refresh when requested', async () => {
      mockedAxios.head.mockResolvedValue({
        headers: { 'last-modified': 'Thu, 01 Jan 2024 00:00:00 GMT' },
        status: 200,
      });
      mockedAxios.get.mockResolvedValue({
        data: '# MCP Specification\n\nTest content',
        status: 200,
      });

      await specFetcher.checkForUpdates(true);
      
      expect(mockedAxios.head).toHaveBeenCalled();
    });
  });

  describe('getSpec', () => {
    it('should return cached spec when available', async () => {
      // First call to populate cache
      mockedAxios.get.mockResolvedValue({
        data: '# MCP Specification\n\nTest content',
        status: 200,
      });

      await specFetcher.checkForUpdates();
      const spec = await specFetcher.getSpec();
      
      expect(spec).toContain('# MCP Specification');
    });

    it('should fetch spec when cache is empty', async () => {
      mockedAxios.get.mockResolvedValue({
        data: '# MCP Specification\n\nFresh content',
        status: 200,
      });

      const spec = await specFetcher.getSpec();
      
      expect(spec).toContain('# MCP Specification');
      expect(mockedAxios.get).toHaveBeenCalled();
    });
  });
});