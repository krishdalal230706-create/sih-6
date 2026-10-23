import { Router, Request, Response } from 'express';
import { vulnerabilityDb } from '../db/vulnerabilityDb.js';
import { syncService } from '../services/syncService.js';
import { VulnerabilityFilterOptions } from '../types/vulnerability.js';

export const vulnerabilityRouter = Router();

// 1. Get Vulnerabilities with Search, Filtering, Sorting, and Pagination
vulnerabilityRouter.get('/', async (req: Request, res: Response) => {
  try {
    const options: VulnerabilityFilterOptions = {
      search: req.query.search as string,
      cveId: req.query.cveId as string,
      vendor: req.query.vendor as string,
      product: req.query.product as string,
      severity: req.query.severity as string,
      minCvss: req.query.minCvss ? parseFloat(req.query.minCvss as string) : undefined,
      maxCvss: req.query.maxCvss ? parseFloat(req.query.maxCvss as string) : undefined,
      knownExploited: req.query.knownExploited !== undefined ? req.query.knownExploited === 'true' : undefined,
      source: req.query.source as string,
      cyberGuardPriority: req.query.cyberGuardPriority as string,
      sortBy: (req.query.sortBy as any) || 'cyberGuardScore',
      sortOrder: (req.query.sortOrder as any) || 'desc',
      page: req.query.page ? parseInt(req.query.page as string, 10) : 1,
      limit: req.query.limit ? parseInt(req.query.limit as string, 10) : 20
    };

    const result = await vulnerabilityDb.getVulnerabilities(options);
    res.json(result);
  } catch (err: any) {
    console.error('Error fetching vulnerabilities:', err);
    res.status(500).json({ error: 'Failed to retrieve vulnerabilities', details: err.message });
  }
});

// 2. Vulnerability Statistics & Summary Metrics
vulnerabilityRouter.get('/stats', async (req: Request, res: Response) => {
  try {
    const stats = await vulnerabilityDb.getVulnerabilityStats();
    res.json(stats);
  } catch (err: any) {
    console.error('Error fetching vulnerability stats:', err);
    res.status(500).json({ error: 'Failed to retrieve vulnerability stats', details: err.message });
  }
});

// 3. Recent Vulnerabilities
vulnerabilityRouter.get('/recent', async (req: Request, res: Response) => {
  try {
    const limit = req.query.limit ? parseInt(req.query.limit as string, 10) : 10;
    const recent = await vulnerabilityDb.getRecentVulnerabilities(limit);
    res.json({ vulnerabilities: recent });
  } catch (err: any) {
    res.status(500).json({ error: 'Failed to retrieve recent vulnerabilities' });
  }
});

// 4. Trending / Highest Risk Prioritized Vulnerabilities
vulnerabilityRouter.get('/trending', async (req: Request, res: Response) => {
  try {
    const limit = req.query.limit ? parseInt(req.query.limit as string, 10) : 10;
    const trending = await vulnerabilityDb.getTrendingVulnerabilities(limit);
    res.json({ vulnerabilities: trending });
  } catch (err: any) {
    res.status(500).json({ error: 'Failed to retrieve trending vulnerabilities' });
  }
});

// 5. CISA KEV / Known Exploited Vulnerabilities
vulnerabilityRouter.get('/exploited', async (req: Request, res: Response) => {
  try {
    const limit = req.query.limit ? parseInt(req.query.limit as string, 10) : 20;
    const exploited = await vulnerabilityDb.getExploitedVulnerabilities(limit);
    res.json({ vulnerabilities: exploited });
  } catch (err: any) {
    res.status(500).json({ error: 'Failed to retrieve exploited vulnerabilities' });
  }
});

// 6. Get Vulnerability by ID or CVE ID
vulnerabilityRouter.get('/:id', async (req: Request, res: Response) => {
  try {
    const vuln = await vulnerabilityDb.getVulnerabilityByCveId(req.params.id);
    if (!vuln) {
      return res.status(404).json({ error: 'Vulnerability not found' });
    }
    res.json(vuln);
  } catch (err: any) {
    res.status(500).json({ error: 'Failed to retrieve vulnerability details' });
  }
});
