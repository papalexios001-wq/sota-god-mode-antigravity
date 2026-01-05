# URL Batch Optimizer - Integration Guide

## SOTA Enterprise-Grade Implementation

This guide documents the comprehensive implementation of the URL Batch Optimizer feature in the SOTA God Mode application, including all frontend and backend components.

## Overview

The URL Batch Optimizer is a SOTA-grade enhancement to the Gap Analysis (God Mode) menu that allows users to:
- Add single or multiple URLs for analysis
- Perform gap analysis, competitive analysis, SEO audits, and content opportunity analysis
- Queue and process URLs with priority-based handling
- View detailed analysis results with recommendations
- Export analysis reports

## Components Implemented

### 1. Frontend Component: URLBatchOptimizer (`src/url-batch-optimizer.tsx`)

**Features:**
- Dual-mode URL input (single URL or bulk upload)
- CSV/text file upload support
- Priority-based URL processing queue
- Real-time status tracking
- Existing URLs management with remove functionality
- Enterprise-grade styling with dark theme
- Responsive grid layout
- Accessibility features (ARIA labels, semantic HTML)

**Key Functions:**
- `handleAddSingleURL()` - Process single URL input
- `handleAddBulkURLs()` - Process bulk URL uploads
- `handleRemoveURL()` - Remove URL from queue
- `handleAnalyze()` - Trigger analysis via API

**State Management:**
```typescript
const [inputMode, setInputMode] = useState<'single' | 'bulk'>('single');
const [singleUrl, setSingleUrl] = useState('');
const [bulkUrls, setBulkUrls] = useState('');
const [analysisType, setAnalysisType] = useState<'gap' | 'competitive' | 'seo-audit' | 'content-opportunity'>('gap');
const [depth, setDepth] = useState<'light' | 'medium' | 'deep'>('medium');
const [existingURLs, setExistingURLs] = useState<URLQueueItem[]>([]);
const [loading, setLoading] = useState(false);
```

### 2. Backend API: Analyze URLs (`pages/api/analyze-urls.ts`)

**Endpoint:** `POST /api/analyze-urls`

**Request Payload:**
```typescript
interface URLAnalysisRequest {
  urls: string[];
  analysisType: 'gap' | 'competitive' | 'seo-audit' | 'content-opportunity';
  focusKeywords?: string[];
  depth?: 'light' | 'medium' | 'deep';
}
```

**Response Structure:**
```typescript
{
  timestamp: string;
  analysisType: string;
  totalUrls: number;
  successCount: number;
  failureCount: number;
  results: URLAnalysisResult[];
  summary: {
    averageScore: string;
    topGaps: { gap: string; frequency: number }[];
    topOpportunities: { opportunity: string; frequency: number }[];
  }
}
```

**Features:**
- Validates up to 25 URLs per request
- Parallel processing using `Promise.all()`
- AI-powered analysis via `callAI()` integration
- Comprehensive gap and opportunity extraction
- Error handling with detailed messages
- 60-second timeout configuration for long-running analyses

### 3. App Integration (`src/App.tsx`)

**Import:**
```typescript
import { URLBatchOptimizer } from './url-batch-optimizer';
```

## Integration Steps

### Step 1: Integrate Component into Gap Analysis View

In your main App component, find the Gap Analysis menu/view section and add:

```typescript
{activeView === 'gap-analysis' && (
  <div className="gap-analysis-container">
    <URLBatchOptimizer
      onAnalysisComplete={(results) => {
        // Handle analysis results
        console.log('Analysis complete:', results);
      }}
      onError={(error) => {
        // Handle errors
        console.error('Analysis error:', error);
      }}
    />
  </div>
)}
```

### Step 2: Wire Frontend to Backend

In the URLBatchOptimizer component, the `handleAnalyze()` function calls:

```typescript
const handleAnalyze = async () => {
  setLoading(true);
  try {
    const response = await fetch('/api/analyze-urls', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        urls: existingURLs.map(u => u.url),
        analysisType,
        depth,
      }),
    });
    
    if (!response.ok) throw new Error('Analysis failed');
    const results = await response.json();
    
    // Handle results
    onAnalysisComplete?.(results);
  } catch (error) {
    onError?.(error as Error);
  } finally {
    setLoading(false);
  }
};
```

### Step 3: Add to Navigation

If needed, add to your sidebar navigation:

```typescript
const navItems = [
  { id: 'setup', name: 'Configuration', icon: <SetupIcon /> },
  { id: 'strategy', name: 'Content Strategy', icon: <StrategyIcon /> },
  { id: 'gap-analysis', name: 'Gap Analysis (God Mode)', icon: <GapAnalysisIcon /> },
  { id: 'review', name: 'Review & Export', icon: <ReviewIcon /> }
];
```

## API Integration Details

### Calling the Analysis Endpoint

```typescript
const analyzeURLs = async (urls: string[], analysisType: string, depth: string) => {
  const response = await fetch('/api/analyze-urls', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ urls, analysisType, depth }),
  });
  return response.json();
};
```

### Error Handling

The API returns:
- 200: Successful analysis
- 400: Invalid request (missing/invalid URLs)
- 405: Wrong HTTP method
- 500: Server error

## Styling & Theming

The component uses CSS variables for enterprise-grade theming:

```css
--accent-primary: Primary color for buttons/highlights
--accent-success: Success state color
--border-subtle: Border color
--text-primary: Primary text color
--text-secondary: Secondary text color
--bg-primary: Primary background
--bg-secondary: Secondary background
```

## Performance Considerations

1. **URL Limit**: Maximum 25 URLs per request to avoid timeouts
2. **Concurrent Processing**: Uses `Promise.all()` for parallel analysis
3. **API Timeout**: 60 seconds maximum execution time
4. **State Management**: Uses React hooks for efficient re-renders
5. **Loading States**: Visual feedback during processing

## Database/Storage Integration (Future)

When adding persistent storage:

```typescript
// Store analysis results
const saveAnalysisResults = async (results: URLAnalysisResult[]) => {
  await db.insert('analyses', {
    timestamp: new Date(),
    results,
    userId: currentUser.id,
  });
};

// Retrieve historical analyses
const getAnalysisHistory = async (userId: string) => {
  return await db.query('analyses', { userId });
};
```

## Testing

### Unit Tests

```typescript
describe('URLBatchOptimizer', () => {
  it('should add single URL', async () => {
    // Test implementation
  });
  
  it('should process bulk URLs from CSV', async () => {
    // Test implementation
  });
  
  it('should call API with correct payload', async () => {
    // Test implementation
  });
});
```

### API Tests

```typescript
describe('POST /api/analyze-urls', () => {
  it('should validate URL count', async () => {
    // Test implementation
  });
  
  it('should return analysis results', async () => {
    // Test implementation
  });
});
```

## Deployment Checklist

- [ ] URLBatchOptimizer component imported in App.tsx
- [ ] Component integrated into Gap Analysis view
- [ ] API route configured in pages/api/
- [ ] Environment variables set for AI service
- [ ] Error handling tested
- [ ] Performance tested with max URL load
- [ ] Styling verified across browsers
- [ ] Accessibility audit completed
- [ ] Documentation updated
- [ ] Team trained on new feature

## Support & Maintenance

For issues or enhancements:
1. Check this integration guide
2. Review component props and API response structure
3. Test with smaller URL batches first
4. Enable debug logging for troubleshooting

---

**Implementation Status**: ✅ SOTA Enterprise-Grade
**Last Updated**: 2025
**Version**: 1.0.0
