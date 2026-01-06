
import { SitemapPage } from "./types";
import { MIN_INTERNAL_LINKS } from "./constants";
import { GeneratedContent } from './types';
import { WpConfig, SiteInfo, ExpandedGeoTargeting } from './types';
import { generateFullSchema, generateSchemaMarkup } from './schema-generator';
import { fetchWithProxies } from './contentUtils';

// --- START: Performance & Caching Enhancements ---

/**
 * SERVER GUARD: INTELLIGENT RESOURCE GOVERNOR v1.0
 * Prevents VPS exhaustion by enforcing cool-downs and adapting to latency.
 */
class ServerGuard {
    private lastRequestTime: number = 0;
    private baseDelay: number = 2000; // Minimum 2 seconds between WP hits
    private currentDelay: number = 2000;

    async wait() {
        const now = Date.now();
        const timeSinceLast = now - this.lastRequestTime;

        if (timeSinceLast < this.currentDelay) {
            const waitTime = this.currentDelay - timeSinceLast;
            console.log(`[ServerGuard] Cooling down for ${waitTime}ms...`);
            await new Promise(resolve => setTimeout(resolve, waitTime));
        }
        this.lastRequestTime = Date.now();
    }

    reportMetrics(durationMs: number) {
        // If server is slow (>3s response), throttle down
        if (durationMs > 3000) {
            this.currentDelay = Math.min(this.currentDelay * 1.5, 10000); // Cap at 10s
            console.warn(`[ServerGuard] High Latency detected (${durationMs}ms). Increasing cooldown to ${this.currentDelay}ms.`);
        } else {
            // Gradually recover speed
            this.currentDelay = Math.max(this.baseDelay, this.currentDelay * 0.9);
        }
    }
}
export const serverGuard = new ServerGuard();

/**
 * A sophisticated caching layer for API responses to reduce redundant calls
 * and improve performance within a session.
 */
class ContentCache {
    private cache = new Map<string, { data: any, timestamp: number }>();
    private TTL = 3600000; // 1 hour

    set(key: string, data: any) {
        this.cache.set(key, { data, timestamp: Date.now() });
    }

    get(key: string): any | null {
        const item = this.cache.get(key);
        if (item && Date.now() - item.timestamp < this.TTL) {
            console.log(`[Cache] HIT for key: ${key.substring(0, 30)}...`);
            return item.data;
        }
        return null;
    }
}
export const apiCache = new ContentCache();

// SOTA PERFORMANCE ENGINE v5.0
// 1. PERSISTENT CACHE (survives session)
class PersistentCache {
    private storage = localStorage;

    set(key: string, data: any, ttl: number = 86400000) { // 24h default
        const item = {
            data,
            expiry: Date.now() + ttl
        };
        try {
            this.storage.setItem(`wcop_${key}`, JSON.stringify(item));
        } catch (e) {
            console.error("Failed to write to persistent cache (localStorage full?):", e);
        }
    }

    get(key: string): any | null {
        const item = this.storage.getItem(`wcop_${key}`);
        if (!item) return null;

        try {
            const parsed = JSON.parse(item);
            if (Date.now() > parsed.expiry) {
                this.storage.removeItem(`wcop_${key}`);
                return null;
            }
            return parsed.data;
        } catch {
            return null;
        }
    }

    has(key: string): boolean {
        return this.get(key) !== null;
    }
}

export const persistentCache = new PersistentCache();

// 3. LAZY SCHEMA GENERATION (generate only when needed)
export const lazySchemaGeneration = (content: GeneratedContent, wpConfig: WpConfig, siteInfo: SiteInfo, geoTargeting: ExpandedGeoTargeting) => {
    let schemaCache: string | null = null;

    return () => {
        if (!schemaCache) {
            schemaCache = generateSchemaMarkup(
                generateFullSchema(content, wpConfig, siteInfo, content.faqSection, geoTargeting.enabled ? geoTargeting : undefined)
            );
        }
        return schemaCache;
    };
};

// 4. CONNECTION POOLING
class AIClientPool {
    private clients: Map<string, any> = new Map();

    get(clientType: string, apiKey: string) {
        const key = `${clientType}_${apiKey.slice(-8)}`;
        return this.clients.get(key);
    }

    set(clientType: string, apiKey: string, client: any) {
        const key = `${clientType}_${apiKey.slice(-8)}`;
        this.clients.set(key, client);
    }
}

export const clientPool = new AIClientPool();

// --- START: Core Utility Functions ---

// Debounce function to limit how often a function gets called
export const debounce = (func: (...args: any[]) => void, delay: number) => {
    let timeoutId: ReturnType<typeof setTimeout>;
    return (...args: any[]) => {
        clearTimeout(timeoutId);
        timeoutId = setTimeout(() => {
            func.apply(null, args);
        }, delay);
    };
};


/**
 * A highly resilient function to extract a JSON object from a string.
 */
export const extractJson = (text: string): string => {
    if (!text || typeof text !== 'string') {
        throw new Error("Input text is invalid or empty.");
    }

    try {
        JSON.parse(text);
        return text;
    } catch (e: any) { }

    let cleanedText = text
        .replace(/^```(?:json)?\s*/, '')
        .replace(/\s*```$/, '')
        .trim();

    cleanedText = cleanedText.replace(/```json\s*/gi, '').replace(/```\s*/g, '');
    cleanedText = cleanedText.replace(/,(\s*[}\]])/g, '$1');

    const firstBracket = cleanedText.indexOf('{');
    const firstSquare = cleanedText.indexOf('[');

    if (firstBracket === -1 && firstSquare === -1) {
        throw new Error("No JSON object/array found. Ensure your prompt requests JSON output only without markdown.");
    }

    let startIndex = -1;
    if (firstBracket === -1) startIndex = firstSquare;
    else if (firstSquare === -1) startIndex = firstBracket;
    else startIndex = Math.min(firstBracket, firstSquare);

    let potentialJson = cleanedText.substring(startIndex);

    const startChar = potentialJson[0];
    const endChar = startChar === '{' ? '}' : ']';

    let balance = 1;
    let inString = false;
    let escapeNext = false;
    let endIndex = -1;

    for (let i = 1; i < potentialJson.length; i++) {
        const char = potentialJson[i];
        if (escapeNext) { escapeNext = false; continue; }
        if (char === '\\') { escapeNext = true; continue; }
        if (char === '"' && !escapeNext) { inString = !inString; }
        if (inString) continue;
        if (char === startChar) balance++;
        else if (char === endChar) balance--;
        if (balance === 0) { endIndex = i; break; }
    }

    let jsonCandidate;
    if (endIndex !== -1) {
        jsonCandidate = potentialJson.substring(0, endIndex + 1);
    } else {
        jsonCandidate = potentialJson;
        if (balance > 0) {
            jsonCandidate += endChar.repeat(balance);
        }
    }

    try {
        JSON.parse(jsonCandidate);
        return jsonCandidate;
    } catch (e) {
        try {
            const repaired = jsonCandidate.replace(/,(?=\s*[}\]])/g, '');
            JSON.parse(repaired);
            return repaired;
        } catch (repairError: any) {
            throw new Error(`Unable to parse JSON.`);
        }
    }
};

/**
 * SOTA Self-Healing JSON Parser.
 */
export async function parseJsonWithAiRepair(
    text: string,
    aiRepairer: (brokenText: string) => Promise<string>
): Promise<any> {
    try {
        const jsonString = extractJson(text);
        return JSON.parse(jsonString);
    } catch (initialError: any) {
        console.warn(`[JSON Repair] Initial parsing failed. Attempting AI repair.`);
        try {
            const repairedResponseText = await aiRepairer(text);
            const repairedJsonString = extractJson(repairedResponseText);
            return JSON.parse(repairedJsonString);
        } catch (repairError: any) {
            throw new Error(`Failed to parse JSON even after AI repair: ${repairError.message}`);
        }
    }
}


/**
 * Strips markdown code fences and conversational text.
 * NOW WITH SOTA "EXPLANATION KILLER" LOGIC.
 */
export const sanitizeHtmlResponse = (rawHtml: string): string => {
    if (!rawHtml || typeof rawHtml !== 'string') {
        return '';
    }
    let cleanedHtml = rawHtml
        .replace(/^```(?:html)?\s*/i, '') // Remove start markdown fence
        .replace(/```\s*$/g, '')          // Remove end markdown fence
        .trim();

    // 1. Remove text before the first tag if it looks like conversational filler
    const firstTagIndex = cleanedHtml.indexOf('<');
    if (firstTagIndex > 0) {
        const pretext = cleanedHtml.substring(0, firstTagIndex).trim();
        if (pretext.length > 0 && pretext.length < 150) {
            cleanedHtml = cleanedHtml.substring(firstTagIndex);
        }
    }

    // 2. Remove "Explanation of Changes" that AI appends at the end
    // Logic: Look for "## Explanation" or similar headers and cut everything after
    const explanationRegex = /(\n\s*##\s*(?:Explanation|Summary|Changes|Notes)|^\s*##\s*(?:Explanation|Summary|Changes|Notes))/im;
    const explanationMatch = cleanedHtml.match(explanationRegex);
    if (explanationMatch && explanationMatch.index !== undefined) {
        cleanedHtml = cleanedHtml.substring(0, explanationMatch.index).trim();
    }

    // 3. Fallback: If "```" remains at the end, kill it
    cleanedHtml = cleanedHtml.replace(/```\s*$/, '');

    return cleanedHtml;
};


/**
 * Extracts the final, clean slug from a URL.
 */
export const extractSlugFromUrl = (urlString: string): string => {
    try {
        let cleanUrl = urlString.trim();
        if (!cleanUrl.startsWith('http')) {
            cleanUrl = 'https://' + cleanUrl;
        }

        const url = new URL(cleanUrl);
        let pathname = url.pathname;

        if (pathname.endsWith('/') && pathname.length > 1) {
            pathname = pathname.slice(0, -1);
        }

        const lastSegment = pathname.substring(pathname.lastIndexOf('/') + 1);
        const cleanedSlug = decodeURIComponent(lastSegment)
            .replace(/\.[a-zA-Z0-9]{2,5}$/, '')
            .split('?')[0]
            .split('#')[0];

        return cleanedSlug
            .toLowerCase()
            .replace(/[^a-z0-9/_\-]/g, '-')
            .replace(/-+/g, '-')
            .replace(/^-|-$/g, '');

    } catch (error: any) {
        const fallback = urlString.split(/[?#]/)[0].split('/').pop() || '';
        return decodeURIComponent(fallback)
            .toLowerCase()
            .replace(/[^a-z0-9/_\-]/g, '-')
            .replace(/-+/g, '-')
            .replace(/^-|-$/g, '');
    }
};

/**
 * SOTA URL RESOLVER: Follows redirects to find the true final URL.
 */
export const resolveFinalUrl = async (url: string): Promise<string> => {
    try {
        const response = await fetchWithProxies(url, { method: 'HEAD' });
        return response.url || url;
    } catch (e) {
        try {
            const response = await fetchWithProxies(url, { method: 'GET' });
            return response.url || url;
        } catch (e2) {
            return url;
        }
    }
};

/**
 * SOTA LINK VALIDATOR & FIXER
 */
export const validateAndFixUrl = async (
    originalUrl: string,
    contextQuery: string,
    serperApiKey: string
): Promise<{ valid: boolean, url: string | null, fixed: boolean }> => {

    let isValid = false;
    try {
        const checkRes = await fetchWithProxies(originalUrl, { method: 'HEAD' });
        if (checkRes.ok) {
            isValid = true;
        } else if (checkRes.status === 405 || checkRes.status === 403) {
            const getRes = await fetchWithProxies(originalUrl, { method: 'GET' });
            if (getRes.ok) isValid = true;
        }
    } catch (e) {
        isValid = false;
    }

    if (isValid) {
        return { valid: true, url: originalUrl, fixed: false };
    }

    if (serperApiKey) {
        console.log(`[Link Validator] Fixing link for context: ${contextQuery}`);
        try {
            const query = `${contextQuery} official site`;
            const response = await fetchWithProxies("https://google.serper.dev/search", {
                method: 'POST',
                headers: { 'X-API-KEY': serperApiKey, 'Content-Type': 'application/json' },
                body: JSON.stringify({ q: query, num: 1 })
            });
            const data = await response.json();
            if (data.organic && data.organic.length > 0) {
                const newUrl = data.organic[0].link;
                return { valid: true, url: newUrl, fixed: true };
            }
        } catch (e) {
            console.error("[Link Validator] Serper fallback failed.", e);
        }
    }

    return { valid: false, url: null, fixed: false };
};


/**
 * A more professional and resilient fetch function for AI APIs.
 */
export const callAiWithRetry = async (apiCall: () => Promise<any>, maxRetries = 5, initialDelay = 5000) => {
    for (let attempt = 0; attempt < maxRetries; attempt++) {
        try {
            return await apiCall();
        } catch (error: any) {
            const errorMessage = (error?.message || '').toLowerCase();
            const isNonRetriable = errorMessage.includes('api key') || errorMessage.includes('context length');
            if (isNonRetriable) throw error;

            if (attempt === maxRetries - 1) throw error;

            const backoff = Math.pow(2, attempt) * 1000 + initialDelay;
            await new Promise(resolve => setTimeout(resolve, backoff));
        }
    }
    throw new Error("AI call failed after all retries.");
};

/**
 * Smartly fetches a WordPress API endpoint.
 * INTEGRATES SERVER GUARD TO PREVENT CPU SPIKES.
 */
export const fetchWordPressWithRetry = async (targetUrl: string, options: RequestInit): Promise<Response> => {
    const REQUEST_TIMEOUT = 45000;

    // ENTERPRISE FIX: Defensively check for Authorization header across all header types
    let hasAuthHeader = false;
    if (options.headers) {
        if (typeof options.headers === 'object' && options.headers !== null) {
            // Check if .has() method exists (Headers instance)
            if (typeof (options.headers as any).has === 'function') {
                hasAuthHeader = (options.headers as Headers).has('Authorization');
            } else if (Array.isArray(options.headers)) {
                // Array format: [['Authorization', 'value']]
                hasAuthHeader = options.headers.some((pair: any) => pair[0].toLowerCase() === 'authorization');
            } else {
                // Plain object format: { Authorization: 'value' }
                const headers = options.headers as Record<string, string>;
                hasAuthHeader = Object.keys(headers).some(k => k.toLowerCase() === 'authorization');
            }
        }
    }

    // SERVER GUARD: Enforce cooldown before sending any WP request
    await serverGuard.wait();
    const startTime = Date.now();

    const executeFetch = async (url: string, opts: RequestInit) => {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), REQUEST_TIMEOUT);
        try {
            const res = await fetch(url, { ...opts, signal: controller.signal });
            clearTimeout(timeoutId);
            return res;
        } catch (e) {
            clearTimeout(timeoutId);
            throw e;
        }
    };

    try {
        let response: Response;
        if (hasAuthHeader) {
            // Auth requests must go direct
            response = await executeFetch(targetUrl, options);
        } else {
            // Non-auth can try direct then proxy
            try {
                response = await executeFetch(targetUrl, options);
                if (!response.ok && response.status >= 500) throw new Error("Direct 5xx");
            } catch (e) {
                const encodedUrl = encodeURIComponent(targetUrl);
                const proxyUrl = `https://corsproxy.io/?${encodedUrl}`;
                console.log(`[WP Fetch] Direct failed, using proxy: ${proxyUrl}`);
                response = await executeFetch(proxyUrl, options);
            }
        }

        // Report metrics to ServerGuard
        const duration = Date.now() - startTime;
        serverGuard.reportMetrics(duration);

        return response;
    } catch (error: any) {
        // Report failure as high latency to trigger cooldown
        serverGuard.reportMetrics(5000);
        throw error;
    }
};


export async function processConcurrently<T>(
    items: T[],
    processor: (item: T) => Promise<void>,
    concurrency = 1, // Default to 1 for safety on VPS
    onProgress?: (completed: number, total: number) => void,
    shouldStop?: () => boolean
): Promise<void> {
    const queue = [...items];
    let completed = 0;
    const total = items.length;

    const run = async () => {
        while (queue.length > 0) {
            if (shouldStop?.()) {
                queue.length = 0;
                break;
            }
            const item = queue.shift();
            if (item) {
                await processor(item);
                completed++;
                onProgress?.(completed, total);

                // SOTA SAFETY: Force a small sleep between queue items to yield CPU
                await new Promise(r => setTimeout(r, 1000));
            }
        }
    };

    const workers = Array(concurrency).fill(null).map(run);
    await Promise.all(workers);
};

export const sanitizeTitle = (title: string, slug: string): string => {
    try {
        new URL(title);
        const decodedSlug = decodeURIComponent(slug);
        return decodedSlug.replace(/-/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
    } catch (e) {
        return title;
    }
};

export const isNullish = (value: any): value is null | undefined => {
    return value === null || value === undefined;
};

export const isValidSortKey = (key: string, obj: any): boolean => {
    if (!key || !obj || typeof obj !== 'object') return false;
    return key in obj;
};

export const safeAccess = <T, K extends keyof T>(
    obj: T,
    key: K,
    fallback: T[K]
): T[K] => {
    return obj?.[key] ?? fallback;
};

export function parseValidatedJson<T>(text: string, schema: (data: any) => data is T): T {
    try {
        const parsed = JSON.parse(text);
        if (!schema(parsed)) {
            throw new Error('Schema validation failed');
        }
        return parsed;
    } catch (error: any) {
        console.error('JSON parse+validation failed:', error);
        throw error;
    }
};
