// Fingerprints stay in extension session memory; only provenance goes to the Agent.
const MatchStore = (() => {
    const TTL = 30 * 60 * 1000;
    const MAX = 100;
    const isDigest = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
    let serial = Promise.resolve();
    function locked(fn) {
        const result = serial.then(fn);
        serial = result.catch(() => {});
        return result;
    }
    async function state() {
        const saved = (await chrome.storage.session.get('matching')).matching || {};
        saved.seed ||= crypto.randomUUID();
        saved.sources = (saved.sources || []).filter(x => Date.now() - x.observed < TTL);
        saved.downloads = (saved.downloads || []).filter(x => Date.now() - x.observed < TTL);
        return saved;
    }
    async function persist(saved) {
        saved.sources = saved.sources.slice(-MAX);
        saved.downloads = saved.downloads.slice(-MAX);
        await chrome.storage.session.set({matching: saved});
    }
    const seed = () => locked(async () => {
        const saved = await state(); await persist(saved); return saved.seed;
    });
    const remember = source => locked(async () => {
        if (!isDigest(source.digest)) return;
        const saved = await state();
        if (!saved.sources.some(x => x.trace_id === source.trace_id)) saved.sources.push(source);
        await persist(saved);
    });
    const match = (kind, digest, destination, observed = Date.now()) => locked(async () => {
        const saved = await state(); await persist(saved);
        if (!isDigest(digest)) return {match_status: 'not_checked'};
        if (destination === 'desktop-oli.tail2bbbea.ts.net') return {match_status: 'internal_destination'};
        const candidates = saved.sources.filter(x => x.kind === kind && x.digest === digest &&
            observed >= x.observed && observed - x.observed <= TTL);
        if (!candidates.length) return {match_status: 'no_match'};
        const source = candidates[candidates.length - 1];
        return {match_status: 'matched', source_inspection:source.inspection || {}, match: {
            source_trace_id: source.trace_id,
            source_kind: kind === 'text' ? 'COPY_ATTEMPT' : 'DOWNLOAD_COMPLETED',
            source_domain: 'desktop-oli.tail2bbbea.ts.net',
            source_path: kind === 'text' ? '/db' : '/db/download',
            source_time: source.timestamp,
            method: kind === 'text' ? 'salted_sha256_text_lf' : 'sha256_file_bytes',
            age_seconds: Math.floor((observed - source.observed) / 1000),
            candidate_count: candidates.length
        }};
    });
    const prepare = data => locked(async () => {
        if (!isDigest(data.digest) || !data.blob_url.startsWith('blob:https://desktop-oli.tail2bbbea.ts.net/'))
            throw new Error('INVALID_DOWNLOAD');
        const saved = await state();
        saved.downloads.push({...data, observed: Date.now()}); await persist(saved);
    });
    const prepared = url => locked(async () => {
        const saved = await state(); await persist(saved);
        return saved.downloads.find(x => x.blob_url === url);
    });
    return {seed, remember, match, prepare, prepared, isDigest};
})();
