// A small deterministic PRNG. Every generated case is a pure function of a
// 32-bit case seed, and the case seed is a pure function of the run seed, the
// surface id and the case index, so any case is reproducible from three numbers
// without replaying the ones before it.

/** xmur3 string hash, used to derive a case seed from run seed + surface + index. */
export function deriveSeed(runSeed, surfaceId, index) {
  let h = (runSeed >>> 0) ^ 0x9e3779b9;
  const s = `${surfaceId}#${index}`;
  for (let i = 0; i < s.length; i++) {
    h = Math.imul(h ^ s.charCodeAt(i), 3432918353);
    h = (h << 13) | (h >>> 19);
  }
  h = Math.imul(h ^ (h >>> 16), 2246822507);
  h = Math.imul(h ^ (h >>> 13), 3266489909);
  return (h ^ (h >>> 16)) >>> 0;
}

/** mulberry32. Fast, fine for structure-aware generation, not for crypto. */
export function rngFromSeed(seed) {
  let a = seed >>> 0;
  const next = () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
  return {
    next,
    /** integer in [0, n) */
    int: (n) => Math.floor(next() * n),
    /** integer in [lo, hi] */
    between: (lo, hi) => lo + Math.floor(next() * (hi - lo + 1)),
    bool: (p = 0.5) => next() < p,
    pick: (arr) => arr[Math.floor(next() * arr.length)],
    /** k distinct-ish picks, order preserved */
    sample: (arr, k) => {
      const out = [];
      for (let i = 0; i < k; i++) out.push(arr[Math.floor(next() * arr.length)]);
      return out;
    },
  };
}
