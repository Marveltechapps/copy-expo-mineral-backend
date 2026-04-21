'use strict';

const path = require('path');
const fs = require('fs');

const CATALOG_PATH = path.join(__dirname, '..', '..', 'frontend', 'data', 'artisanalMineralCatalog.json');

let STATIC_CATALOG = [];
try {
  const raw = fs.readFileSync(CATALOG_PATH, 'utf8');
  STATIC_CATALOG = JSON.parse(raw);
  if (!Array.isArray(STATIC_CATALOG)) STATIC_CATALOG = [];
} catch (e) {
  console.error('artisanalMineralCatalog.json:', e.message);
}

/** Legacy app / seed names — kept so older profiles and aliases still validate. */
const LEGACY_APP_MINERAL_NAMES = [
  'Gold',
  'Silver',
  'Diamonds',
  'Emerald',
  'Ruby',
  'Tanzanite',
  'Black & Fire Opal',
  'Black Opal',
  'Fire Opal',
  'Copper',
  'Nickel',
  'Cobalt',
  'Limestone',
  'Quartz',
  'Lithium',
  'Uranium',
];

function addToMapFirstWins(map, raw) {
  const t = String(raw || '').trim();
  if (!t) return;
  const lower = t.toLowerCase();
  if (!map.has(lower)) map.set(lower, t);
}

/** Dashboard / DB names override canonical spelling for the same lower-case key. */
function addToMapPrefer(map, raw) {
  const t = String(raw || '').trim();
  if (!t) return;
  map.set(t.toLowerCase(), t);
}

function applyAliases(map) {
  const opalCanon = map.get('black & fire opal') || map.get('opal') || 'Opal';
  map.set('black opal', opalCanon);
  map.set('fire opal', opalCanon);
  if (!map.has('diamonds')) {
    const d = map.get('diamond (rough)') || map.get('diamond (polished)');
    if (d) map.set('diamonds', d);
  }
}

let cachedMap = null;
let cachedAt = 0;
const MAP_TTL_MS = 2 * 60 * 1000;

async function buildArtisanalMineralLowerMap(db) {
  const map = new Map();
  for (const n of STATIC_CATALOG) addToMapFirstWins(map, n);
  for (const n of LEGACY_APP_MINERAL_NAMES) addToMapFirstWins(map, n);
  if (db) {
    try {
      const names = await db.collection('minerals').distinct('name');
      if (Array.isArray(names)) {
        for (const n of names) addToMapPrefer(map, n);
      }
    } catch (e) {
      /* ignore */
    }
  }
  applyAliases(map);
  return map;
}

async function getArtisanalMineralLowerMap(db) {
  const now = Date.now();
  if (cachedMap && now - cachedAt < MAP_TTL_MS) return cachedMap;
  cachedMap = await buildArtisanalMineralLowerMap(db);
  cachedAt = now;
  return cachedMap;
}

function invalidateArtisanalMineralCache() {
  cachedMap = null;
  cachedAt = 0;
}

function normalizeArtisanalMineralType(raw, map) {
  const t = String(raw || '').trim();
  if (!t) return null;
  return map.get(t.toLowerCase()) || null;
}

function isValidArtisanalMineralType(raw, map) {
  if (raw == null || typeof raw !== 'string') return false;
  return normalizeArtisanalMineralType(raw, map) != null;
}

module.exports = {
  getArtisanalMineralLowerMap,
  normalizeArtisanalMineralType,
  isValidArtisanalMineralType,
  invalidateArtisanalMineralCache,
};
