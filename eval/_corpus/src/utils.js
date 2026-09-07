// 시크릿이 아니지만 형태가 비슷해 오탐을 유발하는 값들

const BUILD_COMMIT = "3f7a2c9e1b8d4f6a0c5e2b9d7f4a1c8e3b6d9f2a";
const SESSION_ID = "550e8400-e29b-41d4-a716-446655440000";
const CONTENT_HASH = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
const CACHE_KEY = "v2:user:profile:8f14e45fceea167a5a36dedd4bea2543";

const TRANSPARENT_PIXEL =
  "data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7";

const CSP_NONCE_SAMPLE = "bmNlLTIzNDU2Nzg5MGFiY2RlZmdoaWprbG1ub3A";

function buildInfo() {
  return { commit: BUILD_COMMIT, session: SESSION_ID };
}

module.exports = { buildInfo, CONTENT_HASH, CACHE_KEY, TRANSPARENT_PIXEL, CSP_NONCE_SAMPLE };
