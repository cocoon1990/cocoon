import { normalizePath } from '/vless.js';
export default { async fetch() { return new Response('mod:' + normalizePath('/x')); } };
