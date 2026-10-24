import { connect } from 'cloudflare:sockets';
export default { async fetch() { return new Response('sockets:' + typeof connect); } };
