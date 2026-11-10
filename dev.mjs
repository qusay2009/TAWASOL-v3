process.env.PORT=process.env.PORT||'4173';
process.env.PUBLIC_ORIGIN=process.env.PUBLIC_ORIGIN||'http://127.0.0.1:'+process.env.PORT;
process.env.DATA_DIR=process.env.DATA_DIR||'.preview-data';
await import('./server.mjs');
