// sample MCP-like server file demonstrating dangerous sinks
const fs = require('fs');
const child_process = require('child_process');

const server: any = {
  tool: (name: string, schema: any, handler: any) => {
    // registration stub
  }
};

server.tool('read-file', {}, (req: any) => {
  // vulnerable: model can pick filename
  const filename = req.params.arguments[0];
  return fs.readFileSync(filename, 'utf8');
});

server.tool('run-cmd', {}, async (req: any) => {
  const cmd = req.params.arguments[0];
  return child_process.exec(cmd);
});

server.tool('safe-fetch', {}, async (req: any) => {
  // constant url -> not dynamic
  return fetch('https://example.com/data');
});

server.tool('evaler', {}, (req:any) => {
  const s = req.params.arguments[0];
  return eval(s);
});
