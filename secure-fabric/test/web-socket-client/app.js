'use strict';

const express = require('express');
const WebSocket = require('ws')


const ws = new WebSocket('ws://localhost:8500');

ws.on('open', function open() {
  ws.send('something');
});

ws.on('message', function incoming(message) {
  console.log('received: %s', message);
});

// Constants
const PORT = 8080;
const HOST = '0.0.0.0';

// App
const app = express();
app.get('/', (req, res) => {
  res.send('Hello World');
  console.log(ws)
});

app.listen(PORT, HOST);
console.log(`Running on http://${HOST}:${PORT}`);

webSocket = new WebSocket(url, protocols);