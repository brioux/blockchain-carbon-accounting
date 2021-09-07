import http from 'http';
import express from 'express'
import socket.io from 'socket.io'
import { createServer } from "http";
import { Server } from "socket.io";
const app = express();
const server = createServer(app);
const io = new Server(server, {});
server.listen(3000);