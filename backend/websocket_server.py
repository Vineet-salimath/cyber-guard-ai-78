# REAL-TIME WEBSOCKET SERVER FOR SIEM INTEGRATION
# Runs alongside Flask backend to provide real-time updates to dashboard

import asyncio
import websockets
import json
import logging
from datetime import datetime
from typing import Set
import signal

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('WebSocketServer')

# Store connected clients
connected_clients: Set[websockets.WebSocketServerProtocol] = set()

class SIEMWebSocketServer:
    """WebSocket server for real-time SIEM updates"""
    
    def __init__(self, host='localhost', port=8080):
        self.host = host
        self.port = port
        self.server = None
        
    async def register_client(self, websocket):
        """Register a new client connection"""
        connected_clients.add(websocket)
        logger.info(f"✅ New client connected. Total clients: {len(connected_clients)}")
        
        # Send welcome message
        await self.send_to_client(websocket, {
            'type': 'connection',
            'status': 'connected',
            'message': 'Connected to MalwareSnipper SIEM',
            'timestamp': datetime.now().isoformat()
        })
    
    async def unregister_client(self, websocket):
        """Unregister a disconnected client"""
        connected_clients.discard(websocket)
        logger.info(f"❌ Client disconnected. Total clients: {len(connected_clients)}")
    
    async def send_to_client(self, websocket, message):
        """Send message to a specific client"""
        try:
            await websocket.send(json.dumps(message))
        except Exception as e:
            logger.error(f"Error sending to client: {e}")
    
    async def broadcast(self, message):
        """Broadcast message to all connected clients"""
        if not connected_clients:
            logger.debug("No clients connected to broadcast to")
            return
        
        logger.info(f"📡 Broadcasting to {len(connected_clients)} clients: {message.get('type', 'unknown')}")
        
        # Send to all connected clients
        disconnected = set()
        for websocket in connected_clients:
            try:
                await self.send_to_client(websocket, message)
            except websockets.exceptions.ConnectionClosed:
                disconnected.add(websocket)
            except Exception as e:
                logger.error(f"Error broadcasting to client: {e}")
                disconnected.add(websocket)
        
        # Remove disconnected clients
        for websocket in disconnected:
            await self.unregister_client(websocket)
    
    async def handle_client(self, websocket, path):
        """Handle individual client connection"""
        await self.register_client(websocket)
        
        try:
            async for message in websocket:
                try:
                    data = json.loads(message)
                    logger.info(f"📨 Received from client: {data}")
                    
                    # Handle ping/pong for keep-alive
                    if data.get('type') == 'ping':
                        await self.send_to_client(websocket, {
                            'type': 'pong',
                            'timestamp': datetime.now().isoformat()
                        })
                    
                    # Handle scan requests (forward to Flask backend)
                    elif data.get('type') == 'scan_request':
                        # In production, this would trigger a scan
                        logger.info(f"Scan request received for: {data.get('url')}")
                        
                except json.JSONDecodeError:
                    logger.error(f"Invalid JSON received: {message}")
                except Exception as e:
                    logger.error(f"Error handling message: {e}")
                    
        except websockets.exceptions.ConnectionClosed:
            logger.info("Client connection closed normally")
        finally:
            await self.unregister_client(websocket)
    
    async def start(self):
        """Start the WebSocket server"""
        logger.info(f"🚀 Starting WebSocket server on {self.host}:{self.port}")
        
        self.server = await websockets.serve(
            self.handle_client,
            self.host,
            self.port,
            ping_interval=30,  # Send ping every 30 seconds
            ping_timeout=10    # Wait 10 seconds for pong
        )
        
        logger.info(f"✅ WebSocket server running on ws://{self.host}:{self.port}")
        
        # Keep server running
        await asyncio.Future()  # Run forever
    
    def stop(self):
        """Stop the WebSocket server"""
        if self.server:
            self.server.close()
            logger.info("WebSocket server stopped")


# Global server instance
ws_server = SIEMWebSocketServer()

async def broadcast_scan_result(scan_data):
    """
    Broadcast scan result to all connected clients
    Called from Flask backend after scan completion
    """
    message = {
        'type': 'scan_complete',
        'data': scan_data,
        'timestamp': datetime.now().isoformat()
    }
    await ws_server.broadcast(message)

async def broadcast_stats_update(stats):
    """
    Broadcast statistics update to all connected clients
    """
    message = {
        'type': 'stats_update',
        'data': stats,
        'timestamp': datetime.now().isoformat()
    }
    await ws_server.broadcast(message)

def main():
    """Main entry point"""
    logger.info("=" * 60)
    logger.info("MalwareSnipper SIEM - WebSocket Server")
    logger.info("=" * 60)
    
    # Handle graceful shutdown
    def signal_handler(signum, frame):
        logger.info("Received shutdown signal")
        ws_server.stop()
        exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Start server
    try:
        asyncio.run(ws_server.start())
    except KeyboardInterrupt:
        logger.info("Server stopped by user")
    except Exception as e:
        logger.error(f"Server error: {e}")
        raise

if __name__ == '__main__':
    main()
