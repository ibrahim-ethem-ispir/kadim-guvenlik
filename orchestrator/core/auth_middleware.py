from fastapi import Request, HTTPException
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
import os
import jwt
import logging

logger = logging.getLogger("uvicorn")

class AuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # Exclude open endpoints
        # Türkçe: Wordlist listeleme gibi read-only public endpoint'ler auth gerektirmez
        # NOT: nginx /api/ prefix'ini strip ediyor, bu yüzden /fuzz/wordlists olarak gelir
        public_endpoints = [
            "/docs", "/openapi.json", "/health", "/metrics",
            "/fuzz/wordlists",  # Wordlist metadata - public read access
        ]

        if request.url.path in public_endpoints:
            return await call_next(request)
        
        # Türkçe: AI endpoints authentication gerektirir (kullanıcıların scan verilerine erişir)
        # Ancak path check yerine token validation yapılacak, bu yüzden bu bloğu bypassla
        
        if request.method == "OPTIONS":
            return await call_next(request)
            
        # Get Token
        auth_header = request.headers.get("Authorization")
        if not auth_header:
            return JSONResponse(status_code=401, content={"detail": "Missing Authorization Header"})
            
        try:
            scheme, token = auth_header.split()
            if scheme.lower() != "bearer":
                return JSONResponse(status_code=401, content={"detail": "Invalid authentication scheme"})
                
            # Verify Token
            # Türkçe: Default secret YOK — bilinen default ile token forge edilebilirdi.
            # JWT_SECRET tanımlı değilse doğrulama güvenli reddedilir.
            secret = os.getenv("JWT_SECRET")
            if not secret:
                logger.error("JWT_SECRET tanımlı değil. .env dosyasına JWT_SECRET ekleyin.")
                return JSONResponse(status_code=500, content={"detail": "Server auth yapılandırması eksik (JWT_SECRET)"})
            payload = jwt.decode(token, secret, algorithms=["HS256"])
            
            # Add user info to request state if needed
            request.state.user = payload
            
        except (ValueError, jwt.ExpiredSignatureError, jwt.InvalidTokenError) as e:
            logger.warning(f"Auth failed: {e}")
            return JSONResponse(status_code=401, content={"detail": "Invalid or expired token"})
            
        response = await call_next(request)
        return response
