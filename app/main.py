from fastapi import FastAPI
from app.database import Base, engine
from app.routers import auth

app = FastAPI(title="Auth System API")

Base.metadata.create_all(bind=engine)

app.include_router(auth.router, prefix="/auth", tags=["auth"])

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)