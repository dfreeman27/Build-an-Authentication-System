

from pydantic import BaseModel, ConfigDict, Field, field_validator


class UserCreate(BaseModel):
    """Schema for user registration."""
    username: str = Field(..., max_length=100)
    email: str = Field(..., max_length=100)
    password: str = Field(..., min_length=8, max_length=72)
    @field_validator("password")
    def validate_password_length(cls, value: str) -> str:
        """Validate that the password does not exceed 72 UTF-8 bytes."""
        if len(value.encode("utf-8")) > 72:
            raise ValueError("Password exceeds 72 UTF-8 bytes")
        return value


class UserResponse(BaseModel):
    """Schema for returning user data (no password fields)."""
    id: int
    username: str
    email: str


class TokenResponse(BaseModel):
    """Schema for the JWT response."""
    access_token: str
    token_type: str = "bearer"