from pydantic import SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_WEAK_PATTERNS = (
    "replace-with",
    "example",
    "securevault-super-secure",
    "change-me",
    "your-secret",
    "placeholder",
)

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_prefix="SECUREVAULT_", extra="ignore")
    database_url: str
    jwt_secret: SecretStr
    refresh_token_hash_secret: SecretStr
    step_up_hash_secret: SecretStr
    # Google OAuth: required in production; may be empty string in local dev only.
    google_web_client_id: str = ""
    jwt_issuer: str = "securevault-api"
    jwt_audience: str = "securevault-android"
    environment: str = "production"
    # Default True so that production is safe by default.
    # Developers must explicitly set SECUREVAULT_REQUIRE_DEVICE_SIGNATURE=false in dev.
    require_device_signature: bool = True
    redis_url: str | None = None
    s3_endpoint_url: str | None = None
    s3_bucket_name: str = "securevault-blobs"
    s3_access_key_id: SecretStr | None = None
    s3_secret_access_key: SecretStr | None = None
    s3_region: str = "auto"

    @field_validator("jwt_secret", "refresh_token_hash_secret", "step_up_hash_secret")
    @classmethod
    def secret_is_not_placeholder(cls, value: SecretStr) -> SecretStr:
        raw = value.get_secret_value()
        if len(raw) < 32:
            raise ValueError("Secret must be at least 32 bytes")
        if any(pat in raw.lower() for pat in _WEAK_PATTERNS):
            raise ValueError(
                "Secret appears to be a placeholder or default value. "
                "Generate a cryptographically random secret before deploying."
            )
        return value

def get_settings() -> Settings:
    return Settings()

def assert_production_secrets(settings: Settings) -> None:
    """Call at startup when ENVIRONMENT=production. Aborts if any secret is weak or missing.

    Enforced checks (all must pass):
    1. google_web_client_id is set.
    2. require_device_signature is True.
    3. database_url is a PostgreSQL URL (not SQLite).
    4. redis_url is set (in-memory fallback is not safe across multiple instances).
    """
    if settings.environment != "production":
        return

    errors: list[str] = []

    if not settings.google_web_client_id:
        errors.append(
            "SECUREVAULT_GOOGLE_WEB_CLIENT_ID must be set in production. "
            "Get it from Google Cloud Console → APIs & Services → Credentials."
        )

    if not settings.require_device_signature:
        errors.append(
            "SECUREVAULT_REQUIRE_DEVICE_SIGNATURE must be true in production. "
            "Device signatures bind refresh tokens to hardware — disabling this is insecure."
        )

    db_url = settings.database_url.lower()
    if "sqlite" in db_url or not (
        db_url.startswith("postgresql") or db_url.startswith("postgres")
    ):
        errors.append(
            "SECUREVAULT_DATABASE_URL must be a PostgreSQL URL in production "
            "(e.g. postgresql+asyncpg://...). SQLite is not supported in production."
        )

    if not settings.redis_url:
        errors.append(
            "SECUREVAULT_REDIS_URL must be set in production. "
            "The in-memory rate limiter is not safe across multiple API instances."
        )

    if errors:
        raise RuntimeError(
            "SecureVault refuses to start in production with the following misconfigurations:\n"
            + "\n".join(f"  • {e}" for e in errors)
        )
