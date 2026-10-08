from pathlib import Path
from pydantic_settings import BaseSettings
from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parents[2] / ".env")


class Settings(BaseSettings):
    app_name: str = "Vendor Disclosure Monitoring Platform"
    database_url: str = ""
    sqlite_path: Path = Path(__file__).resolve().parents[2] / "data" / "monitor.db"
    enable_scheduler: bool = False
    cors_origins: str = "http://localhost:3000,http://127.0.0.1:3000"
    poll_interval_minutes: int = 5
    vendors_config_path: Path = Path(__file__).resolve().parents[2] / "config" / "vendors.yaml"

    class Config:
        env_prefix = "VDM_"


settings = Settings()

