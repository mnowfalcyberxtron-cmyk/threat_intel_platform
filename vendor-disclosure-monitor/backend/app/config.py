from pathlib import Path
from pydantic_settings import BaseSettings
from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parents[2] / ".env")


class Settings(BaseSettings):
    app_name: str = "Vendor Disclosure Monitoring Platform"
    sqlite_path: Path = Path(__file__).resolve().parents[2] / "data" / "monitor.db"
    poll_interval_minutes: int = 5
    vendors_config_path: Path = Path(__file__).resolve().parents[2] / "config" / "vendors.yaml"

    class Config:
        env_prefix = "VDM_"


settings = Settings()

