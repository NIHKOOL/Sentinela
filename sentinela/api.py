"""FastAPI app: serves the web pages and the REST API."""
import asyncio
import os
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Callable, Optional

from dotenv import load_dotenv
from fastapi import APIRouter, FastAPI, HTTPException, Query, Request, Response
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from .alerting import DiscordNotifier
from .attacks import SCENARIOS
from .models import AlertUpdate, AssetIn, AttackRequest, SimulationSettings, TelemetryEvent
from .organization import Organization
from .rules import DEFAULT_RULES_DIR, RuleSet, load_rules
from .simulation import Simulation

WEB_DIR = Path(__file__).resolve().parent.parent / "web"
PAGES = {
    "/": "index.html",
    "/organization": "organization.html",
    "/soc": "soc.html",
    "/attacker": "attacker.html",
}

router = APIRouter(prefix="/api/v1")


def get_sim(request: Request) -> Simulation:
    return request.app.state.simulation


# --- Organization ---

@router.get("/assets")
def list_assets(request: Request):
    return get_sim(request).org.all()


@router.post("/assets", status_code=201)
def add_asset(data: AssetIn, request: Request):
    try:
        return get_sim(request).org.add(data)
    except ValueError as e:
        raise HTTPException(409, str(e))


@router.put("/assets/{asset_id}")
def update_asset(asset_id: str, data: AssetIn, request: Request):
    try:
        asset = get_sim(request).org.update(asset_id, data)
    except ValueError as e:
        raise HTTPException(409, str(e))
    if asset is None:
        raise HTTPException(404, "Asset not found.")
    return asset


@router.delete("/assets/{asset_id}", status_code=204)
def delete_asset(asset_id: str, request: Request):
    if not get_sim(request).org.remove(asset_id):
        raise HTTPException(404, "Asset not found.")
    return Response(status_code=204)


@router.post("/assets/reset")
def reset_assets(request: Request):
    get_sim(request).org.reset_to_sample()
    return get_sim(request).org.all()


# --- Rules and scenarios (reference data) ---

def _rules_response(ruleset: RuleSet) -> dict:
    return {
        "directory": str(ruleset.directory) if ruleset.directory else None,
        "rules": [meta.to_dict() for meta in ruleset.alerting],
        "errors": ruleset.errors,
    }


@router.get("/rules")
def list_rules(request: Request):
    return _rules_response(get_sim(request).ruleset)


@router.post("/rules/reload")
def reload_rules(request: Request):
    """Read the rule files again, so edited or new rules work without restarting."""
    ruleset = _load_and_report(request.app.state.rules_dir)
    get_sim(request).reload_rules(ruleset)
    return _rules_response(ruleset)


@router.get("/scenarios")
def list_scenarios():
    return [scenario.to_dict() for scenario in SCENARIOS.values()]


# --- Attacker ---

@router.post("/attacks", status_code=201)
def launch_attack(attack: AttackRequest, request: Request):
    try:
        return get_sim(request).launch_attack(attack)
    except ValueError as e:
        raise HTTPException(400, str(e))


@router.get("/attacks")
def list_attacks(request: Request):
    return get_sim(request).list_attacks()


# --- Events ---

@router.post("/ingest")
def ingest_event(event: TelemetryEvent, request: Request):
    """Entry point for real agents. Events go through the same pipeline as simulated ones."""
    stored = get_sim(request).ingest(event, origin="external")
    return {
        "status": "processed",
        "event_id": stored["id"],
        "alert_triggered": bool(stored["alert_ids"]),
        "alert_ids": stored["alert_ids"],
    }


@router.get("/events")
def list_events(request: Request, limit: int = Query(100, ge=1, le=1000),
                hostname: Optional[str] = None, search: Optional[str] = Query(None, max_length=200)):
    return get_sim(request).list_events(limit, hostname, search)


# --- SOC ---

@router.get("/alerts")
def list_alerts(request: Request, status: Optional[str] = Query(None, pattern="^(open|new|investigating|closed)$")):
    return get_sim(request).list_alerts(status)


@router.get("/alerts/{alert_id}")
def get_alert(alert_id: int, request: Request):
    alert = get_sim(request).get_alert(alert_id)
    if alert is None:
        raise HTTPException(404, "Alert not found.")
    return alert


@router.patch("/alerts/{alert_id}")
def update_alert(alert_id: int, update: AlertUpdate, request: Request):
    try:
        alert = get_sim(request).update_alert(alert_id, update)
    except ValueError as e:
        raise HTTPException(400, str(e))
    if alert is None:
        raise HTTPException(404, "Alert not found.")
    return alert


@router.get("/stats")
def get_stats(request: Request):
    return {**get_sim(request).stats(), "webhook_configured": request.app.state.webhook_configured}


@router.get("/score")
def get_score(request: Request):
    return get_sim(request).score()


# --- Simulation control ---

@router.get("/simulation")
def get_simulation(request: Request):
    return get_sim(request).settings()


@router.patch("/simulation")
def update_simulation(settings: SimulationSettings, request: Request):
    simulation = get_sim(request)
    simulation.update_settings(settings.running, settings.interval_seconds)
    return simulation.settings()


@router.post("/simulation/reset")
def reset_simulation(request: Request):
    get_sim(request).reset()
    return {"status": "reset"}


# --- App ---

async def _background_loop(simulation: Simulation):
    while True:
        await asyncio.sleep(simulation.interval_seconds)
        if simulation.running:
            try:
                simulation.background_tick()
            except Exception as e:  # keep the simulation alive if one tick fails
                print(f"[-] Background activity error: {e}")


@asynccontextmanager
async def lifespan(app: FastAPI):
    task = asyncio.create_task(_background_loop(app.state.simulation))
    yield
    task.cancel()


def _load_and_report(rules_dir: Path) -> RuleSet:
    ruleset = load_rules(rules_dir)
    print(f"[*] Loaded {len(ruleset.alerting)} detection rules from {rules_dir}")
    for error in ruleset.errors:
        print(f"[-] Rule error: {error}")
    return ruleset


def _page(filename: str):
    def serve():
        return FileResponse(WEB_DIR / filename)
    return serve


def create_app(data_dir: Optional[Path] = None, notify: Optional[Callable[[dict], None]] = None,
               seed: Optional[int] = None, rules_dir: Path = DEFAULT_RULES_DIR) -> FastAPI:
    """Build the app. Without `data_dir` the organization is kept in memory only (used by tests)."""
    app = FastAPI(title="Sentinela SOC Simulator", version="0.3.0", lifespan=lifespan)
    organization = Organization(data_dir / "organization.json" if data_dir else None)
    app.state.rules_dir = Path(rules_dir)
    ruleset = _load_and_report(app.state.rules_dir)
    app.state.simulation = Simulation(organization, notify or (lambda alert: None), seed, ruleset)
    app.state.webhook_configured = bool(getattr(notify, "configured", False))

    app.include_router(router)
    app.mount("/static", StaticFiles(directory=WEB_DIR / "static"), name="static")
    for path, filename in PAGES.items():
        app.add_api_route(path, _page(filename), methods=["GET"], include_in_schema=False)

    @app.middleware("http")
    async def always_check_for_updates(request: Request, call_next):
        response = await call_next(request)
        if not request.url.path.startswith("/api/"):
            # Pages and static files: the browser must ask whether its cached copy is still current
            # (cheap thanks to ETag), so an updated common.js or style.css is used right away.
            response.headers.setdefault("Cache-Control", "no-cache")
        return response

    @app.get("/favicon.ico", include_in_schema=False)
    def favicon():
        return FileResponse(WEB_DIR / "static" / "logo-64.png", media_type="image/png")

    @app.get("/health")
    def health_check():
        return {"status": "online", "engine": "Sentinela SOC Simulator"}

    return app


load_dotenv()
app = create_app(
    data_dir=Path(os.getenv("SENTINELA_DATA_DIR", "data")),
    rules_dir=Path(os.getenv("SENTINELA_RULES_DIR", DEFAULT_RULES_DIR)),
    notify=DiscordNotifier(os.getenv("DISCORD_WEBHOOK_URL", ""), os.getenv("DISCORD_MIN_SEVERITY", "HIGH")),
)
