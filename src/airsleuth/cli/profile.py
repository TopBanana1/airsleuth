from __future__ import annotations
import argparse, os, sys, json

from rich.console import Console
from rich.text import Text
from rich.progress import (
    Progress,
    SpinnerColumn,
    TextColumn,
    BarColumn,
    ProgressColumn,
)

from airsleuth import SCHEMA_VERSION
from ..build.assemble import build_manifest, dumps_json
from ..build.merge import merge_manifests

# --- portable ms-precision columns that work on older Rich versions ---
class MsElapsedColumn(ProgressColumn):
    """Elapsed time with millisecond precision (portable)."""
    def render(self, task):  # type: ignore[override]
        # use finished_time if available & finished; else live elapsed
        elapsed = task.finished_time if getattr(task, "finished", False) and getattr(task, "finished_time", None) is not None else getattr(task, "elapsed", None)
        return Text(f"{elapsed:.3f}s" if elapsed is not None else "--")

class MsRemainingColumn(ProgressColumn):
    """ETA with millisecond precision (portable)."""
    def render(self, task):  # type: ignore[override]
        # Hide ETA if we can't estimate yet or once the task is finished
        remaining = getattr(task, "time_remaining", None)
        if remaining is None or getattr(task, "finished", False):
            return Text("")  # or Text("—")
        return Text(f"{remaining:.3f}s")


console = Console()

def main(argv=None):
    ap = argparse.ArgumentParser(description="Build/merge Wi-Fi manifest JSON from capture(s).")
    ap.add_argument("-f", "--file", dest="files", action="append", help="pcap/pcapng file (repeatable)")
    ap.add_argument("-e", "--essid", dest="essids", action="append", help="ESSID to include (repeatable). If omitted, include all seen.")
    ap.add_argument("-o", "--out", default="manifest.json", help="Output path (default: manifest.json)")
    args = ap.parse_args(argv)

    files = args.files or []
    if not files:
        console.print("[red]No capture files provided (-f).[/red]")
        return 2
    for f in files:
        if not os.path.exists(f):
            console.print(f"[red]File not found:[/red] {f}")
            return 2

    console.print("[bold]airsleuth profile[/bold] — building manifest")
    try:
        with Progress(
        SpinnerColumn(),
        TextColumn("{task.description}"),
        BarColumn(),
        MsElapsedColumn(),      # elapsed in ms
        MsRemainingColumn(),    # ETA in ms
        console=console,
        transient=False,
        refresh_per_second=30,  # smoother updates for sub-second durations
        ) as progress:
            try:
                manifest = build_manifest(files, args.essids or [], progress=progress)
            except ValueError as e:
                console.print(f"[red]{e}[/red]")
                return 2
    except KeyboardInterrupt:
        console.print("[yellow]Interrupted by user (Ctrl+C). Exiting…[/yellow]")
        return 130

    out = args.out
    # Merge if exists and same schema version
    if os.path.exists(out):
        try:
            with open(out, "rb") as fh:
                old = json.loads(fh.read())
            if old.get("schema_version") != SCHEMA_VERSION:
                # STRONGER check: refuse to merge when versions diverge
                console.print(f"[red]Cannot merge:[/red] existing manifest has schema_version {old.get('schema_version')}, expected {SCHEMA_VERSION}. Writing a new file instead.")
                # Do NOT merge; proceed to write new file (manifest as built)
            else:
                manifest = merge_manifests(old, manifest)
        except Exception:
            console.print("[yellow]Existing manifest unreadable/malformed. Creating a new file.[/yellow]")

    try:
        with open(out, "wb") as fh:
            fh.write(dumps_json(manifest))
    except KeyboardInterrupt:
        console.print("[yellow]Interrupted while writing output. Partial work discarded.[/yellow]")
        return 130

    # Export artifacts next to manifest
    try:
        from airsleuth.build.assemble import export_artifacts
        base_dir = os.path.dirname(out) or "."
        artifacts_dir = os.path.join(base_dir, "artifacts")
        export_artifacts(manifest, artifacts_dir)
        # Re-write manifest including artifact paths
        with open(out, "wb") as fh:
            fh.write(dumps_json(manifest))
        console.print(f"[green]Artifacts exported to:[/green] {artifacts_dir}")
    except KeyboardInterrupt:
        console.print("[yellow]Interrupted while exporting artifacts.[/yellow]")
        return 130
    except Exception as e:
        console.print(f"[yellow]Artifact export skipped:[/yellow] {e}")

    console.print(f"[green]Manifest written to:[/green] {out}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
