from pathlib import Path

from typing_extensions import override

from .filescan import RoutedFiles, scan_files


class GrepVF:
    def __init__(self, root_path: str) -> None:
        if not root_path or not isinstance(root_path, str):
            raise ValueError("root_path must be a valid, non-empty string.")

        self.root_path: Path = Path(root_path).resolve()
        if not self.root_path.is_dir():
            raise FileNotFoundError(
                f"Target directory does not exist: {self.root_path}"
            )

        self.files: RoutedFiles | None = None

    def run_file_scan(self) -> None:
        print(f"Starting file scan at: {self.root_path}")

        self.files = scan_files(str(self.root_path))
        if self.files.total_routed == 0:
            print("Scan completed, but no supported files were found to route.")

    @override
    def __repr__(self) -> str:
        status = "Scanned" if self.files else "Pending"
        return f"<GrepVF(path='{self.root_path.name}', status='{status}')>"
