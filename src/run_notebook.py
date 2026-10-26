"""Execute a notebook top to bottom in a fresh kernel and save its outputs in place.

The kernel is the project's python3 kernel (.venv) and starts in the notebook's
folder, as in VS Code. The outputs are written back into the same .ipynb, so
running it again replaces them instead of adding to them. Timing metadata is not
recorded: it changes on every run and only adds noise to git diffs. If a cell
fails, the notebook is still saved with its traceback and the script stops.

Usage: uv run python src/run_notebook.py notebooks/analysis.ipynb
"""

import sys
from pathlib import Path

import nbformat
from nbclient import NotebookClient

PROJECT_ROOT = Path(__file__).resolve().parent.parent
KERNEL_NAME = "python3"
CELL_TIMEOUT_SECONDS = 600


def main() -> None:
    assert len(sys.argv) == 2, "usage: uv run python src/run_notebook.py <path/to/notebook.ipynb>"
    path = Path(sys.argv[1]).resolve()
    assert path.suffix == ".ipynb" and path.is_file(), f"notebook not found: {sys.argv[1]}"
    assert path.is_relative_to(PROJECT_ROOT), f"{path} is outside the project"

    notebook = nbformat.read(path, as_version=4)
    for cell in notebook.cells:
        cell.metadata.pop("execution", None)  # timing left by earlier runs
    client = NotebookClient(
        notebook,
        kernel_name=KERNEL_NAME,
        timeout=CELL_TIMEOUT_SECONDS,
        record_timing=False,
        resources={"metadata": {"path": str(path.parent)}},  # the kernel starts in the notebook's folder
    )
    try:
        client.execute()
    finally:
        # Save whatever ran, so a failing cell keeps its traceback in the notebook.
        nbformat.write(notebook, path)

    code_cells = [cell for cell in notebook.cells if cell.cell_type == "code"]
    outputs = [output for cell in code_cells for output in cell.outputs]
    errors = [cell.execution_count for cell in code_cells if any(o.output_type == "error" for o in cell.outputs)]
    images = sum("image/png" in output.get("data", {}) for output in outputs)

    print("\nSummary")
    print(f"  Notebook:   {path.relative_to(PROJECT_ROOT)}")
    print(f"  Cells:      {len(notebook.cells)} ({len(code_cells)} code, {len(notebook.cells) - len(code_cells)} markdown)")
    print(f"  Outputs:    {len(outputs)} ({images} images)")

    assert [cell.execution_count for cell in code_cells] == list(range(1, len(code_cells) + 1)), (
        "not every code cell ran once, in order"
    )
    assert not errors, f"cells with an error output: {errors}"
    print("All checks passed.")


if __name__ == "__main__":
    main()
