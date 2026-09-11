"""
PhishGuard Model Downloader
============================
Downloads Qwen2.5-VL-3B-Instruct and Qwen2.5-3B-Instruct from HuggingFace.
Run this ONCE before starting agent_server.py.

Usage:
    export HF_TOKEN=hf_your_token_here        # Linux/Mac
    $env:HF_TOKEN = "hf_your_token_here"     # Windows PowerShell

    python download_models.py
    # OR pass token directly:
    python download_models.py hf_your_token_here
"""

import os, sys
from pathlib import Path
from huggingface_hub import snapshot_download, login

# Get token from env or command line argument
token = os.environ.get("HF_TOKEN")
if not token and len(sys.argv) > 1:
    token = sys.argv[1]

if not token:
    print("\nERROR: HuggingFace token required.")
    print("\nOption 1 — Environment variable:")
    print("  Linux/Mac:  export HF_TOKEN=hf_your_token_here")
    print("  PowerShell: $env:HF_TOKEN = 'hf_your_token_here'")
    print("\nOption 2 — Command line argument:")
    print("  python download_models.py hf_your_token_here")
    print("\nGet a free token at: https://huggingface.co/settings/tokens")
    sys.exit(1)

login(token=token)

models_dir = Path(__file__).parent.parent / "models"
models_dir.mkdir(exist_ok=True)

MODELS = [
    {
        "repo_id":    "Qwen/Qwen2.5-VL-3B-Instruct",
        "local_dir":  models_dir / "Qwen2.5-VL-3B-Instruct",
        "desc":       "VLM — visual screenshot analysis (~3.5 GB)",
    },
    {
        "repo_id":    "Qwen/Qwen2.5-3B-Instruct",
        "local_dir":  models_dir / "Qwen2.5-3B-Instruct",
        "desc":       "LLM — URL structure reasoning (~2.5 GB)",
    },
]

print("\nPhishGuard Model Downloader")
print("=" * 50)
print(f"Saving to: {models_dir}")
print("=" * 50)

for m in MODELS:
    print(f"\nDownloading: {m['repo_id']}")
    print(f"Description: {m['desc']}")
    snapshot_download(
        repo_id=m["repo_id"],
        local_dir=str(m["local_dir"]),
        token=token,
        ignore_patterns=[
            "*.msgpack", "flax_model*", "tf_model*", "rust_model*",
        ],
    )
    print(f"Saved to: {m['local_dir']}")

print("\n" + "=" * 50)
print("All models downloaded successfully!")
print(f"Location: {models_dir}")
print("\nNext step: python agent_server.py")
