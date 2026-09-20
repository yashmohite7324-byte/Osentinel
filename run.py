#!/usr/bin/env python3
"""Entry point. `python run.py` starts the agent and serves the console."""

import argparse
import sys

import uvicorn

from osentinel.api import create_app
from osentinel.config import Config


def main() -> int:
    ap = argparse.ArgumentParser(prog="osentinel", description="OSentinel AI security console")
    ap.add_argument("--config", default="config.yaml")
    ap.add_argument("--host", default=None)
    ap.add_argument("--port", type=int, default=None)
    ap.add_argument("--enforce", action="store_true",
                    help="allow autonomous containment (default is dry run)")
    ap.add_argument("--train", action="store_true",
                    help="build the corpus and train the classifier, then exit. "
                         "Uses the LLM teacher if ANTHROPIC_API_KEY is set, "
                         "otherwise the built-in synthetic corpus.")
    ap.add_argument("--no-llm", action="store_true",
                    help="with --train, force the synthetic corpus even if a key is set")
    args = ap.parse_args()

    cfg = Config.load(args.config)

    if args.train:
        from osentinel.learn.corpus import build_corpus
        from osentinel.learn.trainer import train
        print("Building training corpus"
              + ("" if args.no_llm else " (LLM teacher used if a key is set)") + " ...")
        rep = build_corpus(cfg.classifier_corpus_path, use_llm=not args.no_llm,
                           progress=lambda m: print("  ", m))
        print(f"corpus: {rep.total} samples {rep.by_family}, "
              f"{rep.llm_batches} LLM batches")
        print("Training classifier ...")
        tr = train(cfg.classifier_corpus_path, cfg.classifier_model_path,
                   progress=lambda m: print("  ", m))
        print("\n" + tr.summary())
        for fam, m in tr.per_class.items():
            print(f"  {fam:11} precision {m['precision']:.3f}  recall {m['recall']:.3f}  "
                  f"f1 {m['f1']:.3f}")
        return 0
    if args.host:
        cfg.host = args.host
    if args.port:
        cfg.port = args.port
    if args.enforce:
        cfg.dry_run = False

    mode = "ENFORCING" if not cfg.dry_run else "dry run"
    print(f"OSentinel AI  |  response mode: {mode}")
    print(f"Console: http://{cfg.host}:{cfg.port}\n")

    uvicorn.run(create_app(cfg), host=cfg.host, port=cfg.port, log_level="warning")
    return 0


if __name__ == "__main__":
    sys.exit(main())
