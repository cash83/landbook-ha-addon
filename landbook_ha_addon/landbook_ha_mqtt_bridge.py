"""Entrypoint compatibile: il codice vive nel package landbook/ (split 1:1 dal monolite)."""
from landbook.bridge_main import main

if __name__ == "__main__":
    main()
