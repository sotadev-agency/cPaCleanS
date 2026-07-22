"""Punto de entrada de cPacleanS."""
import sys
import os
import multiprocessing

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def main():
    from src.gui.app import CpacleanSApp
    app = CpacleanSApp()
    app.mainloop()


if __name__ == "__main__":
    multiprocessing.freeze_support()
    main()
