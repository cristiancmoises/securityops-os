# CodeMark v1 project=4c63e0fe-589c-4944-8449-97e211a38b72 file=25b12cb5b0f150f29cc9e4804491fe0f owner="Cristian Cezar Mois\u00e9s"
"""Structural unittest result only; failures/skips never become success."""
import json
import os
from pathlib import Path
import sys
import unittest

source, destination = map(Path, sys.argv[1:])
suite = unittest.defaultTestLoader.discover(str(source/'tests'), pattern='test_*.py')
with open(os.devnull, 'w') as sink:
    result = unittest.TextTestRunner(stream=sink).run(suite)
counts = {'check':'unittest', 'tests':result.testsRun, 'failures':len(result.failures),
          'errors':len(result.errors), 'skipped':len(result.skipped)}
with destination.open('x', encoding='utf-8') as stream:
    json.dump(counts, stream, sort_keys=True)
    stream.write('\n')
raise SystemExit(0 if result.wasSuccessful() and result.testsRun and not result.skipped else 1)
