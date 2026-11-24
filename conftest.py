import sys
import os

# Ensure project root is in sys.path so pytest can resolve 'src' seamlessly
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))
